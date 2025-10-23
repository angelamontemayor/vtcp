mod state;
mod events;

pub use state::*;
pub use events::*;

use std::collections::VecDeque;
use crate::socket::tcp::{SocketBuffer, State};
use crate::socket::Context;
use crate::wire::{IpRepr, IpProtocol, TcpRepr, TcpSeqNumber, TcpControl, Ipv4Repr};
use crate::time::Instant;
#[cfg(feature = "proto-ipv6")]
use crate::wire::Ipv6Repr;

pub struct Socket<'a> {
    /// Organized state components
    state: TcpState<'a>,
}

impl<'a> Socket<'a> {
    pub fn new(rx_buffer: SocketBuffer<'a>, tx_buffer: SocketBuffer<'a>) -> Self {
        Socket {
            state: TcpState::new(rx_buffer, tx_buffer),
        }
    }

    fn process_rx_rod_events(rod_state: &mut ReliableOrderedDeliveryState,
        events: Vec<DeliveryEvent>) {
        for event in events {
            match event {
                DeliveryEvent::InOrderData { seq, data } => {
                                let offset = 0;
                                let payload_len = data.len();
                
                                let contig_len = match rod_state.assembler
                                    .add_then_remove_front(offset, payload_len) 
                                {
                                    Ok(len) => len,
                                    Err(_) => {
                                        // Too many holes - shouldn't happen for in-order data at offset 0
                                        // but handle gracefully
                                        return;
                                    }
                                };

                                rod_state.rx_buffer.write_unallocated(offset, &data);

                                if contig_len > 0 {
                                    rod_state.rx_buffer.enqueue_unallocated(contig_len);
                    
                                    rod_state.remote_seq_no += contig_len;
                                }
                            }
                DeliveryEvent::OutOfOrderData { seq, data } => {
                                let offset = (seq - rod_state.remote_seq_no) as usize;
                                let payload_len = data.len();
                
                                if let Ok(_) = rod_state.assembler.add(offset, payload_len) {
                                    rod_state.rx_buffer.write_unallocated(offset, &data);
                                }
                            }
                // we reach this branch through process_ack. if there is data acknowledged, we need to remove it from the rx buffer
                DeliveryEvent::DataAcknowledged { ack_number, acked_bytes } => todo!(),
            }
        }
    }
    
    fn process_rx_flow_events(flow_state: &mut FlowControlState, events: Vec<FlowEvent>) {
        for event in events {
            match event {
                FlowEvent::RemoteWindowUpdate { new_window, .. } => {
                    flow_state.remote_win_len = new_window;
                }
                
                FlowEvent::RemoteWindowZero {} => {
                    flow_state.remote_win_len = 0;
                }
            }
        }
    }

    pub fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state.conn_mgmt.tcp_state == State::Closed {
            return false;
        }

        if self.state.conn_mgmt.tcp_state == State::Listen
            && (repr.ack_number.is_some() || repr.control == TcpControl::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.state.conn_mgmt.tuple {
            ip_repr.dst_addr() == tuple.local.addr
                && repr.dst_port == tuple.local.port
                && ip_repr.src_addr() == tuple.remote.addr
                && repr.src_port == tuple.remote.port
        } else {
            let addr_ok = match self.state.conn_mgmt.listen_endpoint.addr {
                Some(addr) => ip_repr.dst_addr() == addr,
                None => true,
            };
            addr_ok && repr.dst_port != 0 && repr.dst_port == self.state.conn_mgmt.listen_endpoint.port
        }
    }

    fn process_ack(&mut self, repr: &TcpRepr, ip_repr: &IpRepr) -> Option<(IpRepr, TcpRepr<'static>)> {
        let mut fc_events: Vec<FlowEvent> = Vec::new();

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state.conn_mgmt.tcp_state {
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgements for
            // all of the control flags we sent.
            _ => (false, false),
        };
        let control_len = (sent_syn as usize) + (sent_fin as usize);

        // Reject unacceptable acknowledgements.
        match (self.state.conn_mgmt.tcp_state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                net_debug!("unacceptable RST (expecting RST|ACK) in response to initial SYN");
                return None;
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if ack_number != self.state.delivery.local_seq_no + 1 {
                    net_debug!("unacceptable RST|ACK in response to initial SYN");
                    return None;
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpControl::Rst, _) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, _, None) => (),
            // This case is handled in `accepts()`.
            (State::Listen, _, Some(_)) => unreachable!(),
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if ack_number != self.state.delivery.local_seq_no + 1 {
                    net_debug!("unacceptable SYN|ACK in response to initial SYN");
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // TCP simultaneous open.
            // This is required by RFC 9293, which states "A TCP implementation MUST support
            // simultaneous open attempts (MUST-10)."
            (State::SynSent, TcpControl::Syn, None) => (),
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // If the sequence number matches, ignore it instead of RSTing.
                // I'm not sure why, I think it may be a workaround for broken TCP
                // servers, or a defense against reordering. Either way, if Linux
                // does it, we do too.
                if ack_number == self.state.delivery.local_seq_no + 1 {
                    net_debug!(
                        "expecting a SYN|ACK, received an ACK with the right ack_number, ignoring."
                    );
                    return None;
                }

                net_debug!(
                    "expecting a SYN|ACK, received an ACK with the wrong ack_number, sending RST."
                );
                return Some(Self::rst_reply(ip_repr, repr));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                net_debug!("expecting a SYN|ACK");
                return None;
            }
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                net_debug!("expecting an ACK");
                return None;
            }
            // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
            (State::SynReceived, _, Some(ack_number)) => {
                if ack_number != self.state.delivery.local_seq_no + 1 {
                    net_debug!("unacceptable ACK in response to SYN|ACK");
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, _, Some(ack_number)) => {
                let unacknowledged = self.state.delivery.tx_buffer.len() + control_len;

                // Acceptable ACK range (both inclusive)
                let mut ack_min = self.state.delivery.local_seq_no;
                let ack_max = self.state.delivery.local_seq_no + unacknowledged;

                // If we have sent a SYN, it MUST be acknowledged.
                if sent_syn {
                    ack_min += 1;
                }

                if ack_number < ack_min {
                    net_debug!(
                        "duplicate ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return None;
                }

                if ack_number > ack_max {
                    net_debug!(
                        "unacceptable ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    //return self.challenge_ack_reply(cx, ip_repr, repr);
                    return None;
                }
            }
        }

        let assembler_was_empty = self.state.delivery.assembler.is_empty();

        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.state.flow_control.remote_win_scale.unwrap_or(0),
        };
        
        let new_remote_win_len = (repr.window_len as usize) << (scale as usize);
        let old_remote_win_len = self.state.flow_control.remote_win_len;

        // Generate flow control events based on window changes
        if new_remote_win_len != old_remote_win_len {
            if new_remote_win_len == 0 {
                fc_events.push(FlowEvent::RemoteWindowZero{});
            } else {
                fc_events.push(FlowEvent::RemoteWindowUpdate {
                    new_window: new_remote_win_len,
                    window_scale: scale,
                });
            }
        }

        Self::process_rx_flow_events(&mut self.state.flow_control, fc_events);

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.state.delivery.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because smoltcp assumes that it can always transmit zero or one
            // packets for every packet it receives.
            //tcp_trace!("ACKing incoming segment");
            //Some(self.ack_reply(ip_repr, repr))
            return None;
        } else {
            return None;
        }
        None
    }
    
    fn process_data(&mut self, repr: &TcpRepr) {
        let mut rod_events = Vec::new();
        if repr.seq_number == self.state.delivery.remote_seq_no {
            let event = DeliveryEvent::InOrderData {
                seq: repr.seq_number,
                data: repr.payload.to_vec(),
            };
            rod_events.push(event);
        } else {
            let event = DeliveryEvent::OutOfOrderData {
                seq: repr.seq_number,
                data: repr.payload.to_vec(),
            };
            rod_events.push(event);
        }
        Self::process_rx_rod_events(&mut self.state.delivery,
            rod_events);
    }

    /// Main packet processing with component-specific event handling
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if !self.accepts(cx, ip_repr, repr) {
            return None;
        }
        
        if let Some(ack_number) = repr.ack_number {
            if let Some(reply) = self.process_ack(repr, ip_repr) {
                return Some(reply);
            }
        }
        if !repr.payload.is_empty() {
            self.process_data(&repr);
        }

        return None // double check what is expected here
    }

    pub(crate) fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_reply_repr = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            reply_repr.buffer_len(),
            64,
        );
        (ip_reply_repr, reply_repr)
    }
    /* 
    fn ack_reply(&mut self, ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let (mut ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);
        reply_repr.timestamp = repr
            .timestamp
            .and_then(|tcp_ts| tcp_ts.generate_reply(self.tsval_generator));

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.remote_last_seq;
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
        self.remote_last_ack = reply_repr.ack_number;

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();
        self.remote_last_win = reply_repr.window_len;

        // If the remote supports selective acknowledgement, add the option to the outgoing
        // segment.
        if self.remote_has_sack {
            net_debug!("sending sACK option with current assembler ranges");

            // RFC 2018: The first SACK block (i.e., the one immediately following the kind and
            // length fields in the option) MUST specify the contiguous block of data containing
            // the segment which triggered this ACK, unless that segment advanced the
            // Acknowledgment Number field in the header.
            reply_repr.sack_ranges[0] = None;

            if let Some(last_seg_seq) = self.local_rx_last_seq.map(|s| s.0 as u32) {
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data(reply_repr.ack_number.map(|s| s.0 as usize).unwrap_or(0))
                    .map(|(left, right)| (left as u32, right as u32))
                    .find(|(left, right)| *left <= last_seg_seq && *right >= last_seg_seq);
            }

            if reply_repr.sack_ranges[0].is_none() {
                // The matching segment was removed from the assembler, meaning the acknowledgement
                // number has advanced, or there was no previous sACK.
                //
                // While the RFC says we SHOULD keep a list of reported sACK ranges, and iterate
                // through those, that is currently infeasible. Instead, we offer the range with
                // the lowest sequence number (if one exists) to hint at what segments would
                // most quickly advance the acknowledgement number.
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data(reply_repr.ack_number.map(|s| s.0 as usize).unwrap_or(0))
                    .map(|(left, right)| (left as u32, right as u32))
                    .next();
            }
        }

        // Since the sACK option may have changed the length of the payload, update that.
        ip_reply_repr.set_payload_len(reply_repr.buffer_len());
        (ip_reply_repr, reply_repr)
    } */

    pub(crate) fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn create_ack_packet(
        &self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        window: u16,
    ) -> (IpRepr, TcpRepr<'static>) {
        let ack_repr = TcpRepr {
            src_port: tcp_repr.dst_port,
            dst_port: tcp_repr.src_port,
            control: TcpControl::None,
            seq_number: seq,
            ack_number: Some(ack),
            window_len: window,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        
        let response_ip = self.swap_ip_addresses(ip_repr, ack_repr.buffer_len());
        (response_ip, ack_repr)
    }
    
    fn swap_ip_addresses(&self, ip_repr: &IpRepr, payload_len: usize) -> IpRepr {
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: ipv4_repr.dst_addr,
                dst_addr: ipv4_repr.src_addr,
                next_header: IpProtocol::Tcp,
                payload_len,
                hop_limit: 64,
            }),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: ipv6_repr.dst_addr,
                dst_addr: ipv6_repr.src_addr,
                next_header: IpProtocol::Tcp,
                payload_len,
                hop_limit: 64,
            }),
            _ => ip_repr.clone(),
        }
    }
    
    pub fn set_sequence_numbers(&mut self, remote_seq_no: u32, local_seq_no: u32) {
        self.state.delivery.remote_seq_no = TcpSeqNumber(remote_seq_no.try_into().unwrap());
        self.state.delivery.local_seq_no = TcpSeqNumber(local_seq_no.try_into().unwrap());
    }
    
    pub fn set_state(&mut self, state: crate::socket::tcp::State) {
        self.state.conn_mgmt.tcp_state = state;
    }
}

