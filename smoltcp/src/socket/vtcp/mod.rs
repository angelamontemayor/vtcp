mod state;
mod events;

pub use state::*;
pub use events::*;

use std::collections::VecDeque;
use crate::socket::tcp::{SocketBuffer, State};
use crate::socket::Context;
use crate::wire::{IpRepr, IpProtocol, TcpRepr, TcpSeqNumber, TcpControl, Ipv4Repr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::Ipv6Repr;

/// Event-based TCP Socket
pub struct Socket<'a> {
    /// Organized state components
    state: TcpState,
    
    /// Buffer for received data
    rx_buffer: SocketBuffer<'a>,
    
    /// Buffer for data to send
    tx_buffer: SocketBuffer<'a>,
    
    /// Events to process
    events: VecDeque<Event>,
}

// ================================================================================
// CONTROL LOGIC - Can modify ALL state components
// ================================================================================

struct ControlLogic;

impl ControlLogic {
    /// Control Logic gets FULL mutable access to ALL state
    fn process_control_event(
        state: &mut TcpState,  // Can modify EVERYTHING!
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        
        match (state.conn_mgmt.tcp_state, control) {
            (crate::socket::tcp::State::Listen, TcpControl::Syn) => {
                // Control can modify ALL components
                state.conn_mgmt.tcp_state = crate::socket::tcp::State::SynReceived;
                state.delivery.rcv_nxt = seq + 1;
                state.flow_control.rcv_wnd = 8192;  // Can also modify flow control
                
                actions.push(Action::StateTransition {
                    new_state: crate::socket::tcp::State::SynReceived,
                });
                actions.push(Action::SendSynAck {
                    seq: state.delivery.snd_nxt,
                    ack: state.delivery.rcv_nxt,
                    window: state.flow_control.rcv_wnd,
                });
            }
            (crate::socket::tcp::State::SynSent, TcpControl::Syn) if ack.is_some() => {
                state.conn_mgmt.tcp_state = crate::socket::tcp::State::Established;
                state.delivery.rcv_nxt = seq + 1;
                
                actions.push(Action::StateTransition {
                    new_state: crate::socket::tcp::State::Established,
                });
            }
            (crate::socket::tcp::State::Established, TcpControl::Fin) => {
                state.conn_mgmt.tcp_state = crate::socket::tcp::State::CloseWait;
                state.delivery.rx_fin_received = true;
                
                actions.push(Action::StateTransition {
                    new_state: crate::socket::tcp::State::CloseWait,
                });
            }
            _ => {}
        }
        
        actions
    }
}

// ================================================================================
// RELIABLE & ORDERED DELIVERY LOGIC - Can only modify delivery state
// ================================================================================

struct ReliableDeliveryLogic;

impl ReliableDeliveryLogic {
    /// Can ONLY modify ReliableOrderedDelivery, everything else is read-only
    fn process_data_segment(
        delivery: &mut ReliableOrderedDelivery,  // ONLY this is mutable!
        conn_mgmt: &ConnectionManagement,        // Read-only
        flow_control: &FlowControlState,         // Read-only
        rx_buffer: &mut SocketBuffer,            // Buffer access needed
        seq: TcpSeqNumber,
        data: Vec<u8>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        
        // Can only READ connection state
        if conn_mgmt.tcp_state != crate::socket::tcp::State::Established {
            return actions;
        }
        
        // Check sequence number (modifying ONLY delivery state)
        if seq == delivery.rcv_nxt {
            // In-order data
            println!("Delivery: In-order data, {} bytes at seq {}", data.len(), seq);
            
            // Can modify delivery state
            delivery.rcv_nxt += data.len();
            delivery.last_ack_sent = Some(delivery.rcv_nxt);
            delivery.dup_ack_count = 0;
            
            // Store in buffer
            rx_buffer.enqueue_slice(&data);
            
            // Generate actions (using read-only flow_control)
            actions.push(Action::DeliverData { data });
            actions.push(Action::SendAck {
                seq: delivery.snd_nxt,
                ack: delivery.rcv_nxt,
                window: flow_control.rcv_wnd,  // Read flow control's window
            });
            
        } else if seq < delivery.rcv_nxt {
            // Old data
            println!("Delivery: Old data at seq {}, expecting {}", seq, delivery.rcv_nxt);
            
            delivery.dup_ack_count += 1;
            
            actions.push(Action::SendAck {
                seq: delivery.snd_nxt,
                ack: delivery.rcv_nxt,
                window: flow_control.rcv_wnd,  // Read flow control's window
            });
            
        } else {
            // Future data (out of order)
            println!("Delivery: Out-of-order data at seq {}, expecting {}", seq, delivery.rcv_nxt);
            
            delivery.dup_ack_count += 1;
            
            // TODO: Buffer in assembler (part of delivery state)
            
            actions.push(Action::SendAck {
                seq: delivery.snd_nxt,
                ack: delivery.rcv_nxt,
                window: flow_control.rcv_wnd,  // Read flow control's window
            });
        }
        
        actions
    }
    
    /// Process ACKs - only modify delivery state
    fn process_ack(
        delivery: &mut ReliableOrderedDelivery,  // ONLY this is mutable!
        conn_mgmt: &ConnectionManagement,        // Read-only
        ack: TcpSeqNumber,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        
        // Can only READ connection state
        if conn_mgmt.tcp_state != crate::socket::tcp::State::Established {
            return actions;
        }
        
        // Update ONLY delivery state
        if ack > delivery.remote_last_ack.unwrap_or(TcpSeqNumber(0)) {
            println!("Delivery: New ACK for seq {}", ack);
            delivery.remote_last_ack = Some(ack);
            // TODO: Mark acknowledged segments
        } else {
            println!("Delivery: Duplicate ACK for seq {}", ack);
            // TODO: Count for fast retransmit
        }
        
        actions
    }
}

// ================================================================================
// FLOW CONTROL LOGIC - Can only modify flow control state
// ================================================================================

struct FlowControlLogic;

impl FlowControlLogic {
    /// Can ONLY modify FlowControlState, everything else is read-only
    fn process_window_update(
        flow_control: &mut FlowControlState,     // ONLY this is mutable!
        conn_mgmt: &ConnectionManagement,        // Read-only
        delivery: &ReliableOrderedDelivery,      // Read-only
        window: u16,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        
        // Can only READ connection state
        if conn_mgmt.tcp_state != crate::socket::tcp::State::Established {
            return actions;
        }
        
        // Update ONLY flow control state
        let old_window = flow_control.snd_wnd;
        flow_control.snd_wnd = window;
        
        if old_window == 0 && window > 0 {
            println!("Flow: Window opened from zero");
            // TODO: Trigger zero window probe timer stop
        }

        actions
    }
    
    /// Calculate our receive window
    fn calculate_receive_window(
        flow_control: &mut FlowControlState,     // ONLY this is mutable!
        rx_buffer: &SocketBuffer,                // Read buffer state
    ) -> u16 {
        // Update our receive window based on buffer space
        let available = rx_buffer.window() as u16;
        flow_control.rcv_wnd = available;
        available
    }
}

// ================================================================================
// CONGESTION CONTROL LOGIC - Can only modify congestion state (when added)
// ================================================================================

struct CongestionControlLogic;

impl CongestionControlLogic {
    /// Can ONLY modify CongestionState, everything else is read-only
    fn process_ack_for_congestion(
        congestion: &mut CongestionState,        // ONLY this is mutable!
        delivery: &ReliableOrderedDelivery,      // Read-only
        ack: TcpSeqNumber,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        
        // Update congestion window based on ACK
        if ack > delivery.remote_last_ack.unwrap_or(TcpSeqNumber(0)) {
            // New ACK - increase window
            if congestion.cwnd < congestion.ssthresh {
                // Slow start
                congestion.cwnd += 1;
            } else {
                // Congestion avoidance
                congestion.cwnd += 1 / congestion.cwnd;
            }
        }
        
        actions
    }
}

// ================================================================================
// MAIN SOCKET IMPLEMENTATION
// ================================================================================

impl<'a> Socket<'a> {
    pub fn new(rx_buffer: SocketBuffer<'a>, tx_buffer: SocketBuffer<'a>) -> Self {
        Socket {
            state: TcpState::default(),
            rx_buffer,
            tx_buffer,
            events: VecDeque::new(),
        }
    }
    
    fn queue_packet_events(&mut self, tcp_repr: &TcpRepr) {
        if tcp_repr.control != TcpControl::None {
            self.events.push_back(Event::ControlPacket {
                control: tcp_repr.control,
                seq: tcp_repr.seq_number,
                ack: tcp_repr.ack_number,
            });
        }
        
        if !tcp_repr.payload.is_empty() {
            self.events.push_back(Event::DataReceived {
                seq: tcp_repr.seq_number,
                data: tcp_repr.payload.to_vec(),
            });
        }
        
        if let Some(ack_number) = tcp_repr.ack_number {
            self.events.push_back(Event::AckReceived {
                ack: ack_number,
                window: tcp_repr.window_len,
            });
        }
    }
    
    /// Process events with STRICT component separation
    fn process_events(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        
        while let Some(event) = self.events.pop_front() {
            match event {
                Event::ControlPacket { control, seq, ack } => {
                    // Control gets EVERYTHING mutable
                    let control_actions = ControlLogic::process_control_event(
                        &mut self.state,  // ALL mutable!
                        control,
                        seq,
                        ack,
                    );
                    actions.extend(control_actions);
                }
                
                Event::DataReceived { seq, data } => {
                    // Reliable Delivery Logic ONLY gets delivery mutable
                    let delivery_actions = ReliableDeliveryLogic::process_data_segment(
                        &mut self.state.delivery,      // ONLY this mutable!
                        &self.state.conn_mgmt,         // Read-only
                        &self.state.flow_control,      // Read-only
                        &mut self.rx_buffer,
                        seq,
                        data,
                    );
                    actions.extend(delivery_actions);
                }
                
                Event::AckReceived { ack, window } => {
                    // Process ACK in delivery component
                    let ack_actions = ReliableDeliveryLogic::process_ack(
                        &mut self.state.delivery,      // ONLY this mutable!
                        &self.state.conn_mgmt,         // Read-only
                        ack,
                    );
                    actions.extend(ack_actions);
                    
                    // Process window update in flow control component
                    let window_actions = FlowControlLogic::process_window_update(
                        &mut self.state.flow_control,  // ONLY this mutable!
                        &self.state.conn_mgmt,         // Read-only
                        &self.state.delivery,          // Read-only
                        window,
                    );
                    actions.extend(window_actions);
                    
                    // Process ACK for congestion control
                    if self.state.congestion.is_some() {
                        let congestion_actions = CongestionControlLogic::process_ack_for_congestion(
                            self.state.congestion.as_mut().unwrap(),  // ONLY this mutable!
                            &self.state.delivery,          // Read-only
                            ack,
                        );
                        actions.extend(congestion_actions);
                    }
                }
                
                Event::TimerExpired => {
                    // TODO: Route to appropriate component
                }
            }
        }
        
        actions
    }
    
    pub fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state.conn_mgmt.tcp_state == State::Closed {
            return false;
        }

        // If we're still listening for SYNs and the packet has an ACK or a RST,
        // it cannot be destined to this socket, but another one may well listen
        // on the same local endpoint.
        if self.state.conn_mgmt.tcp_state == State::Listen
            && (repr.ack_number.is_some() || repr.control == TcpControl::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.state.conn_mgmt.tuple {
            // Reject packets not matching the 4-tuple
            ip_repr.dst_addr() == tuple.local.addr
                && repr.dst_port == tuple.local.port
                && ip_repr.src_addr() == tuple.remote.addr
                && repr.src_port == tuple.remote.port
        } else {
            // We're listening, reject packets not matching the listen endpoint.
            let addr_ok = match self.state.conn_mgmt.listen_endpoint.addr {
                Some(addr) => ip_repr.dst_addr() == addr,
                None => true,
            };
            addr_ok && repr.dst_port != 0 && repr.dst_port == self.state.conn_mgmt.listen_endpoint.port
        }
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if !self.accepts(cx, ip_repr, repr) {
            return None;  // Don't process packets not for us
        }
        self.queue_packet_events(repr);
        let actions = self.process_events();
        self.actions_to_response(actions, ip_repr, repr)
    }
        
    fn actions_to_response(
        &self,
        actions: Vec<Action>,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        for action in actions {
            match action {
                Action::SendAck { seq, ack, window } => {
                    return Some(self.create_ack_packet(ip_repr, tcp_repr, seq, ack, window));
                }
                Action::SendSynAck { seq, ack, window } => {
                    return Some(self.create_syn_ack_packet(ip_repr, tcp_repr, seq, ack, window));
                }
                _ => {}
            }
        }
        None
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
    
    fn create_syn_ack_packet(
        &self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        window: u16,
    ) -> (IpRepr, TcpRepr<'static>) {
        let syn_ack_repr = TcpRepr {
            src_port: tcp_repr.dst_port,
            dst_port: tcp_repr.src_port,
            control: TcpControl::Syn,
            seq_number: seq,
            ack_number: Some(ack),
            window_len: window,
            window_scale: Some(0),
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        
        let response_ip = self.swap_ip_addresses(ip_repr, syn_ack_repr.buffer_len());
        (response_ip, syn_ack_repr)
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
    
    pub fn set_sequence_numbers(&mut self, rcv_nxt: u32, snd_nxt: u32) {
        self.state.delivery.rcv_nxt = TcpSeqNumber(rcv_nxt.try_into().unwrap());
        self.state.delivery.snd_nxt = TcpSeqNumber(snd_nxt.try_into().unwrap());
    }
    
    pub fn set_state(&mut self, state: crate::socket::tcp::State) {
        self.state.conn_mgmt.tcp_state = state;
    }
}

#[cfg(test)]
mod tests {
    /*
    use super::*;
    use crate::wire::{IpRepr, IpListenEndpoint, IpEndpoint, IpAddress};
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;
    use crate::time::{Duration, Instant};
    use crate::socket::tcp::State;
    use crate::socket::tcp::{ConnectError, ListenError};
    use crate::storage::Assembler;

    const DEFAULT_MSS: usize = 536;
    const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
    const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

    struct Tuple {
        local: IpEndpoint,
        remote: IpEndpoint,
    }

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LISTEN_END: IpListenEndpoint = IpListenEndpoint {
        addr: None,
        port: LOCAL_PORT,
    };
    const TUPLE: Tuple = Tuple {
        local: LOCAL_END,
        remote: REMOTE_END,
    };
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

            const BASE_MSS: u16 = 1460;

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);

            const BASE_MSS: u16 = 1440;

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        }
    }

    const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    const _RECV_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        socket: Socket<'static>,
        cx: Context,
    }

    impl Deref for TestSocket {
        type Target = Socket<'static>;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    #[track_caller]
    fn send(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
    ) -> Option<TcpRepr<'static>> {
        socket.cx.set_now(timestamp);

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        net_trace!("send: {}", repr);

        assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

        match socket.socket.process(&mut socket.cx, &ip_repr, repr) {
            Some((_ip_repr, repr)) => {
                net_trace!("recv: {}", repr);
                Some(repr)
            }
            None => None,
        }
    }

    #[track_caller]
    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr, ()>),
    {
        socket.cx.set_now(timestamp);

        let mut sent = 0;
        let result = socket
            .socket
            .dispatch(&mut socket.cx, |_, (ip_repr, tcp_repr)| {
                assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);
                assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
                assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
                assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

                net_trace!("recv: {}", tcp_repr);
                sent += 1;
                Ok(f(Ok(tcp_repr)))
            });
        match result {
            Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
            Err(e) => f(Err(e)),
        }
    }

    #[track_caller]
    fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
        socket.cx.set_now(timestamp);

        let mut fail = false;
        let result: Result<(), ()> = socket.socket.dispatch(&mut socket.cx, |_, _| {
            fail = true;
            Ok(())
        });
        if fail {
            panic!("Should not send a packet")
        }

        assert_eq!(result, Ok(()))
    }

    #[collapse_debuginfo(yes)]
    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, None));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv_nothing!($socket)
        });
        ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
            $( recv!($socket, time $time, Ok($repr)); )*
            recv_nothing!($socket, time $time)
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv_nothing {
        ($socket:ident) => (recv_nothing!($socket, time 0));
        ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.tuple, s2.tuple, "tuple");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win, s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);

        let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        socket.set_ack_delay(None);
        TestSocket {
            socket,
            cx: iface.inner,
        }
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state.conn_mgmt.tcp_state = State::SynReceived;
        s.state.conn_mgmt.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state.conn_mgmt.tcp_state = State::SynSent;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state.conn_mgmt.tcp_state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = s.scaled_window();
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state.conn_mgmt.tcp_state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state.conn_mgmt.tcp_state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state.conn_mgmt.tcp_state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.timer = Timer::Retransmit {
            expires_at: Instant::from_millis_const(1000),
        };
        s
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state.conn_mgmt.tcp_state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state.conn_mgmt.tcp_state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state.conn_mgmt.tcp_state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TestSocket {
        let mut s = socket();
        s.state.conn_mgmt.tcp_state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        s
    }

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state.conn_mgmt.tcp_state = State::Listen;
            s.listen_endpoint = LISTEN_END;
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(ListenError::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
        assert_eq!(s.listen(80), Ok(()));
        s.set_state(State::SynReceived); // state change, simulate incoming connection
        assert_eq!(s.listen(80), Err(ListenError::InvalidState));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state.conn_mgmt.tcp_state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        let tcp_repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Listen);
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        sanity!(s, socket_established());
    }

    #[cfg(feature = "socket-tcp-pause-synack")]
    #[test]
    fn test_syn_paused_ack() {
        let mut s = socket_syn_received();

        s.pause_synack(true);
        recv_nothing!(s);
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);

        s.pause_synack(false);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Listen);
        assert_eq!(s.listen_endpoint, LISTEN_END);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.tuple, Some(TUPLE));
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//
 
    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, 80),
            Err(ConnectError::InvalidState)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 1001,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    #[test]
    fn test_peek_slice() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        // Populate the recv buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &send_buf[..],
                ..SEND_TEMPL
            }
        );

        // Peek into the recv buffer
        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }

    #[test]
    fn test_peek_slice_buffer_wrap() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456789";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        let _ = s.rx_buffer.enqueue_slice(&send_buf[..8]);
        let _ = s.rx_buffer.dequeue_many(6);
        let _ = s.rx_buffer.enqueue_slice(&send_buf[..5]);

        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }

    fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
        // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
        // in a particular way suitable for those cases.
        //
        // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
        // segments, each containing 500 data bytes.
        let mut s = socket_established_with_buffer_sizes(4000, 4000);
        s.remote_has_sack = true;

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: 3500,
                    ..RECV_TEMPL
                }]
            );
            s.recv(|data| {
                assert_eq!(data.len(), 500);
                assert_eq!(data, segment.as_slice());
                (500, ())
            })
            .unwrap();
        }
        assert_eq!(s.remote_last_win, 3500);
        (s, segment)
    }

    #[test]
    fn test_established_rfc2018_cases() {
        // This test case verifies the exact scenarios described on pages 8-9 of RFC 2018. Please
        // ensure its behavior does not deviate from those scenarios.

        let (mut s, segment) = setup_rfc2018_cases();
        // RFC 2018:
        //
        // Case 2: The first segment is dropped but the remaining 7 are received.
        //
        // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
        // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
        // block of queued data:
        //
        //   Triggering   ACK      Left Edge  Right Edge
        //   Segment
        //
        //   5000         (lost)
        //   5500         5000     5500       6000
        //   6000         5000     5500       6500
        //   6500         5000     5500       7000
        //   7000         5000     5500       7500
        //   7500         5000     5500       8000
        //   8000         5000     5500       8500
        //   8500         5000     5500       9000
        //
        for offset in (500..3500).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 4000,
                    sack_ranges: [
                        Some((
                            REMOTE_SEQ.0 as u32 + 1 + 5500,
                            REMOTE_SEQ.0 as u32 + 1 + 5500 + offset as u32
                        )),
                        None,
                        None
                    ],
                    ..RECV_TEMPL
                })
            );
        }
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.len(), 0);
        s.rx_buffer = SocketBuffer::new(vec![0; 262143]);
        s.assembler = Assembler::new();
        s.remote_win_scale = Some(0);
        s.remote_last_win = 65535;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after adding its data to the assembler.
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
                window_len: 52,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_stated, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send wrong rst again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/smoltcp-rs/smoltcp/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait2);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);

        // ACK received that doesn't ack the FIN: socket should stay in LastAck.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 2399);
        // The second packet should be re-sent.
        recv!(s, time 2400, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();
        s.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 3000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 3005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 3010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();
        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Third duplicate ACK
        // Should trigger a fast retransmit of dropped packet
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit packet
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));

        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1115, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // After all was send out, enter *normal* retransmission,
        // don't stay in fast retransmission.
        assert!(match s.timer {
            Timer::Retransmit { expires_at, .. } => expires_at > Instant::from_millis(1115),
            _ => false,
        });

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx_buffer.is_empty());
        recv_nothing!(s, time 5000);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 999);
        recv!(s, time 1000, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        s.ack_delay = None;

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // Even though the sequence space for the FIN itself is outside the window,
        // it is not data, so FIN must be accepted when window full.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(&buffer[..3], b"abc");
            (3, ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(buffer, b"def");
            (buffer.len(), ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_window_update_with_delay_ack() {
        let mut s = socket_established_with_buffer_sizes(6, 6);
        s.ack_delay = Some(Duration::from_millis(10));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..2], b"ab");
            (2, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 2,
                ..RECV_TEMPL
            })
        );

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"c");
            (1, ())
        })
        .unwrap();
        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"d");
            (1, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 4,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        // Test that `dispatch` updates `remote_last_win`
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        // Provoke immediate ACK to test that `process` updates `remote_last_win`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
    }

    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            time 1010,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1010,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 1100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 6999);
        recv!(
            s,
            time 7000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 3100+1000 = 4100
        recv_nothing!(s, time 4099);
        recv!(
            s,
            time 4100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(Duration::from_millis(100)));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::SynSent);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(250))
        );
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(2000)));
        recv_nothing!(s, time 250);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2250))
        );
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(1255))
        );
        recv!(s, time 1255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2255))
        );
        recv!(s, time 2255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(50)));
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 100);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(150))
        );
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(155))
        );
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 155);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(205))
        );
        recv_nothing!(s, time 200);
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 205);
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.abort();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(100))
        );
        recv_nothing!(s, time 95);
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(200))
        );
        recv_nothing!(s, time 195);
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(350))
        );
        recv_nothing!(s, time 345);
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket.dispatch(&mut s.cx, |_, (ip_repr, _)| {
                assert_eq!(ip_repr.hop_limit(), 0x2a);
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/smoltcp-rs/smoltcp/issues/601.
        s.reset();
        assert_eq!(s.hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abcdef");
            (buffer.len(), ())
        })
        .unwrap();
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abc");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 6];
        assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);

        s.tx_buffer = SocketBuffer::new(vec![b'.'; 9]);
        assert_eq!(s.send_slice(b"xxxyyy"), Ok(6));
        assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
        assert_eq!(s.tx_buffer.len(), 3);

        // "abcdef" not contiguous in tx buffer
        assert_eq!(s.send_slice(b"abcdef"), Ok(6));
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"yyyabc"[..],
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"def"[..],
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::Closing);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state.conn_mgmt.tcp_state, State::TimeWait);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        s.recv(|data| {
            assert_eq!(data, b"");
            (0, ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Error must be `Illegal` even if we've received a FIN,
        // because we are missing data.
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS - 1) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+2 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS - 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef0").unwrap();
        s.socket.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle(Instant::from_millis(1301), None);
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        let rtos = &[
            6000, 5000, 4252, 3692, 3272, 2956, 2720, 2540, 2408, 2308, 2232, 2176, 2132, 2100,
            2076, 2060, 2048, 2036, 2028, 2024, 2020, 2016, 2012, 2012,
        ];

        for &rto in rtos {
            r.sample(2000);
            assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
        }
    }

    #[test]
    fn test_set_get_congestion_control() {
        let mut s = socket_established();

        #[cfg(feature = "socket-tcp-reno")]
        {
            s.set_congestion_control(CongestionControl::Reno);
            assert_eq!(s.congestion_control(), CongestionControl::Reno);
        }

        #[cfg(feature = "socket-tcp-cubic")]
        {
            s.set_congestion_control(CongestionControl::Cubic);
            assert_eq!(s.congestion_control(), CongestionControl::Cubic);
        }

        s.set_congestion_control(CongestionControl::None);
        assert_eq!(s.congestion_control(), CongestionControl::None);
    }

    // =========================================================================================//
    // Timestamp tests
    // =========================================================================================//

    #[test]
    fn test_tsval_established_connection() {
        let mut s = socket_established();
        s.set_tsval_generator(Some(|| 1));

        assert!(s.timestamp_enabled());

        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 500)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_tsval_disabled_in_remote_client() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_local_server() {
        let mut s = socket_listen();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_remote_server() {
        let mut s = socket();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_tsval_disabled_in_local_client() {
        let mut s = socket();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    
    use super::*;
    use crate::wire::{TcpControl, TcpSeqNumber};
    
    // ================================================================================
    // Architecture Enforcement Tests
    // ================================================================================
    
    #[test]
    fn test_control_logic_can_modify_all_state() {
        let mut state = TcpState::default();
        state.conn_mgmt.tcp_state = crate::socket::tcp::State::Listen;
        
        // Control logic should be able to modify everything
        let actions = ControlLogic::process_control_event(
            &mut state,  // Full mutable access
            TcpControl::Syn,
            TcpSeqNumber(1000),
            None,
        );
        
        // Verify it modified connection state
        assert_eq!(state.conn_mgmt.tcp_state, crate::socket::tcp::State::SynReceived);
        // Verify it modified delivery state
        assert_eq!(state.delivery.rcv_nxt, TcpSeqNumber(1001));
    }
    
    #[test]
    fn test_delivery_logic_cannot_modify_other_components() {
        // This test verifies compile-time enforcement
        let mut delivery = ReliableOrderedDelivery::default();
        let conn = ConnectionManagement::default();
        let flow = FlowControlState::default();
        let mut buffer = SocketBuffer::new(vec![0; 1024]);
        
        // Delivery logic can only modify delivery state
        let actions = ReliableDeliveryLogic::process_data_segment(
            &mut delivery,  // Only this is mutable
            &conn,          // Immutable
            &flow,          // Immutable
            &mut buffer,
            TcpSeqNumber(0),
            vec![1, 2, 3],
        );
        
        // The following would NOT compile if uncommented:
        // conn.tcp_state = State::Closed;  // ERROR: cannot borrow as mutable
        // flow.rcv_wnd = 1000;  // ERROR: cannot borrow as mutable
    }
    
    #[test]
    fn test_flow_control_logic_isolation() {
        let mut flow = FlowControlState::default();
        let conn = ConnectionManagement {
            tcp_state: crate::socket::tcp::State::Established,
            ..Default::default()
        };
        let delivery = ReliableOrderedDelivery::default();
        
        // Flow control can only modify flow state
        let actions = FlowControlLogic::process_window_update(
            &mut flow,      // Only this is mutable
            &conn,          // Read-only
            &delivery,      // Read-only
            8192,
        );
        
        // Verify it updated window
        assert_eq!(flow.snd_wnd, 8192);
    }
    
    // ================================================================================
    // Event Processing Tests
    // ================================================================================
    
    #[test]
    fn test_event_queue_processing() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Queue multiple events
        socket.events.push_back(Event::DataReceived {
            seq: TcpSeqNumber(1000),
            data: vec![1, 2, 3],
        });
        socket.events.push_back(Event::AckReceived {
            ack: TcpSeqNumber(5000),
            window: 8192,
        });
        
        // Process all events
        let actions = socket.process_events();
        
        // Should have processed both events
        assert!(socket.events.is_empty());
        // Should generate actions for data and ACK
        assert!(actions.iter().any(|a| matches!(a, Action::DeliverData { .. })));
        assert!(actions.iter().any(|a| matches!(a, Action::SendAck { .. })));
    }
    
    #[test]
    fn test_control_event_state_transition() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Listen);
        
        // Queue SYN event
        socket.events.push_back(Event::ControlPacket {
            control: TcpControl::Syn,
            seq: TcpSeqNumber(1000),
            ack: None,
        });
        
        let actions = socket.process_events();
        
        // Should transition to SynReceived
        assert_eq!(socket.state.conn_mgmt.tcp_state, crate::socket::tcp::State::SynReceived);
        // Should generate SYN-ACK
        assert!(actions.iter().any(|a| matches!(a, Action::SendSynAck { .. })));
    }
    
    // ================================================================================
    // Receiver Functionality Tests
    // ================================================================================
    
    #[test]
    fn test_in_order_data_generates_ack() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Process in-order data
        socket.events.push_back(Event::DataReceived {
            seq: TcpSeqNumber(1000),
            data: vec![1, 2, 3, 4, 5],
        });
        
        let actions = socket.process_events();
        
        // Check ACK was generated with correct values
        let ack_action = actions.iter().find_map(|a| match a {
            Action::SendAck { seq, ack, window } => Some((seq, ack, window)),
            _ => None,
        });
        
        assert!(ack_action.is_some());
        let (seq, ack, window) = ack_action.unwrap();
        assert_eq!(*seq, TcpSeqNumber(5000));    // Our sequence number
        assert_eq!(*ack, TcpSeqNumber(1005));    // 1000 + 5 bytes
        assert_eq!(*window, 8192);
        
        // Verify state was updated
        assert_eq!(socket.state.delivery.rcv_nxt, TcpSeqNumber(1005));
    }
    
    #[test]
    fn test_out_of_order_data_generates_duplicate_ack() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Process future data
        socket.events.push_back(Event::DataReceived {
            seq: TcpSeqNumber(2000),  // Future sequence number
            data: vec![1, 2, 3],
        });
        
        let actions = socket.process_events();
        
        // Should generate duplicate ACK for current position
        let ack_action = actions.iter().find_map(|a| match a {
            Action::SendAck { ack, .. } => Some(ack),
            _ => None,
        });
        
        assert_eq!(*ack_action.unwrap(), TcpSeqNumber(1000));  // Still at 1000
        assert_eq!(socket.state.delivery.dup_ack_count, 1);
    }
    
    #[test]
    fn test_old_data_generates_duplicate_ack() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Process old data
        socket.events.push_back(Event::DataReceived {
            seq: TcpSeqNumber(500),  // Old sequence number
            data: vec![1, 2, 3],
        });
        
        let actions = socket.process_events();
        
        // Should generate ACK for current position
        let ack_action = actions.iter().find_map(|a| match a {
            Action::SendAck { ack, .. } => Some(ack),
            _ => None,
        });
        
        assert_eq!(*ack_action.unwrap(), TcpSeqNumber(1000));
    }
    
    // ================================================================================
    // Integration Tests
    // ================================================================================
    
    #[test]
    fn test_full_packet_processing() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Create a data packet with ACK
        let tcp_repr = TcpRepr {
            src_port: 80,
            dst_port: 1234,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(1000),
            ack_number: Some(TcpSeqNumber(5000)),
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[1, 2, 3],
        };
        
        // Queue events from packet
        socket.queue_packet_events(&tcp_repr);
        
        // Should have both data and ACK events
        assert_eq!(socket.events.len(), 2);
        
        let actions = socket.process_events();
        
        // Verify data was processed
        assert_eq!(socket.state.delivery.rcv_nxt, TcpSeqNumber(1003));
        // Verify window was updated
        assert_eq!(socket.state.flow_control.snd_wnd, 4096);
        // Verify ACK was processed
        assert_eq!(socket.state.delivery.remote_last_ack, Some(TcpSeqNumber(5000)));
    }
    
    #[test]
    fn test_not_established_drops_data() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Listen);
        
        socket.events.push_back(Event::DataReceived {
            seq: TcpSeqNumber(1000),
            data: vec![1, 2, 3],
        });
        
        let actions = socket.process_events();
        
        // Should not process data when not established
        assert!(actions.is_empty());
        // Sequence number should not advance
        assert_eq!(socket.state.delivery.rcv_nxt, TcpSeqNumber(0));
    }
    
    #[test]
    fn test_multiple_duplicate_acks() {
        let rx_buffer = SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        
        socket.set_state(crate::socket::tcp::State::Established);
        socket.set_sequence_numbers(1000, 5000);
        
        // Send multiple out-of-order segments
        for i in 0..3 {
            socket.events.push_back(Event::DataReceived {
                seq: TcpSeqNumber(2000 + i * 100),
                data: vec![1],
            });
        }
        
        let actions = socket.process_events();
        
        // Should have sent 3 duplicate ACKs
        assert_eq!(socket.state.delivery.dup_ack_count, 3);
        
        let ack_count = actions.iter().filter(|a| matches!(a, Action::SendAck { .. })).count();
        assert_eq!(ack_count, 3);
    }
    */
}
