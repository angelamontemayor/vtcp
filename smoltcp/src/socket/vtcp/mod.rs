mod state;
mod events;

pub use state::*;
pub use events::*;

use std::collections::VecDeque;
use crate::socket::tcp::SocketBuffer;
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
    
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        self.queue_packet_events(repr);
        let actions = self.process_events();
        self.actions_to_response(actions, ip_repr, repr)
    }
    
    // Helper methods remain the same...
    
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
}
