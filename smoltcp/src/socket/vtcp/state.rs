use crate::socket::tcp::State;
use crate::wire::TcpSeqNumber;

/// Connection Management - TCP state machine and connection info
/// Only Control Logic can modify this
#[derive(Debug)]
pub struct ConnectionManagement {
    /// TCP state (CLOSED, LISTEN, ESTABLISHED, etc.)
    pub tcp_state: State,
}

impl Default for ConnectionManagement {
    fn default() -> Self {
        Self {
            tcp_state: State::Established,  // Assume established for simple receiver
        }
    }
}

/// Reliable & Ordered Delivery - Sequence numbers and ACK tracking
/// Data Path can modify this
#[derive(Debug)]
pub struct ReliableOrderedDelivery {
    /// Next sequence number we expect to receive
    pub rcv_nxt: TcpSeqNumber, // TODO: angie need to match the names to the ones og impl uses
    
    /// Our next sequence number to send
    pub snd_nxt: TcpSeqNumber,
    
    /// Last ACK we sent (for duplicate ACK detection)
    pub last_ack_sent: Option<TcpSeqNumber>,

    pub remote_last_ack: Option<TcpSeqNumber>,
    
    /// Number of duplicate ACKs sent
    pub dup_ack_count: u8,

    pub rx_fin_received: bool,
}

impl Default for ReliableOrderedDelivery {
    fn default() -> Self {
        Self {
            rcv_nxt: TcpSeqNumber(0),
            snd_nxt: TcpSeqNumber(0),
            last_ack_sent: None,
            remote_last_ack: None,
            dup_ack_count: 0,
            rx_fin_received: false,
        }
    }
}

/// Flow Control - Window management
/// Data Path can modify this
#[derive(Debug)]
pub struct FlowControlState {
    /// Our receive window size
    pub rcv_wnd: u16,
    
    /// Remote's advertised window
    pub snd_wnd: u16,
}

impl Default for FlowControlState {
    fn default() -> Self {
        Self {
            rcv_wnd: 8192,
            snd_wnd: 8192,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CongestionState {
    pub cwnd: usize,
    pub ssthresh: usize,
}

/// Complete TCP State with all components
#[derive(Debug, Default)]
pub struct TcpState {
    pub conn_mgmt: ConnectionManagement,
    pub delivery: ReliableOrderedDelivery,
    pub flow_control: FlowControlState,
    pub congestion: Option<CongestionState>,  // Optional for now
    // pub demux: DemuxState,  // Add when needed
}
