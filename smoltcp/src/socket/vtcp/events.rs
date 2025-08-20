use crate::wire::{TcpSeqNumber, TcpControl};
use crate::socket::tcp::State;

#[derive(Debug)]
pub enum Event {
    /// Control packet received (SYN, FIN, RST)
    ControlPacket {
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
    },
    
    /// Data received
    DataReceived {
        seq: TcpSeqNumber,
        data: Vec<u8>,
    },
    
    /// ACK received
    AckReceived {
        ack: TcpSeqNumber,
        window: u16,
    },
    
    /// Timer expired
    TimerExpired,
}

#[derive(Debug)]
pub enum Action {
    /// Send an ACK
    SendAck {
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        window: u16,
    },
    
    /// Send a SYN-ACK
    SendSynAck {
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        window: u16,
    },
    
    /// Deliver data to application
    DeliverData {
        data: Vec<u8>,
    },
    
    /// State machine transition
    StateTransition {
        new_state: State,
    },
}