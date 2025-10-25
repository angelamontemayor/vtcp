use crate::wire::{TcpSeqNumber, TcpControl};
use crate::socket::tcp::State;
use crate::time::Instant;
use super::state::Tuple;

/// Events for Reliable & Ordered Delivery component
#[derive(Debug)]
pub enum DeliveryEvent {
    InOrderData { seq: TcpSeqNumber, data: Vec<u8> },
    OutOfOrderData { seq: TcpSeqNumber, data: Vec<u8> },
    // when data is acknowledged, we need to remove it from rx buffer
    DataAcknowledged {
        ack_number: TcpSeqNumber,
        acked_bytes: usize,
    },
}

/// Events for Flow Control component  
#[derive(Debug)]
pub enum FlowEvent {
    RemoteWindowUpdate{ new_window: usize, window_scale: u8},
    RemoteWindowZero{},
}

/// Events for Congestion Control component
#[derive(Debug)]
pub enum CongestionEvent {
    NewAck { ack: TcpSeqNumber, now: Instant },
    DuplicateAck { ack: TcpSeqNumber, now: Instant },
    Timeout { now: Instant },
}

pub enum ConnectionEvent {
    NewState {state: State},
    NewTuple {tuple: Tuple},
}

// Control events (can modify all state)
#[derive(Debug)]
pub enum ControlEvent {
    ControlPacket { 
        control: TcpControl, 
        seq: TcpSeqNumber, 
        ack: Option<TcpSeqNumber> 
    },
    TimerExpired,
}
