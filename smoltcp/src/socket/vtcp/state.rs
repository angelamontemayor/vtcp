use crate::time::{Duration, Instant};

use crate::socket::tcp::{SocketBuffer, State};
use crate::socket::PollAt;
use crate::wire::{TcpSeqNumber, IpEndpoint, IpListenEndpoint};
use crate::storage::Assembler;

mod congestion;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Tuple {
    pub local: IpEndpoint,
    pub remote: IpEndpoint,
}
/// Connection Management - TCP state machine and connection info
/// Only Control Logic can modify this
#[derive(Debug)]
pub struct ConnectionManagementState {
    /// TCP state (CLOSED, LISTEN, ESTABLISHED, etc.)
    pub tcp_state: State,
    pub listen_endpoint: IpListenEndpoint,
    pub tuple: Option<Tuple>,
    pub timeout: Option<Duration>,
    pub keep_alive: Option<Duration>,
    pub hop_limit: Option<u8>,
    pub rx_fin_received: bool,
    pub challenge_ack_timer: Instant,     // Rate limiting timer
}

impl Default for ConnectionManagementState {
    fn default() -> Self {
        Self {
            tcp_state: State::Established,
            listen_endpoint: IpListenEndpoint::default(),
            tuple: None,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            rx_fin_received: false,
            challenge_ack_timer: Instant::now(),
        }
    }
}

const RTTE_INITIAL_RTO: u32 = 1000;
const RTTE_MIN_MARGIN: u32 = 5;
const RTTE_K: u32 = 4;
const RTTE_MIN_RTO: u32 = 1000;
const RTTE_MAX_RTO: u32 = 60_000;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RttEstimator {
    /// true if we have made at least one rtt measurement.
    have_measurement: bool,
    // Using u32 instead of Duration to save space (Duration is i64)
    /// Smoothed RTT
    srtt: u32,
    /// RTT variance.
    rttvar: u32,
    /// Retransmission Time-Out
    rto: u32,
    timestamp: Option<(Instant, TcpSeqNumber)>,
    max_seq_sent: Option<TcpSeqNumber>,
    rto_count: u8,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            have_measurement: false,
            srtt: 0,
            rttvar: 0,
            rto: RTTE_INITIAL_RTO,
            timestamp: None,
            max_seq_sent: None,
            rto_count: 0,
        }
    }
}

impl RttEstimator {
    fn retransmission_timeout(&self) -> Duration {
        Duration::from_millis(self.rto as _)
    }

    fn sample(&mut self, new_rtt: u32) {
        if self.have_measurement {
            // RFC 6298 (2.3) When a subsequent RTT measurement R' is made, a host MUST set (...)
            let diff = (self.srtt as i32 - new_rtt as i32).unsigned_abs();
            self.rttvar = (self.rttvar * 3 + diff).div_ceil(4);
            self.srtt = (self.srtt * 7 + new_rtt).div_ceil(8);
        } else {
            // RFC 6298 (2.2) When the first RTT measurement R is made, the host MUST set (...)
            self.have_measurement = true;
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        }

        // RFC 6298 (2.2), (2.3)
        let margin = RTTE_MIN_MARGIN.max(self.rttvar * RTTE_K);
        self.rto = (self.srtt + margin).clamp(RTTE_MIN_RTO, RTTE_MAX_RTO);

        self.rto_count = 0;

        /* 
        tcp_trace!(
            "rtte: sample={:?} srtt={:?} rttvar={:?} rto={:?}",
            new_rtt,
            self.srtt,
            self.rttvar,
            self.rto
        );*/
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self
            .max_seq_sent
            .map(|max_seq_sent| seq > max_seq_sent)
            .unwrap_or(true)
        {
            self.max_seq_sent = Some(seq);
            if self.timestamp.is_none() {
                self.timestamp = Some((timestamp, seq));
                //tcp_trace!("rtte: sampling at seq={:?}", seq);
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if let Some((sent_timestamp, sent_seq)) = self.timestamp {
            if seq >= sent_seq {
                self.sample((timestamp - sent_timestamp).total_millis() as u32);
                self.timestamp = None;
            }
        }
    }

    fn on_retransmit(&mut self) {
        if self.timestamp.is_some() {
            //tcp_trace!("rtte: abort sampling due to retransmit");
        }
        self.timestamp = None;

        // RFC 6298 (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        self.rto = (self.rto * 2).min(RTTE_MAX_RTO);
        //tcp_trace!("rtte: doubling rto to {:?}", self.rto);

        // RFC 6298: a TCP implementation MAY clear SRTT and RTTVAR after
        // backing off the timer multiple times as it is likely that the current
        // SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
        // are cleared, they should be initialized with the next RTT sample
        // taken per (2.2) rather than using (2.3).
        self.rto_count += 1;
        if self.rto_count >= 3 {
            self.rto_count = 0;
            self.have_measurement = false;
            //tcp_trace!("rtte: too many retransmissions, clearing srtt, rttvar.");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retransmit {
        expires_at: Instant,
    },
    FastRetransmit,
    ZeroWindowProbe {
        expires_at: Instant,
        delay: Duration,
    },
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

impl Timer {
    fn new() -> Timer {
        Timer::Idle {
            keep_alive_at: None,
        }
    }

    fn should_keep_alive(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } if timestamp >= keep_alive_at => true,
            _ => false,
        }
    }

    fn should_retransmit(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Retransmit { expires_at } if timestamp >= expires_at => true,
            Timer::FastRetransmit => true,
            _ => false,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn should_zero_window_probe(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::ZeroWindowProbe { expires_at, .. } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } => PollAt::Time(keep_alive_at),
            Timer::Idle {
                keep_alive_at: None,
            } => PollAt::Ingress,
            Timer::ZeroWindowProbe { expires_at, .. } => PollAt::Time(expires_at),
            Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
            Timer::FastRetransmit => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Time(expires_at),
        }
    }

    fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval),
        }
    }

    fn set_keep_alive(&mut self) {
        if let Timer::Idle { keep_alive_at } = self {
            if keep_alive_at.is_none() {
                *keep_alive_at = Some(Instant::from_millis(0))
            }
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
        if let Timer::Idle { keep_alive_at } = self {
            *keep_alive_at = interval.map(|interval| timestamp + interval)
        }
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. }
            | Timer::FastRetransmit { .. }
            | Timer::Retransmit { .. }
            | Timer::ZeroWindowProbe { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                }
            }
            Timer::Close { .. } => (),
        }
    }

    pub fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY,
        }
    }

    fn set_for_zero_window_probe(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::ZeroWindowProbe {
            expires_at: timestamp + delay,
            delay,
        }
    }

    fn rewind_zero_window_probe(&mut self, timestamp: Instant) {
        if let Timer::ZeroWindowProbe { mut delay, .. } = *self {
            delay = (delay * 2).min(Duration::from_millis(RTTE_MAX_RTO as _));
            *self = Timer::ZeroWindowProbe {
                expires_at: timestamp + delay,
                delay,
            }
        }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Timer::Idle { .. })
    }

    fn is_zero_window_probe(&self) -> bool {
        matches!(self, Timer::ZeroWindowProbe { .. })
    }

    fn is_retransmit(&self) -> bool {
        matches!(self, Timer::Retransmit { .. } | Timer::FastRetransmit)
    }
}



/// Reliable & Ordered Delivery - Sequence numbers and ACK tracking
/// Data Path can modify this
#[derive(Debug)]
pub struct ReliableOrderedDeliveryState<'a> {
    pub rx_buffer: SocketBuffer<'a>,
    pub tx_buffer: SocketBuffer<'a>,
    pub local_seq_no: TcpSeqNumber,
    pub remote_seq_no: TcpSeqNumber,
    pub remote_last_seq: TcpSeqNumber,
    pub remote_last_ack: Option<TcpSeqNumber>,
    pub local_rx_last_seq: Option<TcpSeqNumber>,
    pub local_rx_last_ack: Option<TcpSeqNumber>,
    pub local_rx_dup_acks: u8,
    pub assembler: Assembler,
    pub timer: Timer,
    pub rtte: RttEstimator,
    pub ack_delay: Option<Duration>,      // ACK delay duration
    pub ack_delay_timer: AckDelayTimer,   // Delayed ACK timer
}

impl<'a> ReliableOrderedDeliveryState<'a> {
    fn new(rx_buffer: SocketBuffer<'a>, tx_buffer: SocketBuffer<'a>) -> Self {
        Self {
            rx_buffer,
            tx_buffer,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            local_rx_last_seq: None,
            local_rx_last_ack: None,
            local_rx_dup_acks: 0,
            assembler: Assembler::new(),
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

/// Flow Control - Window management
/// Data Path can modify this
#[derive(Debug)]
pub struct FlowControlState {
    pub remote_last_win: u16,             // Last window length sent
    pub remote_win_len: usize,            // Current remote window size  
    pub remote_win_shift: u8,             // Local window scaling factor
    pub remote_win_scale: Option<u8>,     // Remote window scaling
}

impl Default for FlowControlState {
    fn default() -> Self {
        Self {
            remote_last_win: 0,
            remote_win_len: 0,
            remote_win_shift: 0,
            remote_win_scale: None,
        }
    }
}

#[derive(Debug)]
pub struct CongestionState {
    pub congestion_controller: congestion::AnyController, // Reno/Cubic/None
    pub remote_mss: usize,                // Remote max segment size
    pub nagle: bool,  
}

const DEFAULT_MSS: usize = 536;

impl Default for CongestionState {
    fn default() -> Self {
        Self {
            congestion_controller: congestion::AnyController::new(),
            remote_mss: DEFAULT_MSS,
            nagle: true,
        }
    }
}

/// Complete TCP State with all components
#[derive(Debug)]
pub struct TcpState<'a> {
    pub conn_mgmt: ConnectionManagementState,
    pub delivery: ReliableOrderedDeliveryState<'a>,
    pub flow_control: FlowControlState,
    pub congestion: Option<CongestionState>,  // Optional for now
    // pub demux: DemuxState,  // Add when needed
}

impl<'a> TcpState<'a> {
    pub fn new(rx_buffer: SocketBuffer<'a>, tx_buffer: SocketBuffer<'a>) -> Self {
        Self {
            conn_mgmt: ConnectionManagementState::default(),
            delivery: ReliableOrderedDeliveryState::new(rx_buffer, tx_buffer),
            flow_control: FlowControlState::default(),
            congestion: Some(CongestionState::default()),
        }
    }
}
