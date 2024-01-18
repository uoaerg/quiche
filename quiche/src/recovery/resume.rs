use std::time::{Duration, Instant};
use crate::recovery::Acked;

const CR_EVENT_MAXIMUM_GAP: Duration = Duration::from_secs(60);

// No observe state as that always applies to the previous connection and never the current connection
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CrState {
    Reconnaissance,
    // The next two states store the first packet sent when entering that state
    Unvalidated(u64),
    Validating(u64),
    // Stores the last packet sent during the Unvalidated Phase
    SafeRetreat(u64),
    Normal,
}

impl Default for CrState {
    fn default() -> Self { CrState::Reconnaissance }
}

pub struct Resume {
    trace_id: String,
    enabled: bool,
    cr_state: CrState,
    previous_rtt: Duration,
    previous_cwnd: usize,
    pipesize: usize,
}

impl std::fmt::Debug for Resume {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "cr_state={:?} ", self.cr_state)?;
        write!(f, "previous_rtt={:?} ", self.previous_rtt)?;
        write!(f, "previous_cwnd={:?} ", self.previous_cwnd)?;
        write!(f, "pipesize={:?} ", self.pipesize)?;

        Ok(())
    }
}

impl Resume {
    pub fn new(trace_id: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            enabled: false,
            cr_state: CrState::Reconnaissance,
            previous_rtt: Duration::ZERO,
            previous_cwnd: 0,
            pipesize: 0,
        }
    }

    pub fn setup(&mut self, previous_rtt: Duration, previous_cwnd: usize) {
        self.enabled = true;
        self.previous_rtt = previous_rtt;
        self.previous_cwnd = previous_cwnd;
        trace!("{} careful resume configured", self.trace_id);
    }

    pub fn reset(&mut self) {
        self.cr_state = CrState::Reconnaissance;
        self.pipesize = 0;
    }

    pub fn enabled(&self) -> bool {
        if self.enabled {
            self.cr_state != CrState::Normal
        } else {
            false
        }
    }

    // Returns (new_cwnd, new_ssthresh), both optional
    pub fn process_ack(
        &mut self, largest_pkt_sent: u64, packet: &Acked, flightsize: usize
    ) -> (Option<usize>, Option<usize>) {
        match self.cr_state {
            CrState::Unvalidated(first_packet) => {
                self.pipesize += packet.size;
                if packet.pkt_num >= first_packet {
                    trace!("{} entering careful resume validating phase", self.trace_id);
                    // Store the last packet number that was sent in the Unvalidated Phase
                    self.cr_state = CrState::Validating(largest_pkt_sent);
                    (Some(flightsize), None)
                } else {
                    (None, None)
                }
            }
            CrState::Validating(last_packet) => {
                self.pipesize += packet.size;
                if packet.pkt_num >= last_packet {
                    trace!("{} careful resume complete", self.trace_id);
                    self.cr_state = CrState::Normal;
                }
                (None, None)
            }
            CrState::SafeRetreat(last_packet) => {
                if packet.pkt_num >= last_packet {
                    trace!("{} careful resume complete", self.trace_id);
                    self.cr_state = CrState::Normal;
                    (None, Some(self.pipesize))
                } else {
                    self.pipesize += packet.size;
                    (None, None)
                }
            }
            _ => (None, None)
        }
    }

    pub fn send_packet(
        &mut self, rtt_sample: Duration, cwnd: usize, largest_pkt_sent: u64, app_limited: bool,
    ) -> usize {
        // Do nothing when data limited to avoid having insufficient data
        // to be able to validate transmission at a higher rate
        if app_limited {
            return 0;
        }

        if self.cr_state == CrState::Reconnaissance {
            // Confirm RTT is similar to that of the previous connection
            if rtt_sample <= self.previous_rtt / 2 || rtt_sample >= self.previous_rtt * 10 {
                trace!(
                    "{} current RTT too divergent from previous RTT - not using careful resume; \
                    rtt_sample={:?} previous_rtt={:?}",
                    self.trace_id, rtt_sample, self.previous_rtt
                );
                self.cr_state = CrState::Normal;
                return 0;
            }

            // Store the first packet number that was sent in the Unvalidated Phase
            trace!("{} entering careful resume unvalidated phase", self.trace_id);
            self.cr_state = CrState::Unvalidated(largest_pkt_sent);
            self.pipesize = cwnd;
            // we return the jump window, CC code handles the increase in cwnd
            return (self.previous_cwnd / 2) - cwnd;
        }

        0
    }

    pub fn congestion_event(&mut self, largest_pkt_sent: u64) -> usize {
        match self.cr_state {
            CrState::Unvalidated(_) => {
                trace!("{} congestion during unvalidated phase", self.trace_id);
                // TODO: mark used CR parameters as invalid for future connections
                self.cr_state = CrState::SafeRetreat(largest_pkt_sent);
                self.pipesize / 2
            }
            CrState::Validating(p) => {
                trace!("{} congestion during validating phase", self.trace_id);
                // TODO: mark used CR parameters as invalid for future connections
                self.cr_state = CrState::SafeRetreat(p);
                self.pipesize / 2
            }
            CrState::Reconnaissance => {
                trace!("{} congestion during reconnaissance - abandoning careful resume", self.trace_id);
                self.cr_state = CrState::Normal;
                0
            }
            _ => {
                0
            }
        }
    }

    pub fn get_cr_mark(&self) -> u64 {
        match self.cr_state {
            CrState::Reconnaissance | CrState::Normal => 0,
            CrState::Unvalidated(m) | CrState::Validating(m) | CrState::SafeRetreat(m) => m,
        }
    }

    pub fn get_cr_state(&self) -> u64 {
        match self.cr_state {
            CrState::Reconnaissance => { 1 }
            CrState::Unvalidated(_) => { 2 }
            CrState::Validating(_) => { 3 }
            CrState::Normal => { 4 }
            CrState::SafeRetreat(_) => { 100 }
        }
    }
}

pub struct CRMetrics {
    trace_id: String,
    iw: usize,
    min_rtt: Duration,
    cwnd: usize,
    last_update: Instant,
}

impl CRMetrics {
    pub fn new(trace_id: &str, iw: usize) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            iw,
            min_rtt: Duration::ZERO,
            cwnd: 0,
            last_update: Instant::now(),
        }
    }

    // Implementation of the CR observe phase
    pub fn maybe_update(&mut self, new_min_rtt: Duration, new_cwnd: usize) -> Option<CREvent> {
        // Initial guess at something that might work, needs further research
        let now = Instant::now();
        let time_since_last_update = now - self.last_update;

        let should_update = if new_cwnd < self.iw * 4 {
            false
        } else if time_since_last_update > CR_EVENT_MAXIMUM_GAP {
            true
        } else {
            let secs_since_last_update = time_since_last_update.as_secs_f64();
            if secs_since_last_update == 0.0 {
                false
            } else {
                let range = 1.0f64 / secs_since_last_update;

                let min_rtt_micros = self.min_rtt.as_micros() as f64;
                let min_rtt_range_spread = min_rtt_micros * range;
                let min_rtt_range_min = min_rtt_micros - min_rtt_range_spread;
                let min_rtt_range_max = min_rtt_micros + min_rtt_range_spread;

                let cwnd = self.cwnd as f64;
                let cwnd_range_spread = cwnd * range;
                let cwnd_range_min = cwnd - cwnd_range_spread;
                let cwnd_range_max = cwnd + cwnd_range_spread;

                let new_min_rtt_micros = new_min_rtt.as_micros() as f64;
                let new_cwnd_float = new_cwnd as f64;

                new_min_rtt_micros < min_rtt_range_min || new_min_rtt_micros > min_rtt_range_max ||
                    new_cwnd_float < cwnd_range_min || new_cwnd_float > cwnd_range_max
            }
        };

        trace!(
            "{} maybe_update(new_min_rtt={:?}, new_cwnd={}); updating={}",
            self.trace_id, new_min_rtt, new_cwnd, should_update
        );

        if should_update {
            self.min_rtt = new_min_rtt;
            self.cwnd = new_cwnd;
            self.last_update = now;

            Some(CREvent {
                cwnd: new_cwnd,
                min_rtt: new_min_rtt,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CREvent {
    pub min_rtt: Duration,
    pub cwnd: usize,
}