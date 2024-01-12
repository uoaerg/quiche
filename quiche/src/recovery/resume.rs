
use std::time::{Duration, Instant};
use crate::recovery::Acked;


// to be initialised from environment variables later
const PREVIOUS_RTT: Duration = Duration::from_millis(600);
const JUMP_WINDOW: usize = 2000;

const CR_EVENT_MAXIMUM_GAP: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum CrState {
    OBSERVE,
    RECON,
    UNVAL,
    VALIDATE,
    RETREAT,
    NORMAL,
}

impl Default for CrState {
    fn default() -> Self { CrState::OBSERVE }
}

#[derive(Default)]
pub struct Resume {
    enabled: bool,

    cr_state: CrState,

    previous_rtt: Duration,

    jump_window: usize,

    pub cr_mark: u64,

    pub pipesize: usize,

    recover: u64,
}

impl std::fmt::Debug for Resume {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "cr_state={:?} ", self.cr_state)?;
        write!(f, "last_rtt={:?} ", self.previous_rtt)?;
        write!(f, "jump_window={:?} ", self.jump_window)?;
        write!(f, "cr_mark={:?} ", self.cr_mark)?;
        write!(f, "pipesize={:?} ", self.pipesize)?;
        write!(f, "recover={:?} ", self.recover)?;

        Ok(())
    }
}

impl Resume {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,

            //Starting at recon as draft does not yet discuss observe
            cr_state: CrState::RECON,

            previous_rtt: PREVIOUS_RTT,

            jump_window: JUMP_WINDOW,

            pipesize: 0,

            recover: 0,

            ..Default::default()
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.enabled);
    }

    pub fn enabled(&self) -> bool {
        if self.enabled {
            match self.cr_state {
                CrState::NORMAL => false,
                _ => true,
            }
        } else {
            false
        }
    }

    pub fn process_ack(&mut self, largest_pkt_sent: u64, packet: &Acked, flightsize: usize) -> usize {

        if let CrState::UNVAL = self.cr_state {
           self.pipesize += packet.size;
           }

        if let CrState::VALIDATE = self.cr_state {
           self.pipesize += packet.size;
           }

        match (&self.cr_state, packet.pkt_num >= self.cr_mark) {
            (CrState::UNVAL, true) => {
                // move to validating
                self.cr_state = CrState::VALIDATE;
                self.cr_mark  = largest_pkt_sent;
                return flightsize;
            }
            (CrState::VALIDATE, true) => {
                self.cr_state = CrState::NORMAL;
            }
            _ => {
                //in here we can handle other cases
            }
        }
        // this is do_recovery!
        if let CrState::RETREAT = self.cr_state {

            if packet.pkt_num < self.recover {
                self.pipesize += packet.size;
            }
            else {
                self.cr_state = CrState::NORMAL;
                return self.pipesize;
            }
        }
        //otherwise we return 0 aka we don't touch ssthresh
        return 0;
    }

    pub fn send_packet(&mut self, rtt_sample: Duration, flightsize: usize, cwnd: usize, smss: usize, largest_pkt_sent: u64) -> usize {
        match (&self.cr_state, flightsize >= cwnd) {
            (CrState::RECON, true) => {
                if cwnd >= self.jump_window * smss {
                    self.cr_state = CrState::NORMAL;
                    return 0;
                }
                if rtt_sample <= self.previous_rtt / 2 || rtt_sample >= self.previous_rtt * 10 {
                    self.cr_state = CrState::NORMAL;
                    return 0;
                }
                // move to validating and update mark
                self.cr_state = CrState::UNVAL;
                self.cr_mark = largest_pkt_sent;
                self.pipesize = flightsize;
                // we return the jump window, CC code handles the increase in cwnd
                return self.jump_window * smss - flightsize;
            }
            _ => {
                // Otherwise we don't touch the cwnd
                return 0;
            }
        }
    }

    pub fn congestion_event(&mut self, largest_pkt_sent: u64) -> bool {
        match self.cr_state {
            CrState::VALIDATE | CrState::UNVAL => {
                self.cr_state = CrState::RETREAT;
                self.recover = largest_pkt_sent;
                true
            }
            _ => {
                false
            }
        }
    }

    pub fn get_cr_state(&self) -> u64 {
        match self.cr_state {
            CrState::OBSERVE => { 0 }
            CrState::RECON => { 1 }
            CrState::UNVAL => { 2 }
            CrState::VALIDATE => { 3 }
            CrState::NORMAL => { 4 }
            CrState::RETREAT => { 100 }
        }
    }

    pub fn in_retreat(&self) -> bool {
        if self.enabled {
            match self.cr_state {
                CrState::RETREAT => true,
                _ => false,
            }
        } else {
            false
        }
    }

}

pub struct CRMetrics {
    trace_id: String,
    iw: usize,
    min_rtt: Duration,
    cwnd: usize,
    last_update: Instant
}

impl CRMetrics {
    pub fn new(trace_id: &str, iw: usize) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            iw,
            min_rtt: Duration::ZERO,
            cwnd: 0,
            last_update: Instant::now()
        }
    }

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
                min_rtt: new_min_rtt
            })
        } else {
            None
        }
    }
}

pub struct CREvent {
    pub min_rtt: Duration,
    pub cwnd: usize,
}