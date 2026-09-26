use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimers {
    retransmit_at: Option<Instant>,
    idle_at: Instant,
}

impl SessionTimers {
    pub(crate) fn new(now: Instant, retransmit_after: Duration) -> Self {
        Self {
            retransmit_at: Some(now + retransmit_after),
            idle_at: now,
        }
    }

    pub(crate) fn for_session(now: Instant) -> Self {
        Self::new(now, Duration::from_millis(250))
    }

    pub(crate) fn refresh(&mut self, now: Instant) {
        *self = Self::for_session(now);
    }

    pub(crate) fn retransmit_due(&self, now: Instant) -> bool {
        self.retransmit_at
            .map(|deadline| now >= deadline)
            .unwrap_or(false)
    }

    pub(crate) fn mark_retransmitted(&mut self, now: Instant) {
        self.retransmit_at = Some(now + Duration::from_millis(250));
    }

    pub(crate) fn idle_expired(&self, now: Instant, idle_timeout: Duration) -> bool {
        now.duration_since(self.idle_at) >= idle_timeout
    }
}
