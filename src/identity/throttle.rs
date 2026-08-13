use serde::{Deserialize, Serialize};

use super::CallerId;

pub(crate) const AUTHENTICATION_BUCKET_COUNT: usize = 64;
pub(crate) const AUTHENTICATION_BUCKET_FAILURE_LIMIT: u32 = 5;
pub(crate) const AUTHENTICATION_GLOBAL_FAILURE_LIMIT: u32 = 50;
pub(crate) const AUTHENTICATION_WINDOW_MILLIS: u64 = 60_000;
pub(crate) const AUTHENTICATION_BLOCK_MILLIS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationDisposition {
    Proceed,
    Blocked,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticationThrottleState {
    last_observed_unix_time_millis: u64,
    global: FailureWindow,
    buckets: Vec<FailureWindow>,
}

impl Default for AuthenticationThrottleState {
    fn default() -> Self {
        Self {
            last_observed_unix_time_millis: 0,
            global: FailureWindow::default(),
            buckets: vec![FailureWindow::default(); AUTHENTICATION_BUCKET_COUNT],
        }
    }
}

impl AuthenticationThrottleState {
    pub(crate) const fn last_observed_unix_time_millis(&self) -> u64 {
        self.last_observed_unix_time_millis
    }

    pub(crate) fn disposition(
        &mut self,
        caller_id: CallerId,
        unix_time_millis: u64,
    ) -> AuthenticationDisposition {
        let now = self.observe_time(unix_time_millis);
        if self.global.is_blocked(now) || self.bucket(caller_id).is_blocked(now) {
            AuthenticationDisposition::Blocked
        } else {
            AuthenticationDisposition::Proceed
        }
    }

    pub(crate) fn record_result(
        &mut self,
        caller_id: CallerId,
        unix_time_millis: u64,
        authenticated: bool,
        disposition: AuthenticationDisposition,
    ) {
        let now = self.observe_time(unix_time_millis);
        if disposition == AuthenticationDisposition::Blocked {
            return;
        }
        if authenticated {
            *self.bucket_mut(caller_id) = FailureWindow::default();
            return;
        }
        self.global
            .record_failure(now, AUTHENTICATION_GLOBAL_FAILURE_LIMIT);
        self.bucket_mut(caller_id)
            .record_failure(now, AUTHENTICATION_BUCKET_FAILURE_LIMIT);
    }

    pub(crate) fn clear_bucket(&mut self, caller_id: CallerId) {
        *self.bucket_mut(caller_id) = FailureWindow::default();
    }

    pub(crate) fn to_file(&self) -> AuthenticationThrottleFile {
        AuthenticationThrottleFile {
            last_observed_unix_time_millis: self.last_observed_unix_time_millis,
            global: self.global.into(),
            buckets: self
                .buckets
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, window)| *window != FailureWindow::default())
                .map(|(index, window)| AuthenticationBucketFile {
                    index,
                    window: window.into(),
                })
                .collect(),
        }
    }

    pub(crate) fn from_file(
        file: AuthenticationThrottleFile,
    ) -> Result<Self, AuthenticationThrottleError> {
        if file.buckets.len() > AUTHENTICATION_BUCKET_COUNT {
            return Err(AuthenticationThrottleError);
        }
        let mut buckets = vec![FailureWindow::default(); AUTHENTICATION_BUCKET_COUNT];
        let mut previous_index = None;
        for bucket in file.buckets {
            if bucket.index >= AUTHENTICATION_BUCKET_COUNT
                || previous_index.is_some_and(|previous| bucket.index <= previous)
            {
                return Err(AuthenticationThrottleError);
            }
            buckets[bucket.index] = FailureWindow::try_from(bucket.window)?;
            previous_index = Some(bucket.index);
        }
        let state = Self {
            last_observed_unix_time_millis: file.last_observed_unix_time_millis,
            global: FailureWindow::try_from(file.global)?,
            buckets,
        };
        if !state.is_valid() {
            return Err(AuthenticationThrottleError);
        }
        Ok(state)
    }

    fn observe_time(&mut self, unix_time_millis: u64) -> u64 {
        self.last_observed_unix_time_millis =
            self.last_observed_unix_time_millis.max(unix_time_millis);
        self.last_observed_unix_time_millis
    }

    fn bucket(&self, caller_id: CallerId) -> &FailureWindow {
        &self.buckets[bucket_index(caller_id)]
    }

    fn bucket_mut(&mut self, caller_id: CallerId) -> &mut FailureWindow {
        &mut self.buckets[bucket_index(caller_id)]
    }

    fn is_valid(&self) -> bool {
        self.global.is_valid(
            self.last_observed_unix_time_millis,
            AUTHENTICATION_GLOBAL_FAILURE_LIMIT,
        ) && self.buckets.iter().all(|bucket| {
            bucket.is_valid(
                self.last_observed_unix_time_millis,
                AUTHENTICATION_BUCKET_FAILURE_LIMIT,
            )
        })
    }
}

fn bucket_index(caller_id: CallerId) -> usize {
    usize::from(caller_id.as_bytes()[0] & 0x3f)
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct FailureWindow {
    window_started_unix_time_millis: u64,
    failures: u32,
    blocked_until_unix_time_millis: u64,
}

impl FailureWindow {
    fn is_blocked(self, now: u64) -> bool {
        self.blocked_until_unix_time_millis > now
    }

    fn record_failure(&mut self, now: u64, limit: u32) {
        if self.failures == 0
            || now.saturating_sub(self.window_started_unix_time_millis)
                >= AUTHENTICATION_WINDOW_MILLIS
        {
            self.window_started_unix_time_millis = now;
            self.failures = 0;
            self.blocked_until_unix_time_millis = 0;
        }
        self.failures = self.failures.saturating_add(1).min(limit);
        if self.failures == limit {
            self.blocked_until_unix_time_millis = now.saturating_add(AUTHENTICATION_BLOCK_MILLIS);
        }
    }

    fn is_valid(self, last_observed: u64, limit: u32) -> bool {
        self.failures <= limit
            && (self.window_started_unix_time_millis == 0
                || self.window_started_unix_time_millis <= last_observed)
            && (self.failures != 0 || self.window_started_unix_time_millis == 0)
            && (self.blocked_until_unix_time_millis == 0
                || (self.failures == limit
                    && self.blocked_until_unix_time_millis >= self.window_started_unix_time_millis
                    && self.blocked_until_unix_time_millis
                        <= last_observed.saturating_add(AUTHENTICATION_BLOCK_MILLIS)))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticationThrottleFile {
    last_observed_unix_time_millis: u64,
    global: FailureWindowFile,
    buckets: Vec<AuthenticationBucketFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationBucketFile {
    index: usize,
    window: FailureWindowFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureWindowFile {
    window_started_unix_time_millis: u64,
    failures: u32,
    blocked_until_unix_time_millis: u64,
}

impl From<FailureWindow> for FailureWindowFile {
    fn from(value: FailureWindow) -> Self {
        Self {
            window_started_unix_time_millis: value.window_started_unix_time_millis,
            failures: value.failures,
            blocked_until_unix_time_millis: value.blocked_until_unix_time_millis,
        }
    }
}

impl TryFrom<FailureWindowFile> for FailureWindow {
    type Error = AuthenticationThrottleError;

    fn try_from(value: FailureWindowFile) -> Result<Self, Self::Error> {
        Ok(Self {
            window_started_unix_time_millis: value.window_started_unix_time_millis,
            failures: value.failures,
            blocked_until_unix_time_millis: value.blocked_until_unix_time_millis,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticationThrottleError;

#[cfg(test)]
mod tests {
    use super::{
        AUTHENTICATION_BLOCK_MILLIS, AUTHENTICATION_BUCKET_FAILURE_LIMIT,
        AUTHENTICATION_GLOBAL_FAILURE_LIMIT, AuthenticationDisposition,
        AuthenticationThrottleState,
    };
    use crate::identity::CallerId;

    #[test]
    fn bucket_blocks_at_limit_and_clock_rollback_cannot_expire_it() {
        let caller = CallerId::from_bytes([0x11; 16]);
        let mut throttle = AuthenticationThrottleState::default();
        for attempt in 0..AUTHENTICATION_BUCKET_FAILURE_LIMIT {
            assert_eq!(
                throttle.disposition(caller, u64::from(attempt) + 100),
                AuthenticationDisposition::Proceed
            );
            throttle.record_result(
                caller,
                u64::from(attempt) + 100,
                false,
                AuthenticationDisposition::Proceed,
            );
        }
        assert_eq!(
            throttle.disposition(caller, 50),
            AuthenticationDisposition::Blocked
        );
        assert_eq!(
            throttle.disposition(caller, 104 + AUTHENTICATION_BLOCK_MILLIS),
            AuthenticationDisposition::Proceed
        );
    }

    #[test]
    fn success_clears_only_the_claim_bucket() {
        let caller = CallerId::from_bytes([0x11; 16]);
        let same_bucket = CallerId::from_bytes([0x51; 16]);
        let mut throttle = AuthenticationThrottleState::default();
        throttle.record_result(caller, 100, false, AuthenticationDisposition::Proceed);
        throttle.record_result(same_bucket, 101, true, AuthenticationDisposition::Proceed);
        assert_eq!(
            throttle.disposition(caller, 102),
            AuthenticationDisposition::Proceed
        );
    }

    #[test]
    fn cycling_claims_eventually_blocks_the_global_scope() {
        let mut throttle = AuthenticationThrottleState::default();
        assert_eq!(AUTHENTICATION_GLOBAL_FAILURE_LIMIT, 50);
        for attempt in 0_u8..50 {
            let mut bytes = [0_u8; 16];
            bytes[0] = attempt;
            let caller = CallerId::from_bytes(bytes);
            let disposition = throttle.disposition(caller, 200);
            throttle.record_result(caller, 200, false, disposition);
        }
        assert_eq!(
            throttle.disposition(CallerId::from_bytes([0xFE; 16]), 201),
            AuthenticationDisposition::Blocked
        );
    }
}
