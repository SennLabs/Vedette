//! Exponential backoff with jitter.
//!
//! Deliberately hand-rolled: the `backoff` crate's last release is 0.4.0 and it is
//! unmaintained, and the policy here is ~25 lines.

use rand::Rng;
use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base: Duration::from_secs(2),
            cap: Duration::from_secs(120),
        }
    }
}

impl Policy {
    /// Full-jitter backoff: `rand(0, min(cap, base * 2^attempt))`. The jitter matters
    /// because a bare doubling schedule re-synchronises every retrying client onto the
    /// same instants.
    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = self
            .base
            .saturating_mul(2u32.saturating_pow(attempt.min(16)))
            .min(self.cap);
        let millis = exp.as_millis().max(1) as u64;
        Duration::from_millis(rand::rng().random_range(1..=millis))
    }
}

/// Outcome of one attempt, as classified by the caller.
pub enum Attempt<T> {
    Done(T),
    /// Worth another try, e.g. a 503 or a connection reset.
    Retry(anyhow::Error),
    /// Hopeless, e.g. a 401. Returned to the caller immediately.
    Fatal(anyhow::Error),
}

/// Retries `op` according to `policy`. `hint` lets a server-supplied delay
/// (`Retry-After`) override the computed backoff for the next attempt.
pub async fn run<T, F, Fut>(policy: Policy, label: &str, mut op: F) -> anyhow::Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = (Attempt<T>, Option<Duration>)>,
{
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..policy.max_attempts {
        let (outcome, hint) = op(attempt).await;
        match outcome {
            Attempt::Done(v) => return Ok(v),
            Attempt::Fatal(e) => return Err(e),
            Attempt::Retry(e) => {
                let delay = hint.unwrap_or_else(|| policy.delay(attempt)).min(policy.cap);
                if attempt + 1 < policy.max_attempts {
                    tracing::warn!(
                        label,
                        attempt = attempt + 1,
                        max = policy.max_attempts,
                        delay_ms = delay.as_millis(),
                        error = %format!("{e:#}"),
                        "retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("{label}: exhausted retries")))
        .map_err(|e| e.context(format!("{label}: gave up after {} attempts", policy.max_attempts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn delay_is_bounded_by_the_cap() {
        let p = Policy { max_attempts: 10, base: Duration::from_secs(1), cap: Duration::from_secs(8) };
        for attempt in 0..20 {
            assert!(p.delay(attempt) <= p.cap, "attempt {attempt} exceeded cap");
        }
    }

    #[tokio::test]
    async fn succeeds_after_transient_failures() {
        let calls = AtomicU32::new(0);
        let p = Policy { max_attempts: 5, base: Duration::from_millis(1), cap: Duration::from_millis(2) };
        let out: i32 = run(p, "test", |_| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    (Attempt::Retry(anyhow::anyhow!("boom")), None)
                } else {
                    (Attempt::Done(7), None)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(out, 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_fatal_outcome_does_not_retry() {
        let calls = AtomicU32::new(0);
        let p = Policy { max_attempts: 5, base: Duration::from_millis(1), cap: Duration::from_millis(2) };
        let err = run::<i32, _, _>(p, "test", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { (Attempt::Fatal(anyhow::anyhow!("401 unauthorized")), None) }
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("401"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "must not retry a fatal error");
    }

    #[tokio::test]
    async fn exhausting_attempts_reports_the_last_error() {
        let p = Policy { max_attempts: 3, base: Duration::from_millis(1), cap: Duration::from_millis(2) };
        let err = run::<i32, _, _>(p, "fetch", |_| async move {
            (Attempt::Retry(anyhow::anyhow!("503")), None)
        })
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("gave up after 3"));
    }
}
