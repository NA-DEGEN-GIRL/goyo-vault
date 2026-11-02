//! The wall clock in Unix seconds (`written`, review and sync times).
use crate::crypto::Result;

pub fn now() -> Result<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "시스템 시간을 확인하세요.")?
        .as_secs();
    #[cfg(test)]
    let now = now.saturating_add(SHIFT.with(|s| s.get()));
    Ok(now)
}
#[cfg(test)]
thread_local! {
    /// How far the lib's own tests moved this thread's clock forward.
    static SHIFT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
/// Moves this thread's clock `secs` forward (the lib's tests only).
#[cfg(test)]
pub fn shift(secs: u64) {
    SHIFT.with(|s| s.set(s.get().saturating_add(secs)));
}
