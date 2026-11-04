//! The pass state machine lives in the lib (`goyo_vault::syncengine`), so
//! that the Android app runs the same passes over its own transport; this
//! helper runs them over `ssh.exe` (transport.rs).
pub use goyo_vault::syncengine::*;
