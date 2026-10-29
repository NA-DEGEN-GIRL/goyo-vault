//! The security-key build's words in goyo-sync's window (spec v3 §9.3): a
//! file only that build compiles, so the default exe carries none of them,
//! with their English in `i18n::EN_SK`.
use crate::i18n::tr;

/// The list label of `nokeys` (spec v3 §7.12): this PC's server line has
/// no `--key-sync=<id>` for a vault that uses key-file sync.
pub fn no_keys() -> &'static str {
    tr("서버에서 열쇠 파일 동기화 꺼짐")
}
