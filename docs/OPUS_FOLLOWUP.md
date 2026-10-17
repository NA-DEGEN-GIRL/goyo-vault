Four regressions remain in the Win32 layer. The crypto, file-format and vault-logic changes (password rewrap, OTP error mapping, ADS and hardlink checks, `BTreeMap`, zeroize features) look correct. This is a read-only review: no tools were run and no files were changed.

## Findings

### 1. Medium – Normal close can hit `std::process::abort()`
- **Where:** `window_proc` `0x10` arm, `App::timer` close branch, the trailing `drain_pending(h)`, `App::ctrl`.
- **Scenario:**
  1. The user clicks X while the window is foreground and nothing is on the clipboard. The handler calls `DestroyWindow(h)` while the `APP` borrow is still held.
  2. Destroying the active window moves activation to another thread, so Windows sends `WM_ACTIVATEAPP(FALSE)` back into `window_proc` before the window is gone.
  3. `try_borrow_mut` fails, so the event is deferred: it sets `PENDING_EVENTS |= 1`, hides the window and posts `DRAIN_EVENTS`.
  4. The `0x10` handler returns and the trailing `drain_pending(h)` gets the borrow. It calls `a.lock()`, which calls `build()`, which calls `ctrl()`.
  5. `CreateWindowExW` with the destroyed parent returns 0, so `ctrl` aborts.
- **Same path:** The timer branch `closing && clipboard.is_none()` does the same once the close-wait finishes.
- **Impact:** Secrets are already wiped at this point. But every close becomes a fast-fail crash, which can produce a WER report or dump of process memory.
- **Not covered by tests:** The unit test uses a `STATIC` window that is never active and does not use `window_proc`.
- **Fix:**
  - In `drain_pending`, if `a.closing`, consume the pending bits, call `expire_clipboard()` when `pending & 6 != 0`, and return without calling `lock`/`build`.
  - Also set a thread-local "destroyed" flag on `WM_DESTROY`, or check `IsWindow(h)`, and skip any rebuild when it is set.
- **Verify:** Close via X and check the exit code and Event Viewer for an Application Error or WER entry.

### 2. Low–Medium – The visible SECRET field now goes through the IME and text services
- **Where:** `build_edit`. SECRET is now multiline without `ES_PASSWORD`.
- **Scenario:**
  - `ES_PASSWORD` used to disable the IME.
  - Now typed mnemonics and keys reach TSF and IME learning dictionaries, and Windows hardware-keyboard text suggestions and typing personalization when those are enabled.
  - These can persist words to disk outside the vault.
  - This channel is not documented. Visibility on screen is documented; learning is not.
- **Fix:**
  - Either apply a password input scope to SECRET, e.g. `SetInputScope(h, IS_PASSWORD)`, and confirm that Hangul input still works acceptably;
  - or disable the IME context for SECRET (`ImmAssociateContextEx(h, 0, 0)`) and accept the Hangul limitation.
  - In either case, add an explicit README and UI note that typed secrets may be learned by OS input services; recommend pasting instead.

### 3. Low – Enter and Esc now pop "not allowed" error boxes
- **Where:** `App::command`, which calls `allows(id)` first, combined with `IsDialogMessageW` in the main loop.
- **Scenario:**
  - Enter in any single-line edit (PASS, OTP, path fields) or on the list makes `IsDialogMessageW` send `WM_COMMAND(IDOK=1, BN_CLICKED)`.
  - Esc anywhere sends `IDCANCEL=2`.
  - Neither id is in any allowlist, so `command` returns "현재 화면에서 허용되지 않는 작업입니다." and `message()` shows a modal box.
  - Before the allowlist, `_ => {}` ignored these ids. Enter is the natural way to submit the password and OTP, so users will hit this constantly.
- **Fix:** Before the allowlist check:
  - Map `1` to `SUBMIT` on Login, Create, Restore and Password.
  - Map `2` to `CANCEL` on Edit and Password.
  - Otherwise return `Ok(())` silently for ids 1 and 2.

### 4. Low (hardening; same class as fixed #11) – Cross-process edit messages that store callbacks or unmask fields are still forwarded
- **Where:** `edit_proc` blocklist.
- **Scenario:**
  - `EM_SETWORDBREAKPROC` (`0xD0`) from any same-integrity process stores an arbitrary code address. The edit control then calls it in-process with a pointer to the control text. This is the classic shatter primitive; CFG narrows the targets but does not eliminate them.
  - `EM_SETPASSWORDCHAR` (`0xCC`) unmasks PASS, CONFIRM, CURRENT_PASS and OTP.
  - `EM_SETHANDLE` (`0xBC`) swaps the edit buffer.
- **Fix:** Add `0xD0 | 0xCC | 0xBC` to the early-return list. Same-user attackers remain a documented limitation; this only removes the cheap primitive, as #11 did.

## Verification notes (not confirmed defects)
- **Recent-file metadata:** `OFN_DONTADDTORECENT` covers Recent Items. The dialog's per-executable last-folder state (`ComDlg32\LastVisitedPidlMRU`) may still be written. Diff the registry before and after a backup to a USB path; if it is written, cover it under the documented metadata limitation.
- **`/DEPENDENTLOADFLAG`:** Confirm with `dumpbin /loadconfig` (DependentLoadFlags = 0x800) and with Process Monitor launching from a writable folder that contains decoy `dwmapi.dll` and `wtsapi32.dll`.

## Missing context
- `src/lib.rs` (the `goyo_vault` crate root) was not provided. I assumed it only declares `crypto`, `otp` and `vault`.
- The attachments have no line numbers, so locations are given as function names.
