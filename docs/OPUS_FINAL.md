마지막 집중 검토 원문. 아래 OPUS_FINAL.md findings는 현재 OPUS_FOLLOWUP.md에 보존된 두 번째 검토의 네 가지 지적을 가리킵니다.

# Closeout: OPUS_FINAL.md findings 1–4

**No unresolved actionable defect remains in this focused scope.** All four findings are fixed correctly, and I found no immediate regression in the changed code.

| # | Status | Basis |
|---|---|---|
| 1 | Fixed | Close path: the reentrant `WM_ACTIVATEAPP` is deferred because the borrow is held. The nested `drain_pending` cannot borrow and returns with the bits kept. `WM_DESTROY` then sets `WINDOW_GONE` and clears the bits. The outer trailing `drain_pending` exits early. The posted `DRAIN_EVENTS` goes to a dead HWND and is dropped. The timer path is the same. `a.closing` never reaches `lock`/`build`. After destroy, `Drop` sends messages to dead child HWNDs, which is harmless. The regression test goes through the real `window_proc` and covers both paths. |
| 2 | Fixed | `LoadLibraryExW(..., 0x800)` restricts the load to System32. The edit is created with `""`. Scope and IME are applied before `SetWindowTextW`, which is skipped if either fails. `ImmGetContext == 0` is checked for SECRET/NOTES. `input_failed` blocks `submit()` and `SAVE`. `build()` resets the flag before recreating inputs. Scope reset (`0`) runs only after the replace/clear/empty-undo sequence. The README and edit-screen UI disclose the learning limit and recommend pasting. |
| 3 | Fixed | The mapping runs before `allows()`. IDOK maps to SUBMIT/SAVE. IDCANCEL maps to CANCEL, or to LOCK on Vault. Every other 1/2 returns `Ok(())` silently. With no default button, `DM_GETDEFID` falls through to `DefWindowProc` and returns 0, so `IsDialogMessageW` sends IDOK as expected. |
| 4 | Fixed | `0xBC`/`0xCC`/`0xD0` are the correct values for EM_SETHANDLE, EM_SETPASSWORDCHAR and EM_SETWORDBREAKPROC. The app never sends them itself. The test confirms the password mask is unchanged. |

## Verification notes (not confirmed defects)
- **Hangul in non-secret fields:** `IS_PASSWORD` is applied to every input, including TITLE, KIND and the path fields. TSF IMEs may switch to direct input for this scope. If so, Hangul cannot be typed into titles, and the README wording (Hangul is restricted only in SECRET/NOTES) is inaccurate. The test sends `WM_CHAR` directly, which bypasses the IME, so it would not catch this. Check this manually with the Microsoft Korean IME.
- **Test isolation:** `close_and_timer_do_not_rebuild_destroyed_windows` leaves `WINDOW_GONE = true`. It passes now only because libtest runs each test on a fresh thread, so thread-locals start clean. Resetting the flag at the end of the test would remove that hidden dependency.
