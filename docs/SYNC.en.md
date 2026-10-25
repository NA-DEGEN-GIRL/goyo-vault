# Sync (optional): goyo-sync

[한국어](SYNC.md) · <b>English</b>

From 0.8.0 a separate tool, `goyo-sync.exe`, lets you use one vault on several PCs by exchanging **only the encrypted vault file** with your own SSH server. Without it nothing changes. The vault app, `goyo-vault.exe`, still has no network code and no code that starts other programs.

> [!WARNING]
> - **A vault with sync turned on, and every later backup of it, opens only in 0.8.0 or later.** 0.7.x and older refuse it with "Authentication failed". There is no way back. Update all your PCs to 0.8.0 or later first.
> - This feature is new. It has automated tests and AI reviews but no professional security audit. Make a **vault backup and a key backup** before you turn it on.

`my-server`, `<user>` and `<you>` in this document are examples. Use your own ssh alias and user names.

## What travels and what stays on the PC

- **Sent to the server:** the whole encrypted vault file (`GOYOVA02` format).
- **Never leaves the PC:** the key file (`.goyokey`), the password, the OTP secret and any plaintext. Without the key file neither the server nor goyo-sync can decrypt the vault.
- **What the server learns:** the vault ID, the file size, when the contents changed, the IP address you connect from and how many versions it keeps. The helper also connects every `interval` seconds (default 60) while you are signed in, so the server learns **when each PC is on**. A longer interval makes this coarser.
- **OTP-only changes are not uploaded.** In a vault with an OTP each unlock updates the OTP record, but that alone is never uploaded. Even while the server takes no upload from this PC, an upload that is waiting is not made again when you open the vault. So the server normally does not learn when you open the vault. There is one exception: if changes are still waiting to go up and a new copy arrives from the server, the vault app merges it (at the next unlock if it was closed) and uploads its changes again. The server learns that moment.

|Program|Does|Does not|
|---|---|---|
|`goyo-vault.exe` (vault app)|Decrypts, merges changes from other PCs, computes the check code|Network, starting programs|
|`goyo-sync.exe` (helper)|The settings window; moves the encrypted copy to and from the server with Windows' built-in `ssh.exe`|Decrypt, open the vault or key file. It has no network or crypto code of its own.|
|`goyo-sync-server.py` (server)|Keeps the ciphertext it receives, by version, per vault (newest 200)|Decrypt (it has no key). No resident service, no open port.|

The vault app and the helper talk only through files in the `<vault file name>.sync` folder next to the vault (for example `vault.goyo.sync`). The helper never opens the vault file: if any other program holds a handle on it, Windows refuses the vault's save.

## Requirements

- Goyo Vault **0.8.0 or later** on every PC.
- The Windows OpenSSH client on every PC (`C:\Windows\System32\OpenSSH\ssh.exe`). Windows 11 usually has it; otherwise add 'OpenSSH Client' under **Settings > System > Optional features**.
- One server with `python3` (3.8 or later) and `sshd`. Linux is the reference. You must be able to log in to it with an ssh key.
- An ssh key without a passphrase, or the ssh-agent service. The helper runs unattended and cannot ask for a passphrase.
- A way to see the server's host key fingerprint (its console or admin page), to compare on the first connection.
- To use it away from home, do not expose ssh to the internet. A VPN such as Tailscale that reaches the server is recommended.

## 1. Install and open the settings window

Download the sync add-on `GoyoVault-Sync-<version>-windows-x64.zip` from [Releases](https://github.com/NA-DEGEN-GIRL/goyo-vault/releases). Check its hash with `Get-FileHash` as the README describes, then extract it **where you extracted the main ZIP (the folder that contains GoyoVault)**. The ZIP has its own `GoyoVault` folder, so `goyo-sync.exe`, `server\goyo-sync-server.py`, `goyo-sync.conf.example` and `SHA256SUMS-sync.txt` are added to your existing GoyoVault folder. Extracting it inside GoyoVault would make `GoyoVault\GoyoVault`.

In the GoyoVault folder, **double-click `goyo-sync.exe`** to open the settings window. It looks like Goyo Vault, and follows the dark or light theme and the Korean or English language chosen in the vault app. Only one window opens; starting it again brings the open one to the front.

The window has three parts, top to bottom:

- **Server**: the ssh host, 'Check connection', 'Install or update on server', a result line and 'Advanced settings'.
- **Vaults**: the vaults to sync with each one's state, 'Add…', 'Remove' and 'Get from server…'.
- **Run**: 'Start automatically when I sign in to Windows', 'Save and start', 'Sync now', 'Stop', 'View log' and a status line.

The label next to the title shows whether background sync is running. Closing the window does not stop background sync.

## 2. Connect the server

1. In **Server (ssh host)**, enter an alias from `%USERPROFILE%\.ssh\config` (for example `my-server`) or `<user>@my-server`. Put settings such as the port on the alias in your ssh config.
2. Press **Install or update on server**. A dialog shows the server and the install location. On 'Yes' the server script built into goyo-sync.exe is sent on ssh's standard input, and the server runs only this one line (paths from the advanced settings):
   ```
   umask 077 && mkdir -p .local/share/goyo-sync && cat > .local/share/goyo-sync/goyo-sync-server.py.new && chmod 700 .local/share/goyo-sync/goyo-sync-server.py.new && python3 -I .local/share/goyo-sync/goyo-sync-server.py.new selftest && mv -f .local/share/goyo-sync/goyo-sync-server.py.new .local/share/goyo-sync/goyo-sync-server.py
   ```
   The received copy (`.new`) replaces the old script only after its own selftest passes, so a transfer cut off midway never installs a truncated script. It counts as installed only when the selftest prints exactly `PASS` and the replacement succeeds. The selftest checks, on that very server, storing, concurrent-upload conflicts (including real threads racing), keeping 200 versions, refusing key files, folder fsync, refusing a storage root that is a file or a link, the 64-vault limit under simultaneous first uploads, the limit of 8 concurrent connections (including a real serve process), and the free space reserve (256 MiB). It also passed on Ubuntu (Python 3.12) during development (including the vault-count lock, connection limit and free space tests that run only on POSIX), but file systems and Python differ between servers, so it always runs when you install. Press it again after moving the server, changing Python or updating goyo-sync. For the time limits (30 s for the header, 600 s for an upload, 60 s or 600 s for the reply) the selftest checks only the order in which they are set, not that a connection is actually cut off.
   - The install uses **your usual ssh login** (default key or ssh-agent). It never uses the dedicated key below, which may be bound on the server to run only the sync command.
   - For a server you have never connected to, first get its host key with 'Check connection' (step 3). The install does not connect to an unknown host key.
   - The server script handles one request per ssh connection and exits. Data stays under `data` in the script's folder (by default `~/.local/share/goyo-sync/data/`), as version files per vault (folders 0700, files 0600). The same folder also holds empty lock files `slot-0` to `slot-7` that count concurrent connections (POSIX). Storage can reach 64 vaults × 200 versions × 8 MiB, about 100 GiB, but an upload that would leave less than 256 MiB free on the disk is refused. To keep room for the server's other uses, put the `data` folder on its own file system or under a quota.
3. Press **Check connection**. It checks the settings with exactly the rules of goyo-sync.conf (a wrong field gets a red outline), then, with the same ssh options as the background helper, a 512-byte binary round trip and the server's vault list. It writes nothing. `Connection OK · … vaults on the server: N` means all is well. On failure the result line names the cause: offline, authentication, host key, ssh.exe missing, server script missing, Python missing, or a server error.

All ssh work runs behind the window; meanwhile the result line shows how long it has taken. One ssh call never takes longer than the timeout in the advanced settings (120 seconds by default).

### First connection: the host key

goyo-sync's ssh never connects to an unknown or changed host key (`StrictHostKeyChecking=yes`). For a server not yet in this PC's `known_hosts`, 'Check connection' asks:

- **Yes**: one connection with `StrictHostKeyChecking=accept-new` stores the key the server sends in `known_hosts` without checking it (trust on first use). If someone intercepted the connection at that moment, their key is stored, so the window then shows the **fingerprint** (the output of `ssh-keygen -l -F`, for example `my-server ED25519 SHA256:…`). Be sure to compare it with the fingerprint you check on the server itself (for example `ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub` there). If they differ, remove it with `ssh-keygen -R my-server` and do not use that server.
- **No**: nothing is stored.
- If **another key is already stored for the name, or the key changed**, it does not ask and stops. Only if you are sure the server was reinstalled: check the fingerprint on the server itself, remove the old key with `ssh-keygen -R my-server` in PowerShell, then connect once with `ssh my-server` and compare. This window never accepts a changed key.

You can also connect once with `ssh my-server` in PowerShell, check the fingerprint and accept it; 'Check connection' then does not ask.

### Advanced settings

Turn on the 'Advanced settings' switch to see the other settings. Fields that cannot be empty start with their defaults.

|Field|Default|Meaning|
|---|---|---|
|Script path on the server|`.local/share/goyo-sync/goyo-sync-server.py`|Relative to your home folder on the server (absolute when it starts with `/`). Letters, digits and `. _ / ~ + -`.|
|Python command|`python3`|The Python command on the server. Letters, digits and `. _ / + -`.|
|Interval (s)|`60`|Seconds between checks for a new server version, 30 to 3600. It varies by ±10% so PCs do not stay in step.|
|Timeout (s)|`120`|Seconds allowed for one ssh call, 30 to 600. Raise it if you upload a large vault over a slow line.|
|Dedicated SSH key file|(empty)|A dedicated ssh private key, chosen with 'Browse'; when set, only that key is used. `.goyokey` and `.goyo` files are refused.|

**No setting can name a key file.** The ssh program cannot be changed either: it is always `System32\OpenSSH\ssh.exe` with fixed options (unknown host keys refused, no forwarding, no terminal, no password prompts).

### Dedicated key with a forced command (recommended)

Make an ssh key just for goyo-sync and tie it on the server to the sync script. A stolen copy of that key then reaches only the ciphertext store, never a shell. A forced command still runs through your shell, so text printed by shell startup files (`~/.bashrc`, `~/.zshenv` and so on) still reaches the data stream; see `banner=N` under troubleshooting.

1. First install the script with 'Install or update on server' (it uses your usual login).
2. On the PC, create the key. Leave the passphrase empty or use the ssh-agent service.
   ```powershell
   ssh-keygen -t ed25519 -f $HOME\.ssh\goyo_sync -C goyo-sync
   ```
3. On the server, add the public key (the contents of `goyo_sync.pub`) to `~/.ssh/authorized_keys` as one line like this. Find the python path on the server with `command -v python3`.
   ```
   restrict,command="/usr/bin/python3 -I /home/<user>/.local/share/goyo-sync/goyo-sync-server.py serve" ssh-ed25519 AAAA… goyo-sync
   ```
4. In the advanced settings, choose `C:\Users\<you>\.ssh\goyo_sync` as the **Dedicated SSH key file** and press 'Check connection'.

With several PCs, make one key per PC and add one line for each. If you lose a PC, delete only its line. Later script updates also work, since 'Install or update on server' uses your usual login, not the dedicated key.

## 3. Choose the vaults and start

1. Put the vault files to sync in the **Vaults** list. If the list is empty and the GoyoVault folder has `vault.goyo`, it is already there. Add others with **Add…** (up to 8). Key files (`*.goyokey`) are refused. **Remove** takes the selected vault off the list only.
2. Check **Start automatically when I sign in to Windows**. It is on for a first setup. Turning it off applies at once (it removes the `GoyoSync` Run value in the current user's registry); turning it on applies when you press 'Save and start'.
3. Press **Save and start**. It checks the settings, saves them to `goyo-sync.conf` next to the program (text with short comments; you may edit it by hand), applies autostart, stops a running helper if there is one, and starts `goyo-sync.exe --background` without a window. The label next to the title changes to 'Background sync running'.
4. The helper creates the `vault.goyo.sync` folder next to the vault, and the list shows 'Waiting for consent in Goyo Vault'. Now open that vault in Goyo Vault (section 4 below).

The list reads each vault's state from the `status` and `helper.state` files in its sync folder every 2 seconds.

|State|Meaning|
|---|---|
|Not set up yet|No sync folder yet. 'Save and start' lets the helper create it.|
|Waiting for consent in Goyo Vault|The vault app has not left a copy yet. It asks for consent when you unlock the vault.|
|OK · server version N|The helper talks to the server, and the copy it received is server version N.|
|Helper off|The helper has not written its state for 3 minutes.|
|Offline / SSH authentication failed / Host key needs checking / Server error / Upload refused / Settings error / Newer format|See the same state under section 10, Troubleshooting.|
|Vault file not found|Check the path. The vault file is checked in its folder listing only, never opened.|

- **Sync now**: one sync pass over every vault in the list now, with each vault's result shown in the list for a minute (as `--once`). A vault the background helper is working on is skipped.
- **Stop**: stops the running background helper (as `--stop`).
- **View log**: shows the last 400 lines of `goyo-sync.log` inside the window (continued from `goyo-sync.log.1` after the 256 KiB rollover).

The status line tells you about unsaved changes, and closing the window asks once.

## 4. Turn sync on

Once the sync folder exists, open the vault in Goyo Vault and a dialog appears. It says that the key file and password are never sent, and that the vault format changes so **version 0.7 and older cannot open this vault or later backups of it.**

- **Yes:** the vault switches to the sync format (`GOYOVA02`) and its first copy is uploaded. When "Synced" appears at the top of the vault screen, the server has answered that it stored it.
- **No:** nothing changes, and it asks again at the next unlock. To stop the question, **Remove** that vault in the settings window, press **Save and start**, and delete the `vault.goyo.sync` folder.
- If the key file is inside the sync folder, it does not ask and shows a warning. Move the key elsewhere.

Your entries stay the same. The dialog appears only when you unlock a vault, not after a restore or for a new vault.

**Turn sync on for a vault on one PC first.** If another PC has an older or separately edited copy, do not turn sync on for that copy: replace it with the server copy (or the first PC's vault) through Restore, as in section 6. The format before sync keeps no record of deletions, so entries deleted or changed on one side come back from the other copy as they were.

## 5. What the screen shows

With the vault open, the label at the top reads like `Open · Synced · vault.goyo`.

|Label|Meaning|
|---|---|
|**Synced**|This PC's entries and deletion records equal the copy the server last sent or acknowledged, **checked with the key**. The helper's status word never shows it. When the server answers that it stored an upload, the helper keeps this PC's uploaded file as the received copy, so it does not prove that the server really stored it. Nor does it prove that the server's disk is safe.|
|**Uploading**|Changes wait for the helper or the server. They are already saved on this PC.|
|**Helper off**|`goyo-sync.exe` is not running (no status file, or none written for 3 minutes).|
|**Offline**|The helper cannot reach the server: `offline`, `auth`, `hostkey`, `nossh` or `server` under troubleshooting below.|
|**Sync warning**|Something needs you: the server sent an older state, a copy failed authentication, merging would exceed a limit, a newer format arrived, or the helper is in `refused`, `config` or `update`. A warning from the vault side stays until you lock.|

**Check code.** When you unlock (or when the vault first becomes synced afterwards), the status line shows `Synced · check code XXXX-XXXX-XXXX-XXXX` once. It is computed over each live entry's ID and contents (all four fields) and over the deletion records, so **the same code on two PCs means the same contents.** A different code means sync is still under way, or the server shows different copies to different PCs. It is computed with the data key, so the code reveals nothing about the entries. It has 64 bits, so even someone with the key needs about 2^64 tries to make other contents give the same code. The OTP record is left out. Lock and unlock to see it again.

Status-line messages:

|Message|Meaning and what to do|
|---|---|
|Merged changes from another PC: N added, N removed.|Normal.|
|Entries edited on two PCs: N. Both versions were kept; check entries with the same name.|Find the entries with the same name and delete the one you do not need. The message never names an entry, because the status line is window text that other programs can read.|
|N entries were deleted or edited on another PC. The state before merging was kept in ….|Shown in red. N counts the entries merges removed here since you unlocked the vault (or since the last copy made meanwhile; see section 7). If that was not intended, see "Getting things back". It may also be someone with an old key copy deleting or changing entries through the server.|
|Warning: the server sent an older state of the vault.|Nothing here changed, and this PC uploads its state again. The server may have been restored or rolled back. Compare check codes with another PC.|
|The copy from the server failed authentication and was ignored.|The server copy is damaged or altered. This PC uploads its state over it.|
|The server copy belongs to another vault and was ignored.|A new vault was created at the same path, or another vault was restored there. Press 'Stop' in the settings window, delete the `vault.goyo.sync` folder and press 'Save and start'. The old vault's history stays on the server.|
|Merging would exceed 1000 entries or 8 MiB, so nothing was merged.|Remove some entries; the merge is tried again.|
|The server copy uses a newer format, so sync stopped.|Update Goyo Vault on this PC.|
|The key file is inside the sync folder, so this vault does not sync.|Move the key file to another folder.|
|Sync offline / SSH authentication failed / host key changed / helper not running / see goyo-sync.log|See troubleshooting below. Your changes are saved on this PC.|

## 6. Add a second PC

1. Install Goyo Vault 0.8.0 or later and the sync add-on on the new PC, and make ssh to the server work as in Requirements (a key or ssh-agent).
2. **Copy the key file (`.goyokey`) by USB.** Never send it through the server, mail or a cloud service.
3. Start `goyo-sync.exe`, enter the server and press **Check connection** (on a first connection, compare the fingerprint).
4. Get the vault file, one of two ways:
   - **From the server:** **Get from server…** lists the server's vaults. The tag (for example `3FA2-C1D0`) matches the one in the OTP app entry `Goyo Vault (3FA2-C1D0)`; on the first PC, 'Get from server…' marks that vault as 'Same vault as vault.goyo on this PC', so you can read the tag there too. Pick the vault, press **Get…** and choose a **new file** name (for example `from-server-3FA2-C1D0.goyo`): the newest server version is saved to it. An existing file is never overwritten. Open the file with **Restore from backup** in Goyo Vault and set 'Restore to (new file)' to the path this PC will sync (for example `C:\Users\<you>\GoyoVault\vault.goyo`). This first copy trusts the server, so **compare the check code with the first PC** afterwards.
   - **By USB:** copy the first PC's `vault.goyo` by USB too, and restore it the same way. This needs no trust in the server.
5. If the restored vault is not in the list, add it with **Add…**, then press **Save and start**. The vault is already in the sync format, so it links without a dialog; a vault that is open links as soon as the helper creates the folder.
6. When both PCs show the same check code, you are done.

## 7. Edits and deletions on several PCs

- The helper fetches other PCs' changes every interval (60 seconds by default), and the vault app merges them within 2 seconds on the vault screen. While you edit an entry or a dialog is open, it waits and merges afterwards. If the app is closed, it merges at the next unlock, before checking the OTP.
- This PC's changes are saved to the vault file first and uploaded after. The server never holds something this PC's file lacks.
- **When two PCs edit the same entry, both versions are kept** and you are told. Delete the one you do not need; that deletion syncs too.
- An edit on one PC and a deletion on another keep the edit. Deleted on both, it is gone.
- The same text added separately on two PCs gives two entries. Delete one.
- **Deletions spread to the other PCs.** That is what sync does. For a mistaken deletion see "Getting things back".
- When merges remove many of this PC's entries, the state before merging is first kept as an encrypted copy, `vault.goyo.sync\pre-merge-<time>.goyo`, and you are told in red. Removed entries are added up over the merges while the vault is open (from unlock to lock). Once there are 5 or more since the last copy, or 2 or more that are at least 20% of the entries before that merge, the copy is made, and it holds the state before the first of those losses. Entries deleted on another PC, entries edited on another PC (this PC's old text disappears) and entries pushed off their ID by other text under the same ID (even if moved to another ID and kept) all count.
- The newest 3 pre-merge copies stay however old; beyond those, only copies younger than 30 days stay, and at most the newest 20 in all. Copies that do not stay are deleted when a new copy is made.
- If you close the vault app before this PC's changes are uploaded and another PC uploads first in the meantime, this PC's changes are merged and uploaded at its next unlock, because merging needs the key. They are in the vault file, so nothing is lost.
- While sync is on, never drop another file in place of `vault.goyo` by hand. Use **Restore from backup** to work with another copy, and do not edit files inside `vault.goyo.sync`.

## 8. Getting things back: server history and pre-merge copies

The server keeps **the newest 200 versions** of each vault as ciphertext. Each upload of changed contents is one version. The newest version number appears in the 'Get from server…' list and in `goyo-sync.log`. 'Get from server…' in the window gets the newest version only; get an older one from the command line (see "Advanced: command line" below).

```powershell
.\goyo-sync.exe --fetch <32-digit vault ID> 41 C:\Users\<you>\GoyoVault\from-server-v41.goyo | Out-Host
```

The target folder must already exist; the file is never overwritten.

1. Open the file with **Restore from backup**, restoring to a **new name** (for example `vault-v41.goyo`). Your current key file and password open it: a password change never changes the data key, so an old key copy with its old password opens it too.
2. Find the entries you need and enter them again in your current vault.
3. Do not sync the restored copy. It has the same vault ID, so adding it to the list makes it a copy of the same server vault, and the server's deletion records delete those entries again. No merge brings a deletion back.

Open `vault.goyo.sync\pre-merge-*.goyo` the same way (Restore from backup, new name).

## 9. Turning sync off and uninstalling

**Off on one PC:**
1. In the settings window, turn off **Start automatically when I sign in to Windows** (applies at once) and press **Stop**. Stop it first: a running helper creates the folder again.
2. To turn off one vault, **Remove** it and press **Save and start**. To turn off all, delete the helper files (`goyo-sync.exe`, `goyo-sync.conf`, `goyo-sync.log*`, `server\`, `goyo-sync.conf.example`, `SHA256SUMS-sync.txt`).
3. Delete the `vault.goyo.sync` folder. Move any `pre-merge-*.goyo` you want to keep out of it first.

The vault stays in the sync format and keeps opening offline in 0.8.0 or later. There is no way back to the 0.7 format.

**Everything, including the server:**
1. **Stop the helper on every PC first** (autostart off, then Stop). A helper that is still running uploads its copy to the empty server again.
2. On the server, `rm -rf ~/.local/share/goyo-sync`. This deletes all encrypted history.
3. Remove the goyo-sync line from the server's `~/.ssh/authorized_keys`.

## 10. Troubleshooting

The helper writes its state as one word to the `status` file in the sync folder; the vault app and the settings window's list only use that word to pick a label. 'Check connection' and 'Sync now' in the settings window (`--check` and `--once` on the command line) tell you the state right away.

|State|Vault app shows|Meaning|What to do|
|---|---|---|---|
|`ok`|Synced or Uploading|Normal.|–|
|`idle`|No label, or Uploading|The vault app has not left a copy yet, so the helper does not know this vault's ID. Usually sync is not turned on yet.|Unlock the vault in Goyo Vault and turn sync on.|
|`offline`|Offline|Host name not found, connection timed out or refused, no route. A connection that works but does not finish within the timeout also lands here.|Check the network and VPN. On a slow line, raise the timeout in the advanced settings. Changes stay on this PC and upload once connected.|
|`auth`|Offline, authentication message|ssh.exe itself reported that the server refused the key (`Permission denied`). The same words printed by the server or its shell start-up files give `server`.|Check the dedicated key, `authorized_keys` and ssh-agent, and try `ssh my-server` (with a dedicated key, `ssh -i …`) by hand. It tries again every 15 minutes.|
|`hostkey`|Offline, host key message|The server's host key is not in `known_hosts` or has changed. Decided only from ssh.exe's own messages: text the server prints, a reason it sends when it drops the connection, or its version line never gives this state.|Press 'Check connection'. On a first connection you can compare the fingerprint and accept it. For a changed key, unless you reinstalled the server, this can be a man-in-the-middle attack: fix `known_hosts` only after checking the fingerprint on the server itself. Until then it does not connect; it tries again every 15 minutes.|
|`nossh`|Offline|`System32\OpenSSH\ssh.exe` is missing.|Add 'OpenSSH Client' under Optional features.|
|`server`|Offline|The server script is missing or failed, Python is missing, or the reply was malformed. Too much text printed by the login shell also ends here. Also: an upload was answered with a CONFLICT no honest server sends (log: `holding back uploads`), or the remote side printed text that looks like an ssh error. A server already handling 8 connections (`busy` in the log) also lands here; the helper tries again after 30 s, then at growing intervals.|'Check connection' tells a missing script or Python apart. Install again with 'Install or update on server' (selftest included), and check the script path and Python command in the advanced settings. If shell startup files print text, make them print only in interactive shells (for example `[[ $- == *i* ]] \|\| return` at the top of `~/.bashrc`). If the log shows `holding back uploads`, the server may be keeping this PC's uploads out (a freeze); check the server. Your changes stay on this PC, and only the newest file is retried, 30 seconds to 15 minutes apart.|
|`refused`|Sync warning|The helper's checks or the server refused the upload (a link at the file, another vault's ID, the server's limit of 64 vaults, less than 256 MiB would stay free on the server disk, and so on).|Read the reason with 'View log'. Editing the vault again retries with a new file. If the log says `a file of another vault` (for example a new vault at the same path), press 'Stop', delete the `vault.goyo.sync` folder and press 'Save and start'. If it was the server's disk space, free up room on the server, then edit the vault again.|
|`config`|Sync warning|`goyo-sync.conf` has an error, so the helper stopped.|Open the settings window: it names the line and shows the settings it could read. Fix them and press 'Save and start'.|
|`update`|Sync warning, newer-format message|The server copy uses a newer Goyo Vault format.|Update Goyo Vault and goyo-sync on this PC.|

For "Helper off", press 'Save and start' in the settings window and check that autostart is on. If it ends right after starting, the status line and 'View log' tell you why.

**The log, `goyo-sync.log`.** It sits next to the helper and shows with 'View log'; it moves to `goyo-sync.log.1` past 256 KiB. One line per event: UTC time, vault tag, operation, result, server version, bytes sent and received, duration, ssh exit code, the first line of ssh's own messages (`ssh=`) and the first line of the remote side's stderr (`err=`). For each call, ssh's messages go to a `goyo-sync.ssh-*.log` file next to the helper (or in %TEMP% if that folder takes no file) and are deleted when the call ends. One left behind by a helper killed mid-call is deleted at a later start once it is an hour old. The log never contains vault contents, but ssh's message lines can name your server and the lines name your vault files, so check it before sharing. What the settings window did shows as `window check`, `window trust`, `window install`, `window list` and `fetch` lines. Common lines:

|Log line|Meaning|
|---|---|
|`created the sync folder`|The sync folder next to the vault was created.|
|`pinned this vault ID from the app's first upload`|The vault app's first copy set this folder's vault ID.|
|`upload lost to server version N; the app merges it`|Another PC uploaded first. The vault app merges and uploads again. Normal.|
|`upload was already on the server`|An earlier upload went through but its reply was lost. Normal.|
|`server answered CONFLICT although …: it is holding back uploads`|The server took no upload and answered CONFLICT with the copy this PC already holds, under the version the upload expected or under a new number. No honest server answers so. The state is `server`, incoming is not rewritten, and the upload is retried after the wait.|
|`server has no copy; uploading as the first version`|The server does not have this vault yet.|
|`server was empty; re-uploaded the last known copy`|The server was empty (wiped or restored), so the last copy received was uploaded again.|
|`server version went back A->B`|The server sent an older version. The vault app warns and uploads this PC's state again.|
|`incoming changed outside the helper`|The received copy in the sync folder was changed or deleted from outside; it is fetched again.|
|`refused outgoing before upload: …`|The checks refused the file to upload. ssh was not started.|
|`state=config: …`|A settings or folder problem (vault file not found, the sync folder or `helper.lock` in it is a link, …). That folder is left alone.|
|`retry in N s`|Waiting after a failure: from 30 seconds, doubling up to 15 minutes; 15 minutes for authentication and host-key errors. An edit in the vault triggers one immediate try, except after the server was found holding back uploads (`holding back uploads`): then only the newest file is tried, when the wait ends.|
|`banner=N`|N bytes printed by the server's shell were skipped (harmless up to 64 KiB). Making shell startup files (`~/.bashrc`, `~/.zshenv` and so on) print only in interactive shells removes them.|

## 11. Limits

- **A server that keeps hiding other PCs' new versions (a freeze) cannot be detected.** Other PCs' changes simply stop arriving. A freeze that refuses this PC's uploads, or answers them with a CONFLICT carrying the copy this PC already holds, shows as `server` or `refused`, but in front of a server that answers it stored an upload and then drops it, this PC shows "Synced". That case, and a server that shows different copies to different PCs (a fork), show only as different check codes. Compare the check codes of your PCs now and then.
- **There is one case where the server learns when you open the vault.** If changes are still waiting to go up and a new copy arrives from the server, the vault app merges it (at the next unlock if it was closed) and uploads its changes again (see "What travels and what stays on the PC").
- **A new PC's first copy from the server trusts the server.** Compare the check code, or copy the vault by USB.
- **A first connection's host key trusts the network of that moment.** Compare the fingerprint with the one you check on the server itself.
- A server that sends an older version cannot delete entries, and a warning appears. Only a PC that already saw a newer version of that vault can notice, though.
- **A used OTP code is refused again only on the same PC.** OTP-only unlocks are not uploaded, so a code used on one PC can still be accepted on another until the first PC's next content change syncs. That still takes the password, the key file and a currently valid code.
- **Key copies cannot be revoked.** Someone with an old key copy and the password of that time can push real deletions or edits through the server. Swapping in other text under the same IDs also counts as removed entries. Pre-merge copies, messages and server history make that visible but do not prevent it. Deleting only a little at each unlock (one entry, say) makes no pre-merge copy, only an "N removed" message each time. Whoever can write to the server can also push the 200-version history out with new uploads. Changing the data key is not supported yet.
- **Changing the password** changes the key file on that PC only. Copy the new key file to the other PCs by USB. The data key stays the same, so old key copies keep working.
- Folders with a reparse point, such as OneDrive Files On-Demand folders, are not used as sync folders. As the README says, keep the vault out of cloud folders anyway.
- The 200-version history is kept by the server, so a hostile server can delete it. Keep making your own vault and key backups.
- A stolen sync key, even with the forced command, can keep all 8 connection slots busy and stop syncing for every PC (denial of service). It cannot fill the server disk below 256 MiB free or create more than 64 vaults.
- A vault remembers at most 65,536 deletion and edit records and never forgets them. When full, edits and deletions are refused. Normal use is unlikely to get there.
- Two copies with the same vault ID (such as a restored backup) synced from two places both become copies of the same server vault.
- If copies edited separately on different PCs each turn sync on, entries deleted or changed on one side reappear, because the format before sync keeps no record of deletions (section 4).
- Malware running as you can copy the vault and key files or record your password, with or without sync. Sync does not change that risk.

## Advanced: command line and goyo-sync.conf

Everything the settings window does can also be done from the command line. `goyo-sync.exe` has no console window, so in PowerShell add `| Out-Host`: PowerShell then waits for it, shows the output and sets `$LASTEXITCODE`.

### Commands

|Command|What it does|
|---|---|
|(none)|Opens the settings window, or brings the open one to the front.|
|`--background`|Background sync, without a window. Every 2 seconds it looks for a change the vault app left and uploads it at once; every `interval` it fetches a new server version. Only one goyo-sync per folder runs at a time. Autostart and 'Save and start' run it this way.|
|`--once`|One sync pass over every vault, with the results printed.|
|`--check`|Read-only: settings, `ssh.exe`, the connection, and per vault the sync folder, vault ID and server version.|
|`--list`|The server's vaults: tag (`3FA2-C1D0`), 32-digit vault ID, newest version, size, time stored (UTC).|
|`--fetch <vault ID> <head or N> <new-file.goyo>`|Saves one server version to a new file; an existing file is never overwritten. Open it with **Restore from backup** in Goyo Vault.|
|`--autostart on` / `off`|Starts the helper at sign-in, or stops doing so (the `GoyoSync` Run value in the current user's registry, `"<goyo-sync.exe>" --background`). `off` also stops a running helper. After moving the folder, run `on` again or save in the settings window.|
|`--stop`|Stops the running helper.|
|`--self-check`|Checks the process protections and that the settings window can be built (used by the release checks).|

Exit codes: 0 ok, 1 error, 2 settings error. Messages follow `goyo-vault.lang` in the same folder (the language chosen in the vault app).

Setting up from the command line only, the steps are as follows. To install the server script, either use the one-line command that 'Install or update on server' sends (above), or copy it by hand:

```powershell
ssh my-server "mkdir -p ~/.local/share/goyo-sync && chmod 700 ~/.local/share/goyo-sync"
scp .\server\goyo-sync-server.py my-server:.local/share/goyo-sync/
ssh my-server "chmod 700 ~/.local/share/goyo-sync/goyo-sync-server.py && python3 -I ~/.local/share/goyo-sync/goyo-sync-server.py selftest"
.\goyo-sync.exe --check | Out-Host
.\goyo-sync.exe --autostart on | Out-Host
.\goyo-sync.exe --background
```

In this case connect once by hand with `ssh my-server` first, check the fingerprint and accept the host key: `--check`, `--once` and the background helper never connect to an unknown key.

### goyo-sync.conf

'Save and start' writes this file; you may also copy `goyo-sync.conf.example` and edit it with Notepad. One `name = value` per line. `#` starts a comment, so no value can contain `#` (a vault whose path has a `#` cannot be synced). An unknown name, an invalid value or a name given twice stops the helper (exit code 2); a vault whose sync folder already exists then shows "Sync warning" in the vault app. After editing it by hand, restart the helper ('Save and start' in the settings window, or `--stop` and then `--background`).

|Name|Default|Meaning|
|---|---|---|
|`host`|(required)|The ssh destination: an alias from `%USERPROFILE%\.ssh\config`, or `[user@]host`. Letters, digits and `. _ -` only, not starting with `-`.|
|`remote`|`.local/share/goyo-sync/goyo-sync-server.py`|The server script, relative to your home folder on the server. Letters, digits and `. _ / ~ + -`.|
|`python`|`python3`|The Python command on the server. Letters, digits and `. _ / + -`.|
|`identity`|(empty)|Absolute path of a dedicated ssh private key; when set, only that key is used. `.goyokey` and `.goyo` files are refused.|
|`interval`|`60`|Seconds between checks for a new server version, 30 to 3600.|
|`timeout`|`120`|Seconds allowed for one ssh call, 30 to 600.|
|`vault`|(at least one)|Absolute path of a vault file to sync. One per line, up to 8. Key files (`*.goyokey`) are refused.|

Design and review notes: [FORMAT.md](FORMAT.md) and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) (in Korean).
