# Sync (optional): goyo-sync

[한국어](SYNC.md) · <b>English</b>

From 0.8.0 a separate tool, `goyo-sync.exe`, lets you use one vault on several PCs by exchanging **only the encrypted vault file** with your own SSH server. Without it nothing changes. The vault app, `goyo-vault.exe`, still has no network code and no code that starts other programs.

> [!WARNING]
> - **A vault with sync turned on, and every later backup of it, opens only in 0.8.0 or later.** 0.7.x and older refuse it with "Authentication failed". There is no way back. Update all your PCs to 0.8.0 or later first.
> - This feature is new. It has automated tests and AI reviews but no professional security audit. Make a **vault backup and a key backup** before you turn it on.

`my-server`, `<user>` and `<you>` in this document are examples. Use your own ssh alias and user names.

## What travels and what stays on the PC

- **Sent to the server:** the whole encrypted vault file (`GOYOVA02` format; `GOYOVA04` for a vault whose key was changed in 0.9.0).
- **Never leaves the PC:** the key file (`.goyokey`), the password, the OTP secret and any plaintext. Without the key file neither the server nor goyo-sync can decrypt the vault. The only exception is a vault with 'key-file sync' turned on in the experimental security-key build ([SECURITY_KEY.en.md](SECURITY_KEY.en.md)).
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

**Upgrading to 0.9.0, in order.** A vault whose key (data key) was changed in 0.9.0 is uploaded in the `GOYOVA04` format. The 0.9.0 server script and helper take both `GOYOVA02` and `GOYOVA04`; older ones do not take `GOYOVA04`. So update **the server script first** ('Install or update on server'), **then Goyo Vault and goyo-sync on every PC**, and change keys only after that. When the order slips, this is what you see:

- Old server script: the 0.9.0 helper shows the `oldserver` state ('Server script update needed'), and the vault app says "The goyo-sync script on the server does not accept this vault's format…". Changes stay on this PC and go up within 10 minutes of updating the script (at once if you restart the helper).
- 0.8 helper: its own checks refuse the file to upload, so it shows only `refused` (Sync warning, "Sync error: see goyo-sync.log"); the log says `refused outgoing before upload`. Once goyo-sync is 0.9.0, its first run uploads that file once more.
- 0.8 Goyo Vault: it refuses `GOYOVA03`/`GOYOVA04` vault files and server copies as "a vault format made by a newer version" and stops syncing. It never overwrites them.

## 1. Install and open the settings window

`goyo-sync.exe`, `server\goyo-sync-server.py` and `goyo-sync.conf.example` come in the `GoyoVault` folder of the Goyo Vault ZIP you built as the README's "Install" section describes. There is nothing else to install.

In the GoyoVault folder, **double-click `goyo-sync.exe`** to open the settings window. It looks like Goyo Vault, and follows the dark or light theme and the Korean or English language chosen in the vault app. Only one window opens; starting it again brings the open one to the front.

The window has three parts, top to bottom:

- **Server**: the ssh host, 'Check connection', 'Install or update on server', a result line and 'Advanced settings'.
- **Vaults**: the vaults to sync with each one's state, 'Add…', 'Remove' and 'Bring to this PC…' (another PC's vault, from the server). The security-key build has 'Forced command line…' under the list.
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

**Only your Windows account may read the key file.** A key made with `ssh-keygen` as above is so, but a key copied from another folder or PC takes that folder's permissions and may become readable by other accounts (Users and so on). Windows ssh then silently ignores the key (`UNPROTECTED PRIVATE KEY FILE`, `bad permissions` in its `-E` log) and logs in with your usual key, which has no forced command, so the server sees a connection without `--key-sync`. goyo-sync does not use a connection in which ssh ignored the dedicated key it was given: the helper shows `auth` and logs `the dedicated SSH key was ignored: bad permissions`, and 'Check connection' says why and shows the commands that fix it. This counts only when ssh's log names **the dedicated key file** (the same warning about another key file of `~/.ssh/config` does not matter: the dedicated key was used). In PowerShell:
```powershell
icacls "$HOME\.ssh\goyo_sync" /inheritance:r
icacls "$HOME\.ssh\goyo_sync" /grant:r "$($env:USERNAME):F"
```
The settings window makes no keys. Always make the key on this PC with `ssh-keygen` as above.

With several PCs, make one key per PC and add one line for each. If you lose a PC, delete only its line. A vault that uses key-file sync of the security-key build also needs `--key-sync=<vault ID>` on this line. In the security-key build's settings window, 'Forced command line…' makes the line with the listed vaults that use key-file sync (see 'Key-file sync' below). Later script updates also work, since 'Install or update on server' uses your usual login, not the dedicated key.

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
|… · key: on the server / not on the server / not allowed by the server|(Security-key build) The vault's key file on the server, as the helper last saw it. 'Not allowed by the server' means this PC's forced-command line has no `--key-sync` for the vault, and shows only for a vault that uses key-file sync (a vault that keeps its key file on its PCs shows nothing). When such a vault's state is 'key: not allowed by the server · use the 'Forced command line…' line' (`nokeys`), change the line.|

- **Sync now**: one sync pass over every vault in the list now, with each vault's result shown in the list for a minute (as `--once`). A vault the background helper is working on is skipped.
- **Stop**: stops the running background helper (as `--stop`).
- **View log**: shows the last 400 lines of `goyo-sync.log` inside the window (continued from `goyo-sync.log.1` after the 256 KiB rollover).

The status line tells you about unsaved changes, and closing the window asks once.

## 4. Turn sync on

Once the sync folder exists, open the vault in Goyo Vault and a dialog appears. It says that the key file and password are never sent, and that the vault format changes so **version 0.7 and older cannot open this vault or later backups of it.** For a vault whose keys were changed in 0.9.0 it says instead that **0.8 and older cannot open it and a 0.8 server script does not accept its copies, so update the server script first, then your other PCs, to 0.9.0 or later.**

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
|**Sync warning**|Something needs you: the server sent an older state, a copy failed authentication, merging would exceed a limit, a newer format arrived, or the helper is in `refused`, `config`, `update`, `oldserver` or `keyfile`. A warning from the vault side stays until you lock. It also shows while a server copy from a PC that changed the key stops sync, and while this PC is open with an older key file ('After a key change' below).|

**Check code.** When you unlock (or when the vault first becomes synced afterwards), the status line shows `Synced · check code XXXX-XXXX-XXXX-XXXX` once. It is computed over each live entry's ID and contents (all four fields) and over the deletion records, so **the same code on two PCs means the same contents.** For a vault opened with a 0.9.0 key file (one whose key was changed) it also covers the key file's state (revision and tag), so two PCs show the same code only once they hold the same key file. A different code means sync is still under way, one PC has not taken the new key file yet, or the server shows different copies to different PCs. It is computed with the ID key (the first data key), so the code reveals nothing about the entries. It has 64 bits, so even someone with the key needs about 2^64 tries to make other contents give the same code. The OTP record is left out. Lock and unlock to see it again. The 'key check code' that compares key files is in Key management.

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
|The server copy uses a newer format, so sync stopped.|Update Goyo Vault on this PC. This happens for a server copy in `GOYOVA05` or later. It is neither merged nor overwritten with this PC's state.|
|Another PC changed this vault's key, so sync stopped. …|The server copy was saved under a key this PC's key file lacks, at a later key-file state. Bring that PC's new key file by USB and take it with 'Key management › Receive a new key file' (do not copy it over). Until then this PC's changes stay on this PC. If no PC changed the key, the server copy may be forged. Shown once each time sync stops: again if the key changes again after this PC took the new key file.|
|Another PC turned on security keys for this vault, so sync stopped. …|That key file needs a security key, which this build cannot take ([SECURITY_KEY.en.md](SECURITY_KEY.en.md)). If nothing like that happened, the server copy may be forged. Shown whatever the copy's revision.|
|Two PCs changed the key separately, so the key files diverged. …|The server copy was saved under a key this PC does not know at the same or a lower revision (a copy whose key file needs a security key gets the notice above instead), or under this PC's current key at the same revision in another state. On one PC, take the other PC's key file with 'Receive a new key file' to join them ('After a key change' below).|
|The server copy names an old key of this PC's but does not open with it, so sync stopped. …|A damaged or forged copy. Sync resumes when another PC uploads a new copy; if there is no such PC, you can overwrite the server copy in Key management.|
|Another PC's key file is newer than this PC's. Sync stopped. …|The server copy was saved under this PC's current key at a later key-file state. Take that key file with 'Receive a new key file', and do not change the key on this PC before that.|
|This PC is open with a key file older than the one it wrote before, so sync stopped. …|While open with an older key file, this PC neither merges nor overwrites nor uploads. Open again with the latest key file this PC wrote, or, if you went back yourself, press [This key file is right] in Key management. Shown once per session.|
|A server copy made with an old key was overwritten with this PC's state, not merged. …|A PC that has not taken the new key file, or someone with an old key copy, uploaded it. Once that PC takes the new key file, its changes are merged. A copy that holds no entry or deletion this PC lacks (such as this PC's own upload from before its key change) is overwritten without this notice.|
|The goyo-sync script on the server does not accept this vault's format. …|The server script is older than 0.9.0 and refused a `GOYOVA04` upload (helper state `oldserver`). Press 'Install or update on server' in the settings window. Changes are kept on this PC.|
|The server does not take the upload because its key file record does not match this PC's vault copy. …|The server refused the upload with KEY_BEHIND (helper state `keyfile`). Only a server with key-file sync answers so; the current server script does not. Uploads resume once this PC has that key file.|
|The key file is inside the sync folder, so this vault does not sync.|Move the key file to another folder.|
|Sync offline / SSH authentication failed / host key changed / helper not running / see goyo-sync.log|See troubleshooting below. Your changes are saved on this PC.|

## 6. Add a second PC

1. Install Goyo Vault 0.8.0 or later on the new PC, and make ssh to the server work as in Requirements (a key or ssh-agent).
2. **Copy the key file (`.goyokey`) by USB.** Never send it through the server, mail or a cloud service.
3. Start `goyo-sync.exe`, enter the server and press **Check connection** (on a first connection, compare the fingerprint).
4. Get the vault file, one of two ways:
   - **From the server:** **Bring to this PC…** lists the server's vaults. The tag (for example `3FA2-C1D0`) matches the one in the OTP app entry `Goyo Vault (3FA2-C1D0)`; on the first PC this list marks that vault as 'Same vault as vault.goyo on this PC', so you can read the tag there too. The security-key build also shows, per vault, 'key file: on the server / not on the server (by USB) / not checked with this PC's line' (for the first four vaults only, as each takes one more ssh login). A new PC has no key-file sync vault in its list yet, so it shows 'not checked with this PC's line': bring the vault first, then 'Forced command line…' puts it in the line. Pick the vault, press **Bring it here…** and choose the **folder**. The name is `vault.goyo` by default (in Goyo Vault's own folder Goyo Vault opens it at once); if a file or sync folder (`vault.goyo.sync`) of that name is already there, nothing is overwritten and you are asked for another folder. The newest server version is saved there and **added to the sync list** (an unsaved change). A message then says what to do next.
   - **By USB:** copy the first PC's `vault.goyo` by USB too, put it in a folder of this PC and add it with **Add…**. This needs no trust in the server.
5. Put the key file next to that vault under the same name (`vault.goyokey`, step 2). In the security-key build, when the vault uses key-file sync, 'Bring to this PC' brings the server's key file into the sync folder too, so no USB is needed: Goyo Vault's **Vault brought from the server** screen asks for the password, the security key and another PC's key check code, then saves the key file next to the vault ('A new PC' in [SECURITY_KEY.en.md](SECURITY_KEY.en.md)).
6. Press **Save and start**, and open that vault in Goyo Vault (if it is not `vault.goyo` in Goyo Vault's folder, choose it with **Open a vault file (other folder or brought from the server)**, or **Browse** on the login screen). It is already in the sync format, so it links without a dialog. This first copy trusts the server, so after opening it **compare 'Synced · check code …' on the status line at the bottom with the first PC's**. When both show the same code, you are done (it is not the security-key build's 'key check code').

**Restore from a backup file** brings back a backup file made with 'Vault backup'. It is not the way to bring another PC's vault to this PC.

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
- While sync is on, never drop another file in place of `vault.goyo` by hand. Use **Restore from a backup file** to work with another copy, and do not edit files inside `vault.goyo.sync`.

## After a key change (0.9.0)

From 0.9.0 a password change replaces the vault's data key (section 7 of the README). For a synced vault:

- **Update order:** the server script ('Install or update on server'), then Goyo Vault and goyo-sync on every PC, and only then the key change.
- Change the key **on one PC at a time.**
- **On the other PCs,** bring the new key file of the PC that changed it by USB and take it with 'Key management › Receive a new key file'. **Do not copy it over** their key files. Until then such a PC stops with "Another PC changed this vault's key, so sync stopped…", and its changes stay on it until they are merged after it took the file. Two PCs that show the same key check code (`E3 · …`) in Key management have the same key file.
- **One vault file shared by several PCs (a USB stick, a shared folder) with a key file on each PC:** after a password change on one PC the other PCs' key files no longer open that vault file ("This vault file is saved with a new key file changed on another PC (revision N)…"). Carry the new key file to them and open with it. Here the key backup made right after the change is the only safeguard: losing that new key file loses the vault on every PC.
- **Vault file and key file together on a stick used by several PCs:** a change on one PC changes both files on the stick, so the other PCs open as before. Opening an old vault file left elsewhere with the new key file for the first time asks "This vault file is saved under an older key of this key file…"; answer yes only if the key really was changed on another PC and this is the first unlock here since.
- **Halts and forgeries:** a server copy under a key this PC does not know only stops sync; it is neither merged nor overwritten. If no PC changed the key and sync stops anyway, the server copy may be forged. A halt is not recorded: every unlock judges the server copy again, and it ends when another PC uploads a new copy or this PC takes the new key file. It also ends with its copy: when the newest server copy is replaced by one that names no key (damaged, another vault's, a newer format), or the sync folder is reset.
- **Copies uploaded under an old key are overwritten:** a copy that a PC without the new key file, or someone with an old key copy, uploaded under the old key is not merged by a PC with the new key; that PC puts its own state over it ("A server copy made with an old key was overwritten with this PC's state, not merged…"), so deletions or edits sent with an old key copy cannot enter the vault under the new key. A copy that holds nothing this PC lacks (such as this PC's own upload from before its key change) is overwritten without a notice. The overwritten copy stays in the server history, and once the lagging PC takes the new key file its changes are merged.
- **Both PCs changed the key separately (a fork):** both stop with "Two PCs changed the key separately, so the key files diverged…". On one PC, take the other PC's key file with 'Receive a new key file': that writes a key file joining both under a new data key (if both PCs changed the password, you choose the one to keep). Carry that result to the other PC and take it there; it continues that PC's key file, so it is taken as it is. With three or more PCs, do not join the same file on two PCs separately: carry the newest result from PC to PC. Each separate join makes its own data key and splits the files again.
- **Overwriting the server copy:** only when the PC that changed the key died with no key file or key backup left, so that no PC can end the halt (or when you are sure the server copy is forged), use **Overwrite the server copy with this PC's state…** in Key management. It shows that copy's revision, the first 8 hex digits of its key ID and its server version, checks the password (and OTP) again, and puts this PC's state over that server version. The overwritten copy is not merged; it stays only in the server history (last 200 versions). The decision covers that copy (that version with those bytes) in this session only; the next unlock, or any other server copy, is judged again. If the PC that changed the key was alive after all, it sees this PC's copy as an old-key copy and overwrites it in turn, and this PC halts again and takes that PC's key file; no data is lost. It is a last resort because after another PC's genuine key change, it puts this PC's state over what was changed there.
- **A PC opened with an older key file:** if this PC is open with a key file older than the one it wrote before ("This key file is older than the one this Goyo Vault saw before (revision N)…"), it neither merges nor overwrites nor uploads, and the server-copy overwrite is not offered: the server copy is then usually under the newer key this PC itself used before. Open again with the latest key file this PC wrote (a key backup), or take it with 'Receive a new key file'. If you went back yourself, press **This key file is right** in Key management. After that, sync stops again if the server copy was saved under the newer key; if this PC uploaded that copy, put this PC's state over it with the server-copy overwrite.
- **Check code:** for a vault opened with a 0.9.0 key file, the check code covers the key file's state, so two PCs match only after both took the same key file, and 'Synced' does not show before.

## Key-file sync (security-key build, experimental)

In the security-key build ([SECURITY_KEY.en.md](SECURITY_KEY.en.md)), a vault with security keys on can turn on **key-file sync**, per vault. Its security-key key file (`GOYOKS01`) then travels through the server too, so a password change or a key removal needs no USB carry. **In exchange, to anyone with the server or any PC's sync SSH key, the key file is no longer a separately guarded factor.** The remaining barriers are the password and a registered security key (with its PIN), and you must assume a hacked server keeps every key file ever uploaded. In the default build, in vaults without security keys, and in vaults with keys but without key-file sync, the key file never leaves the PCs.

- **Security-key build on both sides:** both the vault app and goyo-sync must be the security-key build. The server script is the same file (0.9.0).
- **Forced command:** in the dedicated-key line of **every PC** that uses the vault, add `--key-sync=<vault ID>` after `serve` (32 lower-case hex digits, the second column of `goyo-sync.exe --list`; several vaults joined by commas, no spaces, up to 64). A connection without it does not take key requests (goyo-sync state `nokeys`), and a malformed argument makes the server refuse every request of that line (`server`). In the settings window of the security-key build's goyo-sync, 'Forced command line…' shows this line (fill in the public key yourself; nothing is saved). It names by itself the listed vaults that use key-file sync: a vault whose file or the server's latest copy was saved with a `GOYOKS01` key file (also when another PC turned it on), one the vault app left a key request for, one whose key file the server holds, and one in state `nokeys`. To name a vault before turning it on, append its ID by hand. Key-file sync is switched in Goyo Vault's 'Key management' only; the settings window has no switch for it.
  ```
  restrict,command="/usr/bin/python3 -I /home/<user>/.local/share/goyo-sync/goyo-sync-server.py serve --key-sync=0123456789abcdef0123456789abcdef" ssh-ed25519 AAAA… goyo-sync-pc1
  ```
  After turning it on in Goyo Vault, press 'Forced command line…' again and put that line on the server. Once the line is changed, the helper checks again within two minutes (at once when 'Save and start' restarts it). Change the other PCs' lines to the same ID too. Remove it from every line once turning it off has finished and every PC has taken that. A vault named on a line keeps a key-record floor on the server, so whoever steals that line's sync key can block every PC's uploads.
- **A data folder with `flock`:** the server takes a `flock` on `data/<vault ID>/lock` for every key operation of that vault. Once a vault has a key record (`data/<vault ID>/k/`), every connection's upload of it is also checked against that record inside this lock (a mismatch is KEY_BEHIND, state `keyfile`). So the data folder (`<script folder>/data`) must support `flock`. Every common local Linux file system does, and NFS emulates it; the selftest at install checks it. If the lock is not obtained within 20 seconds the server answers `busy` (state `server`) and the helper tries again later.
- **Deleting `k/`:** delete `data/<vault ID>/k/` **only while no PC syncs that vault**.
- **Turning it on and using it:** **Turn key-file sync on…** in 'Key management'. Other PCs take changes after their unlock with **Get…** in 'Key management' (a removal by picking the lost keys, an addition or settings change by typing the changing PC's key check code). Until then that PC neither uploads nor merges.
- **A new PC:** **Bring to this PC…** in the settings window brings the server's key file into the sync folder together with the vault file (that PC's line needs `--key-sync` too). Goyo Vault's **Vault brought from the server** screen asks for another PC's key check code and saves the key file next to the vault. Carrying the key file by USB the first time works too; its first unlock asks for the code as well.
- **Turning it off:** **Turn key-file sync off…** in 'Key management' (turning keys off does it too). This PC asks the server to delete the key file (sent when the security-key build's goyo-sync runs) and changes the data key. Turning it off ends the vault's whole key record on the server, so another PC's change that this PC has not taken yet disappears from the server too. Other PCs need this key file by USB. Do not undo it by uploading again from another PC.
- **A lost PC:** delete its `authorized_keys` line at once. That key can fetch the key file or stop key-file sync (never make a forged key file accepted). Use one server account per person.
- **Key files in the sync folder:** `vault.goyo.sync\` may hold `incoming.goyokeysync` (a copy of the server's key file), `outgoing.goyokeysync` (a request to send) and `prune.request`. Do not edit them. They are not authenticated, so someone who can write that folder can disrupt sync or have server history deleted.

The details (the 14 trade-offs, what to do on every PC when a key is lost, the order of turning it off) are in 'Key-file sync' in [SECURITY_KEY.en.md](SECURITY_KEY.en.md).

## 8. Getting things back: server history and pre-merge copies

The server keeps **the newest 200 versions** of each vault as ciphertext. Each upload of changed contents is one version. The newest version number appears in the 'Bring to this PC…' list and in `goyo-sync.log`. 'Bring to this PC…' in the window brings the newest version as a vault this PC syncs, not for going back; get an older one from the command line (see "Advanced: command line" below).

```powershell
.\goyo-sync.exe --fetch <32-digit vault ID> 41 C:\Users\<you>\GoyoVault\from-server-v41.goyo | Out-Host
```

The target folder must already exist; the file is never overwritten.

1. Open the file with **Restore from a backup file**, restoring to a **new name** (for example `vault-v41.goyo`). Your current key file and password open it. After key changes, versions saved within the last 62 key changes (and versions from before the first change, always) still open with the current key file; older ones open with the key copy and password of their time.
2. Find the entries you need and enter them again in your current vault.
3. Do not sync the restored copy. It has the same vault ID, so adding it to the list makes it a copy of the same server vault, and the server's deletion records delete those entries again. No merge brings a deletion back.

Open `vault.goyo.sync\pre-merge-*.goyo` the same way (Restore from a backup file, new name).

## 9. Turning sync off and uninstalling

**Off on one PC:**
1. In the settings window, turn off **Start automatically when I sign in to Windows** (applies at once) and press **Stop**. Stop it first: a running helper creates the folder again.
2. To turn off one vault, **Remove** it and press **Save and start**. To turn off all, delete the helper's settings and log (`goyo-sync.conf`, `goyo-sync.log*`). `goyo-sync.exe` does nothing unless you open it, so it can stay.
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
|`auth`|Offline, authentication message|ssh.exe itself reported that the server refused the key (`Permission denied`). The same words printed by the server or its shell start-up files give `server`.|Check the dedicated key, `authorized_keys` and ssh-agent, and try `ssh my-server` (with a dedicated key, `ssh -i …`) by hand. If other accounts can read the dedicated key file, ssh ignores the key, so goyo-sync does not use that connection and shows this state (log: `the dedicated SSH key was ignored: bad permissions`); 'Check connection' shows the commands that fix it (see 'Dedicated key with a forced command'). It tries again every 15 minutes.|
|`hostkey`|Offline, host key message|The server's host key is not in `known_hosts` or has changed. Decided only from ssh.exe's own messages: text the server prints, a reason it sends when it drops the connection, or its version line never gives this state.|Press 'Check connection'. On a first connection you can compare the fingerprint and accept it. For a changed key, unless you reinstalled the server, this can be a man-in-the-middle attack: fix `known_hosts` only after checking the fingerprint on the server itself. Until then it does not connect; it tries again every 15 minutes.|
|`nossh`|Offline|`System32\OpenSSH\ssh.exe` is missing.|Add 'OpenSSH Client' under Optional features.|
|`server`|Offline|The server script is missing or failed, Python is missing, or the reply was malformed. Too much text printed by the login shell also ends here. Also: an upload was answered with a CONFLICT no honest server sends (log: `holding back uploads`), or the remote side printed text that looks like an ssh error. A server already handling 8 connections (`busy` in the log) also lands here; the helper tries again after 30 s, then at growing intervals.|'Check connection' tells a missing script or Python apart. Install again with 'Install or update on server' (selftest included), and check the script path and Python command in the advanced settings. If shell startup files print text, make them print only in interactive shells (for example `[[ $- == *i* ]] \|\| return` at the top of `~/.bashrc`). If the log shows `holding back uploads`, the server may be keeping this PC's uploads out (a freeze); check the server. Your changes stay on this PC, and only the newest file is retried, 30 seconds to 15 minutes apart.|
|`refused`|Sync warning|The helper's checks or the server refused the upload (a link at the file, another vault's ID, the server's limit of 64 vaults, less than 256 MiB would stay free on the server disk, and so on).|Read the reason with 'View log'. Editing the vault again retries with a new file. If the log says `a file of another vault` (for example a new vault at the same path), press 'Stop', delete the `vault.goyo.sync` folder and press 'Save and start'. If it was the server's disk space, free up room on the server, then edit the vault again.|
|`config`|Sync warning|`goyo-sync.conf` has an error, so the helper stopped.|Open the settings window: it names the line and shows the settings it could read. Fix them and press 'Save and start'.|
|`update`|Sync warning, newer-format message|The server copy uses a newer Goyo Vault format (`GOYOVA05` or later).|Update Goyo Vault and goyo-sync on this PC.|
|`oldserver`|Sync warning, server-script message|The server script is older than 0.9.0 and refused a `GOYOVA04` upload (log: `server refused GOYOVA04`). The settings window's list shows 'Server script update needed'.|Press 'Install or update on server'. The same file is uploaded again every 10 minutes and when the helper restarts.|
|`keyfile`|Sync warning, key-file message|The server refused the upload with KEY_BEHIND: its key file record does not match this vault copy's key. The server answers so only while it holds a key record (`k/`) for that vault, that is, only for a vault that uses key-file sync of the security-key build. The settings window's list shows 'Key file update needed'.|Uploads resume once this PC has the key file changed on another PC; until then it tries again every 10 minutes.|
|`nokeys`|Sync warning|(Security-key build) This vault uses key-file sync, but this PC's server connection does not take its key requests (no `--key-sync=<vault ID>` in the forced command). The settings window's list shows 'key: not allowed by the server · use the 'Forced command line…' line'. When ssh logged in with your usual key because of the dedicated key file's permissions, the state is `auth` instead.|In the server's `authorized_keys`, replace this PC's line with the one 'Forced command line…' in the settings window makes ('Key-file sync'). The helper checks again within two minutes. Until then vault uploads may be refused.|

For "Helper off", press 'Save and start' in the settings window and check that autostart is on. If it ends right after starting, the status line and 'View log' tell you why.

**A key file in a newer format.** If unlocking says "This key file was made by a newer version. Update Goyo Vault.", a newer version than this PC's Goyo Vault wrote that key file: update this PC. For a key file locked by a security key, see [SECURITY_KEY.en.md](SECURITY_KEY.en.md).

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
|`server refused GOYOVA04: its goyo-sync script is older than 0.9.0; use 'Install or update on server'`|The server script does not know `GOYOVA04` (`oldserver`). Press 'Install or update on server'.|
|`retrying a GOYOVA04 upload an older helper refused`|A `GOYOVA04` file that a 0.8 helper refused is uploaded once more in this run. Normal.|
|`server refused the upload: its key file for this vault has another state`|The server refused it with KEY_BEHIND (`keyfile`).|
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
- **After a key change, old key copies can no longer write through the server.** Once the password was changed in 0.9.0, every PC that took the new key file overwrites copies uploaded under an old key instead of merging them, so deletions or edits sent with an old key copy and the password of that time do not get in. Server versions and backups from before the change can still be read, and old copies can be uploaded again to disturb sync (denial of service; they are overwritten). Someone who can also write the vault folder can put an old vault file in place only on a PC that has not opened the vault since the change, and even there the app first asks ("…saved under an older key…"); every other PC refuses it. A PC that has not taken the new key file still uses the old key and behaves as 0.8 until it does.
- **Before any key change it is as in 0.8.** Someone with an old key copy and the password of that time can push real deletions or edits through the server. Swapping in other text under the same IDs also counts as removed entries. Pre-merge copies, messages and server history make that visible but do not prevent it. Deleting only a little at each unlock (one entry, say) makes no pre-merge copy, only an "N removed" message each time. Whoever can write to the server can also push the 200-version history out with new uploads.
- **Changing the password** changes that PC's key file and data key, and the other PCs stop syncing until they take that key file with 'Receive a new key file' ('After a key change' above). If the PC that changed the key is gone together with its key file, only overwriting the server copy is left, and that is left to your judgment.
- Folders with a reparse point, such as OneDrive Files On-Demand folders, are not used as sync folders. As the README says, keep the vault out of cloud folders anyway.
- The 200-version history is kept by the server, so a hostile server can delete it. Keep making your own vault and key backups.
- A stolen sync key, even with the forced command, can keep all 8 connection slots busy and stop syncing for every PC (denial of service). It cannot fill the server disk below 256 MiB free or create more than 64 vaults.
- A vault remembers at most 65,536 deletion and edit records and never forgets them. When full, edits and deletions are refused. Normal use is unlikely to get there.
- Two copies with the same vault ID (such as a restored backup) synced from two places both become copies of the same server vault.
- If copies edited separately on different PCs each turn sync on, entries deleted or changed on one side reappear, because the format before sync keeps no record of deletions (section 4).
- Malware running as you can copy the vault and key files or record your password, with or without sync. Sync does not change that risk.
- **For a vault with key-file sync (security-key build)**, 'the key file never leaves the PCs' above does not hold. A key change the server hides (a freeze) does not reach a PC until you act on that PC, and the server's deletion of key files means something only with an honest server ([SECURITY_KEY.en.md](SECURITY_KEY.en.md)).

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
|`--fetch <vault ID> <head or N> <new-file.goyo>`|Saves one server version to a new file; an existing file is never overwritten. Open it with **Restore from a backup file** in Goyo Vault.|
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
