package app.goyovault

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** The server's vaults as the last "목록 불러오기" showed them (kept while the screen is left for a share). */
private var listed by mutableStateOf<List<ServerVault>?>(null)

/**
 * "서버에서 가져오기" (`importing`) and the sync settings: ① the server
 * (Tailscale only), ② this phone's key and the line the PC's goyo-sync
 * puts on the server ('Android 기기 추가…'), ③ the check with the host
 * key's fingerprint, and for an import ④ the server's vaults, one of
 * which comes to the phone with its key file ("서버에서 가져온 금고").
 */
@Composable
fun ServerSetup(activity: MainActivity, importing: Boolean) {
    val context = LocalContext.current
    val root = Sync.root(context)
    val back = {
        AppState.screen = if (AppState.session != 0L) Screen.List else Screen.Home
    }
    BackHandler { back() }
    val loaded = remember { Native.syncSettingsLoad(root) }
    val host = rememberTextFieldState(loaded?.get(0) ?: "")
    val port = rememberTextFieldState(loaded?.get(1) ?: "22")
    val user = rememberTextFieldState(loaded?.get(2) ?: "")
    val remote = rememberTextFieldState(loaded?.get(3) ?: ".local/share/goyo-sync/goyo-sync-server.py")
    val python = rememberTextFieldState(loaded?.get(4) ?: "python3")
    var saved by remember { mutableStateOf(loaded != null) }
    var blob by remember { mutableStateOf(SyncKey.publicBlob(context)) }
    var pinned by remember { mutableStateOf(Native.syncPinned(root)) }
    var line by remember { mutableStateOf<String?>(null) }
    var advanced by remember { mutableStateOf(false) }
    var confirmNewKey by remember { mutableStateOf(false) }
    var confirmForget by remember { mutableStateOf(false) }
    var hostKeyAsk by remember { mutableStateOf(false) }
    var fetchAsk by remember { mutableStateOf<ServerVault?>(null) }
    fun refreshLine() {
        line = blob?.let {
            try {
                Native.syncLine(root, it, android.os.Build.MODEL ?: "")
            } catch (e: GoyoException) {
                null
            }
        }
    }
    LaunchedEffect(blob) { refreshLine() }
    LaunchedEffect(Sync.state, Sync.fingerprint) {
        if (Sync.state == "hostkey-unknown" && Sync.fingerprint.isNotEmpty()) hostKeyAsk = true
    }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row {
            Text(
                if (importing) "서버에서 가져오기" else "동기화 설정",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { back() }) { Text("‹ 뒤로") }
        }
        Text(
            (if (importing) "PC에서 goyo-sync로 동기화하는 금고를 내 서버에서 받아 옵니다. " else "") +
                "서버와는 Tailscale로만 연결합니다. 휴대폰과 서버가 모두 Tailscale에 들어 있어야 하고, 서버 주소는 " +
                "Tailscale 이름(…ts.net)이나 100.x 주소여야 합니다. 그 밖의 주소에는 연결하지 않습니다.",
            style = MaterialTheme.typography.bodySmall,
        )

        Text("① 서버", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(state = host, label = { Text("서버 (Tailscale 이름 또는 100.x 주소)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(state = user, label = { Text("사용자 이름 (PC의 goyo-sync 설정과 같게)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            state = port,
            label = { Text("포트") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        TextButton(onClick = { advanced = !advanced }) { Text(if (advanced) "고급 설정 숨기기" else "고급 설정 (스크립트 경로, 파이썬)") }
        if (advanced) {
            OutlinedTextField(state = remote, label = { Text("서버의 스크립트 경로") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(state = python, label = { Text("파이썬 명령") }, modifier = Modifier.fillMaxWidth())
        }
        Button(onClick = {
            try {
                Native.syncSettingsSave(
                    root,
                    host.text.toString(),
                    port.text.toString(),
                    user.text.toString(),
                    remote.text.toString(),
                    python.text.toString(),
                )
                saved = true
                AppState.message = "서버 설정을 저장했습니다."
                refreshLine()
                pinned = Native.syncPinned(root)
                Sync.schedule(context)
            } catch (e: GoyoException) {
                AppState.message = e.message
            }
        }) { Text("저장") }

        HorizontalDivider()
        Text("② 이 휴대폰의 키를 서버에 넣기", style = MaterialTheme.typography.titleMedium)
        if (blob == null) {
            Text(
                "이 휴대폰 전용 ed25519 키를 만듭니다. 개인 키는 Android 키 저장소(있으면 StrongBox)의 키로 " +
                    "암호화해 이 앱에만 두고, 밖으로 내보내지 않습니다.",
            )
            Button(onClick = {
                AppState.work("키 만드는 중…", { SyncKey.create(context) }) {
                    blob = it
                    Sync.schedule(context)
                }
            }) { Text("키 만들기") }
        } else {
            Text(
                "아래 줄을 PC로 보낸 뒤, PC에서:\n" +
                    "1. 그 줄을 PC의 클립보드에 복사합니다.\n" +
                    "2. goyo-sync 설정 창(goyo-sync.exe를 그냥 실행하면 열림)을 열고 'Android 기기 추가…'를 누릅니다.\n" +
                    "3. 창이 보여 주는 줄(이 휴대폰의 키와 이름, 그 PC의 금고 ID들)을 확인하고 '예'를 누릅니다.\n" +
                    "줄은 공개 키라 비밀이 아닙니다. [공유…]로 메신저·메일·Tailscale 파일 보내기 등으로 PC에 보내거나, 직접 입력하세요. " +
                    "이 키로는 서버에서 동기화 스크립트만 실행됩니다.",
            )
            val l = line
            if (l != null) {
                SelectionContainer { Text(l, style = MaterialTheme.typography.bodySmall) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        val cm = context.getSystemService(android.content.ClipboardManager::class.java)
                        cm?.setPrimaryClip(android.content.ClipData.newPlainText("goyo-sync line", l))
                        AppState.message = "줄을 복사했습니다(공개 키라 비밀은 아닙니다)."
                    }) { Text("줄 복사") }
                    OutlinedButton(onClick = {
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, l)
                        }
                        activity.startActivity(Intent.createChooser(send, "PC로 줄 보내기"))
                    }) { Text("공유…") }
                }
            } else {
                Text("줄을 만들 수 없습니다. 위 서버 설정을 저장하세요.")
            }
            TextButton(onClick = { confirmNewKey = true }) { Text("키 새로 만들기…") }
        }

        HorizontalDivider()
        Text("③ 연결 확인", style = MaterialTheme.typography.titleMedium)
        val p = pinned
        if (p == null) {
            Text(
                "처음 연결하면 서버의 호스트 키 지문을 보여 주고 받을지 묻습니다. 서버에서 직접 확인한 지문" +
                    "(ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub)과 비교하세요.",
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            Text("고정된 호스트 키: " + p[0] + "\n" + p[1], style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = { confirmForget = true }) { Text("고정된 호스트 키 지우기…") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !Sync.running && saved && blob != null, onClick = {
                AppState.scope.launch {
                    Sync.check(context)
                    pinned = Native.syncPinned(root)
                }
            }) { Text("연결 확인") }
            if (!importing && AppState.home != Home.Welcome) {
                OutlinedButton(enabled = !Sync.running, onClick = { Sync.now(context) }) { Text("지금 동기화") }
            }
        }
        if (Sync.running) Text("진행 중…")
        val st = Sync.state
        if (st != null) {
            Text(
                Sync.label() + " · " + Sync.text,
                color = if (Sync.warning()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
            )
            if (st == "hostkey-changed" && Sync.fingerprint.isNotEmpty()) {
                Text("서버가 보낸 키: " + Sync.fingerprint, style = MaterialTheme.typography.bodySmall)
            }
        }

        if (importing) {
            HorizontalDivider()
            Text("④ 서버의 금고", style = MaterialTheme.typography.titleMedium)
            Button(enabled = saved && blob != null && pinned != null, onClick = {
                AppState.work("서버의 금고 목록 불러오는 중…", { Server.list(context) }) {
                    listed = it
                    if (it.isEmpty()) AppState.message = "서버에 금고가 없습니다. PC에서 goyo-sync로 금고를 먼저 올리세요."
                }
            }) { Text("목록 불러오기") }
            if (pinned == null) {
                Text("먼저 ③ 연결 확인으로 서버의 호스트 키를 받으세요.", style = MaterialTheme.typography.bodySmall)
            }
            listed?.forEach { v ->
                Column(
                    Modifier.fillMaxWidth().clickable { fetchAsk = v }.padding(vertical = 8.dp),
                ) {
                    Text("금고 ${v.tag}", style = MaterialTheme.typography.titleMedium)
                    Text("서버 버전 ${v.head} · ${v.sizeText()} · ${v.keyText()}", style = MaterialTheme.typography.bodySmall)
                    Text(v.id, style = MaterialTheme.typography.bodySmall)
                }
                HorizontalDivider()
            }
        }
    }
    val f = fetchAsk
    if (f != null) {
        AlertDialog(
            onDismissRequest = { fetchAsk = null },
            properties = secureDialog,
            title = { Text("이 휴대폰으로 가져오기") },
            text = {
                Text(
                    "금고 ${f.tag}(서버 버전 ${f.head})를 이 휴대폰으로 가져옵니다. " +
                        if (f.key == "held") {
                            "서버의 열쇠 파일도 함께 받습니다. 다음 화면에서 비밀번호와 YubiKey로 연 뒤, 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다."
                        } else {
                            "서버에서 이 금고의 열쇠 파일을 받지 못하면, 열쇠 파일은 PC에서 파일로 가져와야 합니다."
                        },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    fetchAsk = null
                    AppState.work("가져오는 중…", { Server.fetch(context, f.id) }) { r ->
                        listed = null
                        AppState.refreshHome(context)
                        AppState.screen = Screen.Home
                        AppState.message = "가져왔습니다: 금고 ${f.tag} (서버 버전 ${r[0]}, ${r[1]}바이트). " + Server.keyText(r[2])
                        Sync.schedule(context)
                    }
                }) { Text("가져오기") }
            },
            dismissButton = { TextButton(onClick = { fetchAsk = null }) { Text("취소") } },
        )
    }
    if (hostKeyAsk) {
        val fp = Sync.fingerprint
        AlertDialog(
            onDismissRequest = { hostKeyAsk = false },
            properties = secureDialog,
            title = { Text("처음 연결하는 서버") },
            text = {
                Text(
                    host.text.toString() + "의 호스트 키 지문:\n\n" + fp + "\n\n" +
                        "서버에서 직접 확인한 지문(서버에서 ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub)과 " +
                        "글자 하나까지 같을 때만 받으세요. 받으면 이 키로 고정되고, 다른 키를 보내는 서버에는 연결하지 않습니다.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    hostKeyAsk = false
                    try {
                        Native.syncPinHost(root, fp)
                        pinned = Native.syncPinned(root)
                        Sync.state = null
                        AppState.message = "호스트 키를 고정했습니다. '연결 확인'을 다시 누르세요."
                    } catch (e: GoyoException) {
                        AppState.message = e.message
                    }
                }) { Text("같습니다, 받기") }
            },
            dismissButton = { TextButton(onClick = { hostKeyAsk = false }) { Text("받지 않기") } },
        )
    }
    if (confirmForget) {
        AlertDialog(
            onDismissRequest = { confirmForget = false },
            properties = secureDialog,
            title = { Text("고정된 호스트 키 지우기") },
            text = {
                Text(
                    "서버를 다시 설치해 호스트 키가 바뀐 것이 확실할 때만 지우세요. 지운 뒤 '연결 확인'이 새 지문을 보여 주면 " +
                        "서버에서 직접 확인한 지문과 비교하세요. 그런 일이 없었는데 키가 바뀌었다면 누군가 연결을 가로채고 있을 수 있습니다.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmForget = false
                    try {
                        Native.syncForgetPin(root)
                        pinned = null
                        AppState.message = "고정된 호스트 키를 지웠습니다."
                    } catch (e: GoyoException) {
                        AppState.message = e.message
                    }
                }) { Text("지우기") }
            },
            dismissButton = { TextButton(onClick = { confirmForget = false }) { Text("취소") } },
        )
    }
    if (confirmNewKey) {
        AlertDialog(
            onDismissRequest = { confirmNewKey = false },
            properties = secureDialog,
            title = { Text("키 새로 만들기") },
            text = {
                Text(
                    "지금 키를 지우고 새 키를 만듭니다. 서버의 authorized_keys에서 이 휴대폰의 예전 줄을 지우고 새 줄을 " +
                        "넣어야 다시 연결됩니다. 휴대폰을 잃어버렸다면 이 버튼이 아니라 서버에서 그 줄을 지우세요.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmNewKey = false
                    AppState.work("키 만드는 중…", {
                        SyncKey.delete(context)
                        SyncKey.create(context)
                    }) { blob = it }
                }) { Text("새로 만들기") }
            },
            dismissButton = { TextButton(onClick = { confirmNewKey = false }) { Text("취소") } },
        )
    }
}
