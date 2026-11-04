package app.goyovault

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/** The start screen: what is on the phone decides it (as the PC's welcome or login). */
@Composable
fun Start(activity: MainActivity) {
    when (AppState.home) {
        Home.Welcome -> Welcome(activity)
        Home.Login -> Login(activity)
        Home.Fetched -> Fetched(activity)
        Home.NeedKey -> NeedKey(activity)
    }
}

/** No vault yet (the PC's welcome): 서버에서 가져오기 first, as the way a phone joins. */
@Composable
private fun Welcome(activity: MainActivity) {
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("고요 금고", style = MaterialTheme.typography.headlineMedium)
        Text("이 휴대폰에는 아직 금고가 없습니다.")
        Button(onClick = { AppState.screen = Screen.ServerImport }, modifier = Modifier.fillMaxWidth()) {
            Text("서버에서 가져오기")
        }
        Text(
            "권장. PC에서 쓰는 금고를 내 서버에서 Tailscale로 받아 옵니다(PC의 goyo-sync '이 PC로 가져오기'와 같음). " +
                "열쇠 파일 동기화를 켠 금고는 열쇠 파일도 함께 받고, 다른 PC의 열쇠 확인 코드로 확인합니다. PC에서는 한 번만 확인해 주면 됩니다.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(onClick = { AppState.screen = Screen.Create }, modifier = Modifier.fillMaxWidth()) {
            Text("새 금고 만들기")
        }
        OutlinedButton(onClick = { activity.startImport() }, modifier = Modifier.fillMaxWidth()) {
            Text("파일에서 가져오기")
        }
        Text(
            "PC의 금고 파일(.goyo)과 열쇠 파일(.goyokey)을 USB 케이블로 이 휴대폰에 옮긴 뒤 고릅니다. " +
                "두 파일은 이 앱만 읽을 수 있는 곳에 복사됩니다.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

/** Password and (for a key file with keys) the YubiKey PIN; zeroed when the screen goes. */
@Composable
private fun UnlockFields(activity: MainActivity, needsKey: Boolean, submit: String) {
    val password = rememberTextFieldState()
    val pin = rememberTextFieldState()
    DisposableEffect(Unit) {
        onDispose {
            password.clearText()
            pin.clearText()
        }
    }
    OutlinedSecureTextField(
        state = password,
        label = { Text("비밀번호") },
        keyboardOptions = secretKeyboard,
        modifier = Modifier.fillMaxWidth(),
    )
    if (needsKey) {
        OutlinedSecureTextField(
            state = pin,
            label = { Text("YubiKey PIN") },
            keyboardOptions = pinKeyboard,
            modifier = Modifier.fillMaxWidth(),
        )
    }
    Button(
        onClick = {
            val pw = utf8(password.text)
            val p = if (needsKey) chars(pin.text) else null
            password.clearText()
            pin.clearText()
            activity.unlock(pw, p)
        },
        modifier = Modifier.fillMaxWidth(),
    ) { Text(submit) }
}

/** A vault and its key file: the login ("금고 열기"), as on the PC. */
@Composable
private fun Login(activity: MainActivity) {
    val context = LocalContext.current
    val keys = AppState.loginKeys
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("금고 열기", style = MaterialTheme.typography.headlineSmall)
        Text("금고 ${AppState.tag ?: ""}")
        UnlockFields(activity, needsKey = keys != 0, submit = "잠금 해제")
        Text(
            when {
                keys > 0 -> "이 열쇠 파일은 보안 키가 필요합니다(등록 ${keys}개). '잠금 해제'를 누른 뒤 YubiKey를 휴대폰 뒷면에 대거나(NFC) USB-C에 꽂으세요. 보안 키 PIN은 위 칸에 입력합니다."
                keys == 0 -> "이 열쇠 파일은 보안 키 없이 비밀번호만으로 열립니다."
                else -> "열쇠 파일을 읽을 수 없습니다. 다시 가져오세요."
            },
            style = MaterialTheme.typography.bodySmall,
        )
        if (Sync.configured(context)) SyncBadgeRow(context)
        HorizontalDivider()
        OutlinedButton(onClick = { AppState.screen = Screen.Settings }, modifier = Modifier.fillMaxWidth()) {
            Text("동기화 설정 (Tailscale)")
        }
        RemoveVaultButton(activity)
    }
}

/**
 * "서버에서 가져온 금고" (the PC's `Screen::Fetched`, spec §2.29): the key
 * file is the server's, in the vault's sync folder, not saved on the
 * phone and not trusted before the other PC's code.
 */
@Composable
private fun Fetched(activity: MainActivity) {
    val needsKey = AppState.fetchedNeedsKey
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("서버에서 가져온 금고", style = MaterialTheme.typography.headlineSmall)
        Text("금고 ${AppState.tag ?: ""}")
        Text(
            "서버에서 이 금고와 그 열쇠 파일을 가져왔습니다. 열쇠 파일은 아직 이 휴대폰에 저장되지 않았고, 다른 PC의 코드로 확인하기 전에는 믿지 않습니다.\n" +
                (if (needsKey) "① 비밀번호와 YubiKey PIN을 입력하고 '다음'을 누른 뒤 YubiKey를 댑니다.\n" else "① 비밀번호를 입력하고 '다음'을 누릅니다.\n") +
                "② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다.\n" +
                "③ 열쇠 파일을 이 휴대폰에 저장합니다.",
        )
        UnlockFields(activity, needsKey = needsKey, submit = if (needsKey) "다음 · 보안 키 터치" else "다음")
        HorizontalDivider()
        OutlinedButton(onClick = { activity.startKeyImport() }, modifier = Modifier.fillMaxWidth()) {
            Text("열쇠 파일이 있으면 그것으로 열기 (파일에서 가져오기)")
        }
        RemoveVaultButton(activity)
    }
}

/** A vault without a key file (the server had none for it): the key file comes from the PC. */
@Composable
private fun NeedKey(activity: MainActivity) {
    val context = LocalContext.current
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("열쇠 파일이 필요합니다", style = MaterialTheme.typography.headlineSmall)
        Text("금고 ${AppState.tag ?: ""}")
        Text(
            "이 금고의 열쇠 파일이 이 휴대폰에 없습니다. 서버에 열쇠 파일이 없으면(열쇠 파일 동기화를 쓰지 않는 금고) " +
                "PC의 열쇠 파일(.goyokey)을 USB 케이블로 이 휴대폰에 옮긴 뒤 가져오세요. 메신저나 클라우드는 쓰지 마세요.",
        )
        Button(onClick = { activity.startKeyImport() }, modifier = Modifier.fillMaxWidth()) {
            Text("열쇠 파일 가져오기 (파일에서 가져오기)")
        }
        if (Sync.configured(context)) {
            OutlinedButton(onClick = { fetchKey(activity) }, modifier = Modifier.fillMaxWidth()) {
                Text("서버에서 열쇠 파일 받기")
            }
            Text(
                "PC에서 열쇠 파일 동기화를 켰고 'Android 기기 추가…'로 이 휴대폰 줄에 이 금고가 들어간 뒤에 누르세요.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        RemoveVaultButton(activity)
    }
}

private fun fetchKey(activity: MainActivity) {
    AppState.work("서버에서 열쇠 파일 받는 중…", { Server.fetchKey(activity) }) { word ->
        AppState.refreshHome(activity)
        AppState.message = Server.keyText(word)
    }
}

/** [이 휴대폰에서 지우기…]: the vault leaves the phone (after a yes); the welcome screen follows. */
@Composable
private fun RemoveVaultButton(activity: MainActivity) {
    var confirm by remember { mutableStateOf(false) }
    TextButton(onClick = { confirm = true }) { Text("이 휴대폰에서 금고 지우기…") }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            properties = secureDialog,
            title = { Text("이 휴대폰에서 금고 지우기") },
            text = {
                Text(
                    "이 휴대폰의 금고 파일과 열쇠 파일, 동기화 폴더를 지웁니다. PC와 서버의 파일은 그대로입니다. " +
                        "동기화하지 않은 이 휴대폰의 변경은 사라집니다. 그 뒤 서버나 파일에서 다시 가져오거나 새로 만들 수 있습니다.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    activity.removeVault()
                }) { Text("지우기", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("취소") } },
        )
    }
}

/**
 * "새 금고 만들기" (spec §9.1, §9.2): the password twice (the PC's policy:
 * 12 characters or more, no predictable pieces), "보안 키로도 잠그기" on
 * by default with the first key's PIN, then the registrations, the write
 * and the key backup (MainActivity.createVault).
 */
@Composable
fun CreateVault(activity: MainActivity) {
    BackHandler { AppState.screen = Screen.Home }
    val password = rememberTextFieldState()
    val confirm = rememberTextFieldState()
    val pin = rememberTextFieldState()
    var withKeys by rememberSaveable { mutableStateOf(true) }
    DisposableEffect(Unit) {
        onDispose {
            password.clearText()
            confirm.clearText()
            pin.clearText()
        }
    }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("새 금고 만들기", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            TextButton(onClick = { AppState.screen = Screen.Home }) { Text("‹ 뒤로") }
        }
        Text(
            "이 휴대폰에 새 금고 파일과 열쇠 파일을 만듭니다. PC에서 쓰려면 나중에 동기화를 켜거나 두 파일을 옮기세요.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedSecureTextField(
            state = password,
            label = { Text("비밀번호 · 12자 이상") },
            keyboardOptions = secretKeyboard,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedSecureTextField(
            state = confirm,
            label = { Text("비밀번호 확인") },
            keyboardOptions = secretKeyboard,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("보안 키로도 잠그기", modifier = Modifier.weight(1f))
            Switch(checked = withKeys, onCheckedChange = { withKeys = it })
        }
        if (withKeys) {
            Text(
                "열 때마다 등록한 YubiKey를 대고 키의 PIN을 입력합니다. 모두 잃으면 누구도 복구할 수 없으니 2개 이상, 지금 함께 등록하세요" +
                    "(함께 등록한 키끼리 짝을 맺습니다). 키마다 등록 1번, 확인 1번 터치합니다. PIN이 없는 키는 아래 PIN으로 정하며, 키마다 PIN을 다르게 정하세요.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedSecureTextField(
                state = pin,
                label = { Text("첫 YubiKey의 PIN") },
                keyboardOptions = pinKeyboard,
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            Text(
                "보안 키 없이 비밀번호와 열쇠 파일로 여는 금고를 만듭니다. 휴대폰에서는 금고 파일과 열쇠 파일이 같은 곳에 있으므로, 보안 키를 켜는 것을 권합니다.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Button(onClick = {
            val a = utf8(password.text)
            val b = utf8(confirm.text)
            val same = a.contentEquals(b)
            b.fill(0)
            if (!same) {
                a.fill(0)
                AppState.message = "비밀번호와 비밀번호 확인이 다릅니다."
                return@Button
            }
            val p = if (withKeys) chars(pin.text) else null
            if (withKeys && p!!.isEmpty()) {
                a.fill(0)
                AppState.message = "첫 YubiKey의 PIN을 입력하세요."
                return@Button
            }
            password.clearText()
            confirm.clearText()
            pin.clearText()
            activity.createVault(a, withKeys, p)
        }, modifier = Modifier.fillMaxWidth()) { Text("금고 만들기") }
    }
}
