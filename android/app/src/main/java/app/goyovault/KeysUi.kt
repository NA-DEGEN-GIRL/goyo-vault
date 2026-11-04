package app.goyovault

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private const val CODE_LABEL = "다른 PC의 열쇠 확인 코드 (예: E7 · 1A2B-3C4D-5E6F-7A8B)"

/**
 * "열쇠 관리" basics (spec §9.1): the security keys and their pairing, the
 * key code other devices type, [키 추가] (a YubiKey registered on the
 * phone), [열쇠 백업…]. Removal, pairing, re-seeding, keys on or off and a
 * password change stay on the PC for now.
 */
@Composable
fun KeysScreen(activity: MainActivity) {
    BackHandler { AppState.screen = Screen.List }
    val session = AppState.session
    val info = remember(AppState.keysVersion) {
        try {
            Native.keysInfo(session)
        } catch (e: GoyoException) {
            AppState.message = e.message
            null
        }
    }
    var adding by remember { mutableStateOf(false) }
    val readOnly = AppState.readOnly()
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("열쇠 관리", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            TextButton(onClick = { AppState.screen = Screen.List }) { Text("‹ 뒤로") }
        }
        if (info == null) return@Column
        Text(info[0], style = MaterialTheme.typography.titleMedium)
        val keyed = info.size > 4
        if (keyed) {
            info.drop(4).forEach { Text(it) }
            Text(info[3], style = MaterialTheme.typography.bodySmall)
        } else {
            Text(
                "보안 키 켜기는 PC의 고요 금고 '열쇠 관리'에서 하세요(휴대폰에서는 아직 안 됩니다).",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        HorizontalDivider()
        Text("열쇠 확인 코드", style = MaterialTheme.typography.titleMedium)
        if (info[1].isNotEmpty()) {
            SelectionContainer { Text(info[1], style = MaterialTheme.typography.titleLarge) }
            Text(
                "다른 기기에서 이 금고의 보안 키 추가나 설정 변경을 받을 때 이 코드를 입력합니다.",
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            Text("이 열쇠 파일을 확인하기 전에는 보여 주지 않습니다(목록 화면의 확인을 먼저 하세요).", style = MaterialTheme.typography.bodySmall)
        }
        HorizontalDivider()
        if (info[2] == "1") {
            Text(
                "이 열쇠 파일은 아직 '열쇠 백업'으로 백업하지 않았습니다. 열쇠 파일을 잃으면 보안 키와 비밀번호가 있어도 열 수 없습니다.",
                color = MaterialTheme.colorScheme.error,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (keyed) {
                Button(enabled = !readOnly, onClick = { adding = true }) { Text("키 추가") }
            }
            OutlinedButton(enabled = !readOnly, onClick = { activity.backupKey() }) { Text("열쇠 백업…") }
        }
        if (readOnly) {
            Text("목록 화면의 확인(코드 입력 등)을 끝낸 뒤에 할 수 있습니다.", style = MaterialTheme.typography.bodySmall)
        }
        Text(
            "보안 키 제거, 짝 맺기, 모든 키 새로 잠그기, 비밀번호 변경, 열쇠 파일 동기화 켜기·끄기는 PC의 고요 금고에서 하세요. " +
                "PC에서 바꾼 열쇠는 이 휴대폰이 다음에 열 때(열쇠 파일 동기화) 받을지 묻습니다.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
    if (adding) AddKeyDialog(activity) { adding = false }
}

/** [키 추가]: the current password, the PIN of a registered key, the new key's PIN. */
@Composable
private fun AddKeyDialog(activity: MainActivity, close: () -> Unit) {
    val password = rememberTextFieldState()
    val pin = rememberTextFieldState()
    val newPin = rememberTextFieldState()
    DisposableEffect(Unit) {
        onDispose {
            password.clearText()
            pin.clearText()
            newPin.clearText()
        }
    }
    AlertDialog(
        onDismissRequest = close,
        properties = secureDialog,
        title = { Text("키 추가") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "먼저 지금 등록된 YubiKey로 확인한 뒤, 새 YubiKey를 등록합니다(등록 1번, 확인 1번). " +
                        "새 키는 확인에 쓴 키와 짝을 맺습니다. 다른 키와는 PC에서 '짝 맺기'를 하세요.",
                )
                OutlinedSecureTextField(state = password, label = { Text("현재 비밀번호") }, keyboardOptions = secretKeyboard, modifier = Modifier.fillMaxWidth())
                OutlinedSecureTextField(state = pin, label = { Text("등록된 YubiKey의 PIN") }, keyboardOptions = pinKeyboard, modifier = Modifier.fillMaxWidth())
                OutlinedSecureTextField(
                    state = newPin,
                    label = { Text("새 YubiKey의 PIN (없는 키는 이 PIN으로 정함)") },
                    keyboardOptions = pinKeyboard,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val pw = utf8(password.text)
                val p = chars(pin.text)
                val n = chars(newPin.text)
                password.clearText()
                pin.clearText()
                newPin.clearText()
                close()
                if (p.isEmpty() || n.isEmpty()) {
                    pw.fill(0)
                    p.fill('\u0000')
                    n.fill('\u0000')
                    AppState.message = "두 PIN을 모두 입력하세요."
                    return@TextButton
                }
                activity.addKey(pw, p, n)
            }) { Text("다음") }
        },
        dismissButton = { TextButton(onClick = close) { Text("취소") } },
    )
}

/**
 * "서버에서 가져온 열쇠 파일 확인" (spec §7.17, §2.29): the other PC's code,
 * or the trust without one (S-TOFU-NOPC), then the key file is saved on
 * the phone; for a state this phone confirmed before, only the save.
 */
@Composable
fun FetchedBanner(activity: MainActivity) {
    val code = rememberTextFieldState()
    var noCode by remember { mutableStateOf(false) }
    val tofu = AppState.status and Native.STATUS_TOFU != 0
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("서버에서 가져온 열쇠 파일 확인", style = MaterialTheme.typography.titleMedium)
        if (tofu) {
            Text(
                "이 휴대폰은 이 열쇠 파일을 아직 확인하지 않았습니다. 다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요. " +
                    "확인하기 전에는 항목을 고치거나 서버에 올리지 않고, 열쇠 파일과 금고를 이 휴대폰에 저장하지도 않습니다.",
            )
            OutlinedTextField(state = code, label = { Text(CODE_LABEL) }, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    val typed = code.text.toString()
                    if (typed.isBlank()) {
                        AppState.message = "다른 PC의 열쇠 확인 코드를 입력하세요."
                        return@Button
                    }
                    activity.saveFetched(typed, "코드가 맞습니다. 이 열쇠 파일은 진짜입니다.")
                }) { Text("코드 확인") }
            }
            TextButton(onClick = { noCode = true }) { Text("코드 없이 받기 (이 서버를 믿음)…") }
        } else {
            Text("서버에서 받은 이 열쇠 파일은 이 휴대폰이 이미 확인했습니다. 남은 일은 이 휴대폰에 저장하는 것뿐입니다. '저장하기'를 누르세요.")
            Button(onClick = { activity.saveFetched(null, "이 휴대폰이 이미 확인한 열쇠 파일입니다.") }) { Text("저장하기") }
        }
    }
    if (noCode) {
        AlertDialog(
            onDismissRequest = { noCode = false },
            properties = secureDialog,
            title = { Text("코드 없이 받기") },
            text = {
                Text(
                    "확인할 다른 PC가 없으면 이 열쇠 파일이 진짜인지 확인할 방법이 없습니다.\n" +
                        "잃어버린 보안 키와 그 PIN, 비밀번호를 가진 사람이 서버를 장악했다면 위조된 열쇠 파일일 수 있습니다" +
                        "(보안 키를 뺄 때 비밀번호도 바꿨다면 위조 파일은 새 비밀번호로 열리지 않습니다). 그래도 이 열쇠 파일을 믿고 쓸까요?",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    noCode = false
                    activity.saveFetched(null, "코드 없이 이 서버를 믿기로 했습니다. 이 열쇠 파일이 진짜인지는 확인하지 않았습니다.")
                }) { Text("믿고 받기", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { noCode = false }) { Text("아니요") } },
        )
    }
}

/** S-TOFU: the key file's state is new to this phone; the PC's key code confirms it. */
@Composable
fun TofuBanner() {
    val code = rememberTextFieldState()
    var noCode by remember { mutableStateOf(false) }
    if (noCode) {
        AlertDialog(
            onDismissRequest = { noCode = false },
            properties = secureDialog,
            title = { Text("코드 없이 믿기") },
            text = {
                Text(
                    "확인할 PC가 없으면 이 열쇠 파일이 진짜인지 확인할 방법이 없습니다. " +
                        "잃어버린 보안 키와 그 PIN, 비밀번호를 가진 사람이 만든 위조 파일일 수 있습니다. " +
                        "PC에서 직접 옮겨 온 파일이 맞을 때만 믿으세요. 그래도 이 열쇠 파일을 믿고 쓸까요?",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    noCode = false
                    val session = AppState.session
                    AppState.work("확인 중…", { Native.tofuConfirm(session, null) }) {
                        AppState.reload()
                        AppState.message = "이 휴대폰에서 열쇠 파일을 믿기로 했습니다."
                    }
                }) { Text("믿고 쓰기", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { noCode = false }) { Text("아니요") } },
        )
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("이 열쇠 파일 확인", style = MaterialTheme.typography.titleMedium)
        Text("이 휴대폰에서 처음 연 금고라 지금은 읽기만 됩니다. 고칠 수 있게 하려면 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드(E… · XXXX-XXXX-XXXX-XXXX)를 입력하세요.")
        OutlinedTextField(state = code, label = { Text(CODE_LABEL) }, modifier = Modifier.fillMaxWidth())
        Button(onClick = {
            val typed = code.text.toString()
            val session = AppState.session
            AppState.work("확인 중…", { Native.tofuConfirm(session, typed) }) {
                code.clearText()
                AppState.reload()
                AppState.message = "이 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다."
            }
        }) { Text("코드 확인") }
        TextButton(onClick = { noCode = true }) { Text("코드 없이 이 열쇠 파일 믿기…") }
    }
}

/** The gate's answer: G1 a code field, G2 this device's keys to pick. */
@Composable
private fun GateAnswer(info: Array<String>, ok: String, answer: (String?, IntArray?) -> Unit) {
    val code = rememberTextFieldState()
    val picked = remember(info.contentHashCode()) { mutableStateListOf<Int>() }
    if (info[0] == "G2") {
        Text(
            "다른 기기에서 보안 키가 제거되었습니다. 이 휴대폰에서 고르기 전에는 무엇이 바뀌었는지 보여 주지 않습니다.\n" +
                "잃어버렸거나 뺀 키를 모두 고르세요.",
        )
        info.drop(2).forEach { row ->
            val f = row.split('|')
            val n = f[0].toIntOrNull() ?: return@forEach
            val label = "보안 키 $n · ${f.getOrElse(1) { "" }} 등록" + if (f.getOrNull(2) == "1") " · 이번에 연 키" else ""
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = n in picked, onCheckedChange = { if (it) picked.add(n) else picked.remove(n) })
                Text(label)
            }
        }
        Button(onClick = {
            if (picked.isEmpty()) {
                AppState.message = "잃어버렸거나 뺀 키를 하나 이상 고르세요."
                return@Button
            }
            answer(null, picked.toIntArray())
        }) { Text(ok) }
    } else {
        Text(
            "다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요(E${info[1]} · XXXX-XXXX-XXXX-XXXX).\n" +
                "이 휴대폰에서는 코드를 입력하기 전에 무엇이 바뀌었는지 보여 주지 않습니다.",
        )
        OutlinedTextField(state = code, label = { Text(CODE_LABEL) }, modifier = Modifier.fillMaxWidth())
        Button(onClick = {
            val typed = code.text.toString()
            if (typed.isBlank()) {
                AppState.message = "다른 PC의 열쇠 확인 코드를 입력하세요."
                return@Button
            }
            answer(typed, null)
        }) { Text(ok) }
    }
}

/**
 * Gate-pending mode (spec §5.2): the key file on the phone changed (a key
 * change of another device it took before) and waits for its gate: G2
 * (the keys picked as lost) while allowed, else G1 (the other PC's code).
 */
@Composable
fun GateBanner(activity: MainActivity) {
    val session = AppState.session
    val info = remember(AppState.keysVersion) {
        try {
            Native.gateInfo(session)
        } catch (e: GoyoException) {
            null
        }
    } ?: return
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("바뀐 열쇠 파일 확인", style = MaterialTheme.typography.titleMedium)
        Text(
            "이 휴대폰의 열쇠 파일이 바뀌었습니다. 확인하기 전에는 항목을 고치거나 저장하거나 올리지 않습니다.",
            style = MaterialTheme.typography.bodySmall,
        )
        GateAnswer(info, "확인") { code, picks -> activity.passGate(code, picks) }
    }
}

/**
 * Another device's key change on the server, taken with this unlock's
 * touch (spec §7.15 at login): its gate, then the preview and [받기];
 * [나중에] leaves it for the next unlock.
 */
@Composable
fun TakeBanner(activity: MainActivity) {
    val session = AppState.session
    val info = remember(AppState.keysVersion) {
        try {
            Native.takeInfo(session)
        } catch (e: GoyoException) {
            null
        }
    } ?: return
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("다른 기기의 열쇠 변경", style = MaterialTheme.typography.titleMedium)
        Text(
            "다른 기기에서 바꾼 새 열쇠 파일(수정 ${info[1]})이 서버에 있습니다. 받아야 그 기기와 다시 동기화됩니다. " +
                "그런 변경을 한 적이 없다면 받지 마세요(서버 사본이 위조되었을 수 있습니다).",
        )
        if (info[0] == "none") {
            Button(onClick = { activity.takeChange(null, null) }) { Text("받기…") }
        } else {
            GateAnswer(info, "다음") { code, picks -> activity.takeChange(code, picks) }
        }
        TextButton(onClick = { activity.dropTake() }) { Text("나중에") }
    }
}
