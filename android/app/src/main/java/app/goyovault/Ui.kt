package app.goyovault

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy

/** Dialogs are windows of their own: FLAG_SECURE on them too. */
private val secureDialog = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)
private val secretKeyboard = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)

@Composable
fun GoyoUi(activity: MainActivity) {
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(Modifier.safeDrawingPadding().imePadding().padding(16.dp)) {
            val fatal = AppState.fatal
            if (fatal != null) {
                Text("고요 금고를 시작할 수 없습니다", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(12.dp))
                Text(fatal)
                return@Column
            }
            AppState.message?.let {
                Text(it, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(bottom = 8.dp))
            }
            val busy = AppState.busy
            if (busy != null) {
                Busy(activity, busy)
                return@Column
            }
            when (val s = AppState.screen) {
                Screen.Home -> Home(activity)
                Screen.Unlock -> Unlock(activity)
                Screen.List -> EntryList(activity)
                is Screen.Detail -> Detail(s.index)
                is Screen.Edit -> Edit(s.index)
            }
        }
    }
}

@Composable
private fun Busy(activity: MainActivity, text: String) {
    Column(Modifier.fillMaxWidth().padding(top = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Spacer(Modifier.height(24.dp))
        Text(text, style = MaterialTheme.typography.titleMedium)
        if (text.startsWith("YubiKey")) {
            Spacer(Modifier.height(8.dp))
            Text("NFC: 휴대폰 뒷면에 키를 댄 채 기다리세요. USB-C: 꽂은 뒤 키가 깜박이면 금속 부분을 만지세요.")
            Spacer(Modifier.height(24.dp))
            OutlinedButton(onClick = { activity.cancelKey() }) { Text("취소") }
        }
    }
}

@Composable
private fun Home(activity: MainActivity) {
    val context = LocalContext.current
    var confirmRemove by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("고요 금고", style = MaterialTheme.typography.headlineMedium)
        val tag = AppState.tag
        if (tag != null && VaultFiles.present(context)) {
            Text("가져온 금고: $tag")
            Button(
                onClick = {
                    activity.checkNeedsKey {
                        AppState.needsKey = it
                        AppState.screen = Screen.Unlock
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("금고 열기")
            }
            OutlinedButton(onClick = { activity.startImport() }, modifier = Modifier.fillMaxWidth()) {
                Text("다른 금고 가져오기 (지금 것을 바꿉니다)")
            }
            TextButton(onClick = { confirmRemove = true }) { Text("가져온 파일 지우기") }
        } else {
            Text("PC에서 만든 금고 파일(.goyo)과 열쇠 파일(.goyokey)을 이 휴대폰으로 옮긴 뒤 가져오세요. 두 파일은 이 앱만 읽을 수 있는 곳에 복사됩니다.")
            Button(onClick = { activity.startImport() }, modifier = Modifier.fillMaxWidth()) {
                Text("금고 가져오기")
            }
        }
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            properties = secureDialog,
            title = { Text("가져온 파일 지우기") },
            text = { Text("이 휴대폰에 복사한 금고 파일과 열쇠 파일을 지웁니다. PC의 파일은 그대로입니다.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = false
                    activity.removeImported()
                }) { Text("지우기") }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("취소") } },
        )
    }
}

@Composable
private fun Unlock(activity: MainActivity) {
    val password = rememberTextFieldState()
    val pin = rememberTextFieldState()
    val needsKey = AppState.needsKey
    // The typed text never outlives the screen.
    DisposableEffect(Unit) {
        onDispose {
            password.clearText()
            pin.clearText()
        }
    }
    BackHandler { AppState.screen = Screen.Home }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("금고 열기 (${AppState.tag ?: ""})", style = MaterialTheme.typography.titleLarge)
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
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            Text("이 금고는 보안 키가 필요합니다. [열기]를 누른 뒤 YubiKey를 휴대폰 뒷면에 대거나(NFC) USB-C에 꽂으세요.")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    val pw = utf8(password.text)
                    val p = if (needsKey) chars(pin.text) else null
                    password.clearText()
                    pin.clearText()
                    activity.unlock(pw, p)
                },
            ) { Text("열기") }
            OutlinedButton(onClick = { AppState.screen = Screen.Home }) { Text("뒤로") }
        }
    }
}

@Composable
private fun EntryList(activity: MainActivity) {
    BackHandler { activity.lockNow("잠갔습니다.") }
    val readOnly = AppState.status != 0
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("금고 ${AppState.tag ?: ""}", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            if (!readOnly) TextButton(onClick = { AppState.screen = Screen.Edit(-1) }) { Text("추가") }
            TextButton(onClick = { activity.lockNow("잠갔습니다.") }) { Text("잠그기") }
        }
        if (AppState.status and Native.STATUS_TOFU != 0) Tofu()
        if (AppState.status and Native.STATUS_GATE_PENDING != 0) {
            Text("다른 기기에서 바뀐 열쇠 파일입니다. PC에서 먼저 확인한 뒤 다시 가져오세요. 지금은 읽기만 됩니다.")
        }
        HorizontalDivider()
        if (AppState.rows.isEmpty()) Text("항목이 없습니다.")
        LazyColumn {
            itemsIndexed(AppState.rows) { i, row ->
                Column(
                    Modifier.fillMaxWidth().clickable { AppState.screen = Screen.Detail(i) }.padding(vertical = 12.dp),
                ) {
                    Text(row.title, style = MaterialTheme.typography.titleMedium)
                    if (row.kind.isNotEmpty()) Text(row.kind, style = MaterialTheme.typography.bodySmall)
                }
                HorizontalDivider()
            }
        }
    }
}

/** S-TOFU: the key file's state is new to this device; the PC's key code confirms it. */
@Composable
private fun Tofu() {
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
                        AppState.message = "이 기기에서 열쇠 파일을 믿기로 했습니다."
                    }
                }) { Text("믿고 쓰기") }
            },
            dismissButton = { TextButton(onClick = { noCode = false }) { Text("아니요") } },
        )
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("이 기기에서 처음 연 금고라 지금은 읽기만 됩니다. 고칠 수 있게 하려면 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드(E… · XXXX-XXXX-XXXX-XXXX)를 입력하세요.")
        OutlinedTextField(state = code, label = { Text("열쇠 확인 코드") }, modifier = Modifier.fillMaxWidth())
        Button(onClick = {
            val typed = code.text.toString()
            val session = AppState.session
            AppState.work("확인 중…", { Native.tofuConfirm(session, typed) }) {
                code.clearText()
                AppState.reload()
                AppState.message = "이 기기에서 열쇠 파일을 확인했습니다."
            }
        }) { Text("확인") }
        TextButton(onClick = { noCode = true }) { Text("코드 없이 이 열쇠 파일 믿기…") }
    }
}

/** The fields of one entry, read from Rust while the screen shows them. */
private fun readField(index: Int, which: Int): String {
    val bytes = Native.field(AppState.session, index, which)
    try {
        return String(bytes, Charsets.UTF_8)
    } finally {
        bytes.fill(0)
    }
}

@Composable
private fun Detail(index: Int) {
    val context = LocalContext.current
    BackHandler { AppState.screen = Screen.List }
    var shown by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    val fields = remember(index) {
        try {
            List(4) { readField(index, it) }
        } catch (e: GoyoException) {
            AppState.message = e.message
            null
        }
    }
    if (fields == null) {
        LaunchedEffect(Unit) { AppState.screen = Screen.List }
        return
    }
    val readOnly = AppState.status != 0
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(fields[0], style = MaterialTheme.typography.titleLarge)
        if (fields[1].isNotEmpty()) Text(fields[1], style = MaterialTheme.typography.bodyMedium)
        Text("비밀정보", style = MaterialTheme.typography.labelLarge)
        Text(if (shown) fields[2] else "•".repeat(12), style = MaterialTheme.typography.bodyLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                Clip.copySecret(context, fields[2])
                AppState.message = "복사했습니다. 30초 뒤 클립보드에서 지웁니다."
            }) { Text("복사") }
            OutlinedButton(onClick = { shown = !shown }) { Text(if (shown) "숨기기" else "보기") }
        }
        if (fields[3].isNotEmpty()) {
            Text("메모", style = MaterialTheme.typography.labelLarge)
            Text(fields[3])
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!readOnly) {
                OutlinedButton(onClick = { AppState.screen = Screen.Edit(index) }) { Text("편집") }
                OutlinedButton(onClick = { confirmDelete = true }) { Text("삭제") }
            }
            TextButton(onClick = { AppState.screen = Screen.List }) { Text("목록") }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            properties = secureDialog,
            title = { Text("항목 삭제") },
            text = { Text("'${fields[0]}' 항목을 지울까요?") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    val session = AppState.session
                    AppState.work("저장 중…", { Native.delete(session, index) }) {
                        AppState.reload()
                        AppState.screen = Screen.List
                    }
                }) { Text("삭제") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("취소") } },
        )
    }
}

@Composable
private fun Edit(index: Int) {
    BackHandler { AppState.screen = if (index < 0) Screen.List else Screen.Detail(index) }
    val title = rememberTextFieldState()
    val kind = rememberTextFieldState()
    val secret = rememberTextFieldState()
    val notes = rememberTextFieldState()
    LaunchedEffect(index) {
        if (index >= 0) {
            try {
                listOf(title, kind, secret, notes).forEachIndexed { which, state ->
                    state.setTextAndPlaceCursorAtEnd(readField(index, which))
                }
            } catch (e: GoyoException) {
                AppState.message = e.message
                AppState.screen = Screen.List
            }
        }
    }
    DisposableEffect(Unit) {
        onDispose { listOf(title, kind, secret, notes).forEach(TextFieldState::clearText) }
    }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(if (index < 0) "새 항목" else "항목 편집", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(state = title, label = { Text("이름") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(state = kind, label = { Text("종류") }, modifier = Modifier.fillMaxWidth())
        OutlinedSecureTextField(
            state = secret,
            label = { Text("비밀정보") },
            keyboardOptions = secretKeyboard,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            state = notes,
            label = { Text("메모") },
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = {
                val f = listOf(title, kind, secret, notes).map { utf8(it.text) }
                val session = AppState.session
                AppState.work("저장 중…", {
                    try {
                        Native.put(session, index, f[0], f[1], f[2], f[3])
                    } finally {
                        f.forEach { it.fill(0) }
                    }
                }) {
                    AppState.reload()
                    AppState.screen = Screen.List
                }
            }) { Text("저장") }
            OutlinedButton(onClick = {
                AppState.screen = if (index < 0) Screen.List else Screen.Detail(index)
            }) { Text("취소") }
        }
    }
}
