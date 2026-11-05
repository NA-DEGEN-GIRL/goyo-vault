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
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
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
val secureDialog = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)
val secretKeyboard = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)
val pinKeyboard = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, autoCorrectEnabled = false)

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
            AskDialog()
            val busy = AppState.busy
            if (busy != null) {
                Busy(activity, busy)
                return@Column
            }
            when (val s = AppState.screen) {
                Screen.Home -> Start(activity)
                Screen.Create -> CreateVault(activity)
                Screen.ServerImport -> ServerSetup(activity, importing = true)
                Screen.Settings -> ServerSetup(activity, importing = false)
                Screen.List -> EntryList(activity)
                is Screen.Detail -> Detail(s.index)
                is Screen.Edit -> Edit(s.index)
                Screen.Keys -> KeysScreen(activity)
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
        if (text.contains("YubiKey")) {
            Spacer(Modifier.height(8.dp))
            Text("NFC: 휴대폰 뒷면에 키를 댄 채 기다리세요. USB-C: 꽂은 뒤 키가 깜박이면 금속 부분을 만지세요.")
            Spacer(Modifier.height(24.dp))
            OutlinedButton(onClick = { activity.cancelKey() }) { Text("취소") }
        }
    }
}

/** The question a flow waits on ([Ask]), over every screen. */
@Composable
private fun AskDialog() {
    val q = Ask.current ?: return
    val field = rememberTextFieldState()
    DisposableEffect(q) { onDispose { field.clearText() } }
    AlertDialog(
        onDismissRequest = { q.answer.complete(null) },
        properties = secureDialog,
        title = { Text(q.title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(q.text)
                if (q.field != null) {
                    OutlinedSecureTextField(
                        state = field,
                        label = { Text(q.field) },
                        keyboardOptions = if (q.digits) pinKeyboard else secretKeyboard,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val typed = if (q.field != null) chars(field.text) else CharArray(0)
                field.clearText()
                if (q.field != null && typed.isEmpty()) return@TextButton
                q.answer.complete(typed)
            }) {
                Text(q.yes, color = if (q.danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
        },
        dismissButton = q.no?.let { no -> { TextButton(onClick = { q.answer.complete(null) }) { Text(no) } } },
    )
}

@Composable
private fun EntryList(activity: MainActivity) {
    BackHandler { activity.lockNow("잠갔습니다.") }
    val readOnly = AppState.readOnly()
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("금고 ${AppState.tag ?: ""}", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            if (!readOnly) TextButton(onClick = { AppState.screen = Screen.Edit(-1) }) { Text("+ 새 항목") }
            TextButton(onClick = { activity.lockNow("잠갔습니다.") }) { Text("잠금") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { AppState.screen = Screen.Keys }) { Text("열쇠 관리") }
            OutlinedButton(onClick = { AppState.screen = Screen.Settings }) { Text("동기화 설정") }
        }
        if (Sync.configured(context) || Sync.badge >= 0) SyncBadgeRow(context)
        if (Sync.offer) SyncOffer(context)
        val status = AppState.status
        when {
            status and Native.STATUS_FETCHED != 0 -> FetchedBanner(activity)
            status and Native.STATUS_TOFU != 0 -> TofuBanner()
            status and Native.STATUS_GATE_PENDING != 0 -> GateBanner(activity)
            status and Native.STATUS_TAKE != 0 -> TakeBanner(activity)
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
    // An OTP entry (0.12.1) has no 비밀정보: only its OTP and memo.
    val otpEntry = remember(index) {
        try {
            Native.otpEntry(AppState.session, index)
        } catch (e: GoyoException) {
            false
        }
    }
    val readOnly = AppState.readOnly()
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(fields[0], style = MaterialTheme.typography.titleLarge)
        if (fields[1].isNotEmpty()) Text(fields[1], style = MaterialTheme.typography.bodyMedium)
        if (otpEntry) {
            OtpSection(index, missing = "이 항목에는 OTP 시크릿이 없습니다.")
        } else {
            Text("비밀정보", style = MaterialTheme.typography.labelLarge)
            Text(if (shown) fields[2] else "•".repeat(12), style = MaterialTheme.typography.bodyLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    Clip.copySecret(context, fields[2])
                    AppState.message = "복사했습니다. 30초 뒤 클립보드에서 지웁니다."
                }) { Text("복사") }
                OutlinedButton(onClick = { shown = !shown }) { Text(if (shown) "숨기기" else "보기") }
            }
            OtpSection(index)
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
                        Sync.afterSave(context)
                    }
                }) { Text("삭제") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("취소") } },
        )
    }
}

/** The PC's kind presets (src/main.rs KIND_PRESETS; "OTP" is the OTP kind); any other text is kept as typed. */
private val KIND_PRESETS = listOf("비밀번호", "니모닉", "프라이빗키", "API 키", "OTP")

/** The kind: a drop-down of the PC's presets that also takes a typed kind. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun KindField(kind: TextFieldState) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            state = kind,
            label = { Text("종류") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            lineLimits = TextFieldLineLimits.SingleLine,
            modifier = Modifier.menuAnchor(ExposedDropdownMenuAnchorType.PrimaryEditable).fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            KIND_PRESETS.forEach { name ->
                DropdownMenuItem(
                    text = { Text(name) },
                    onClick = {
                        kind.setTextAndPlaceCursorAtEnd(name)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun Edit(index: Int) {
    val context = LocalContext.current
    BackHandler { AppState.screen = if (index < 0) Screen.List else Screen.Detail(index) }
    val title = rememberTextFieldState()
    // A new entry starts as 비밀번호, as on the PC.
    val kind = rememberTextFieldState(if (index < 0) KIND_PRESETS[0] else "")
    val secret = rememberTextFieldState()
    val notes = rememberTextFieldState()
    // The OTP field starts empty: an entry's secret never comes to the
    // editor. Empty keeps it; a new key or otpauth URI replaces it.
    val otp = rememberTextFieldState()
    var removeOtp by remember { mutableStateOf(false) }
    val otpNow = remember(index) {
        if (index < 0) {
            null
        } else {
            try {
                Native.otpInfo(AppState.session, index)
            } catch (e: GoyoException) {
                null
            }
        }
    }
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
        onDispose { listOf(title, kind, secret, notes, otp).forEach(TextFieldState::clearText) }
    }
    // The OTP kind (0.12.1): no 비밀정보 field; the OTP secret is the main,
    // required field (empty keeps the entry's own), as on the PC.
    val kindText = kind.text.toString()
    val otpKind = remember(kindText) {
        try {
            Native.isOtpKind(kindText)
        } catch (e: GoyoException) {
            false
        }
    }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(if (index < 0) "새 항목" else "항목 편집", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(state = title, label = { Text("이름") }, modifier = Modifier.fillMaxWidth())
        KindField(kind)
        if (otpKind) {
            OtpEditField(otpNow, otp, required = true, remove = null, onRemove = {})
            Text(
                "OTP 항목은 비밀정보 없이 OTP 시크릿만 저장합니다. 이 항목에 비밀정보가 있었다면 저장할 때 지워집니다.",
                style = MaterialTheme.typography.bodySmall,
            )
            NotesField(notes)
        } else {
            OutlinedSecureTextField(
                state = secret,
                label = { Text("비밀정보") },
                keyboardOptions = secretKeyboard,
                modifier = Modifier.fillMaxWidth(),
            )
            NotesField(notes)
            OtpEditField(otpNow, otp, required = false, remove = removeOtp, onRemove = { removeOtp = it })
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = {
                // An OTP entry keeps no 비밀정보: none is sent.
                val f = listOf(title, kind, secret, notes, otp).map {
                    if (otpKind && it === secret) ByteArray(0) else utf8(it.text)
                }
                val remove = removeOtp && !otpKind
                val session = AppState.session
                AppState.work("저장 중…", {
                    try {
                        Native.put(session, index, f[0], f[1], f[2], f[3], f[4], remove)
                    } finally {
                        f.forEach { it.fill(0) }
                    }
                }) {
                    AppState.reload()
                    AppState.screen = Screen.List
                    Sync.afterSave(context)
                }
            }) { Text("저장") }
            OutlinedButton(onClick = {
                AppState.screen = if (index < 0) Screen.List else Screen.Detail(index)
            }) { Text("취소") }
        }
    }
}

@Composable
private fun NotesField(notes: TextFieldState) {
    OutlinedTextField(
        state = notes,
        label = { Text("메모") },
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
}

/**
 * The editor's OTP field: what the entry has (never the secret itself), the
 * remove box for an optional one ([remove] null for the OTP kind, which needs
 * one), and the field (a Base32 key or an otpauth URI; empty keeps the
 * entry's own).
 */
@Composable
private fun OtpEditField(
    otpNow: Array<String>?,
    otp: TextFieldState,
    required: Boolean,
    remove: Boolean?,
    onRemove: (Boolean) -> Unit,
) {
    if (otpNow != null) {
        val names = listOf(otpNow[0], otpNow[1]).filter { it.isNotEmpty() }.joinToString(" · ")
        Text(if (names.isEmpty()) "OTP 시크릿: 있음" else "OTP 시크릿: 있음 ($names)")
        if (remove != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = remove, onCheckedChange = onRemove)
                Text("OTP 시크릿 지우기")
            }
        }
    }
    val label = when {
        otpNow != null -> "새 OTP 시크릿 (비우면 그대로) · 키 또는 otpauth 주소"
        required -> "OTP 시크릿 · 키 또는 otpauth 주소"
        else -> "OTP 시크릿 (선택) · 키 또는 otpauth 주소"
    }
    OutlinedSecureTextField(
        state = otp,
        label = { Text(label) },
        keyboardOptions = secretKeyboard,
        modifier = Modifier.fillMaxWidth(),
    )
}

/** The sync badge, as the PC app's pill: what the open vault and the last run say, and "지금 동기화". */
@Composable
fun SyncBadgeRow(context: android.content.Context) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        val color = if (Sync.warning()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary
        Text(
            "동기화: " + (if (Sync.running) "진행 중…" else Sync.label()),
            color = color,
            modifier = Modifier.weight(1f).clickable { AppState.screen = Screen.Settings },
        )
        TextButton(enabled = !Sync.running, onClick = { Sync.now(context) }) { Text("지금 동기화") }
    }
    if (Sync.warning() && Sync.text.isNotEmpty()) {
        Text(Sync.text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
}

/** The consent to turn sync on (the PC app's question at unlock). */
@Composable
private fun SyncOffer(context: android.content.Context) {
    AlertDialog(
        onDismissRequest = { Sync.offer = false },
        properties = secureDialog,
        title = { Text("이 금고를 동기화할까요?") },
        text = {
            Text(
                "암호화된 금고 파일만 내 서버와 Tailscale로 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다. " +
                    "금고 형식이 바뀌어 고요 금고 0.7 이하에서는 이 금고를 열 수 없게 됩니다. " +
                    "다른 기기에 따로 고친 사본이 있다면 먼저 PC에서 정리하세요.",
            )
        },
        confirmButton = { TextButton(onClick = { Sync.enable(context) }) { Text("예") } },
        dismissButton = { TextButton(onClick = { Sync.offer = false }) { Text("아니요") } },
    )
}

