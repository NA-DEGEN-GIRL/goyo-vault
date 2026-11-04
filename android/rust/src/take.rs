//! Another device's key change taken at unlock (spec §5.2 step 9(b), §7.15
//! at login; the PC's `adopt_from(Taking::Login)`): when the unlock's own
//! key file opened and the server's key record, as precheck snapshotted
//! it, is a plain successor of this device's key file (another device
//! added or removed a key, or changed the password), the vault screen
//! offers it with its gate: G1 (the other device's key code), G2 (the keys
//! picked as lost), none, or the trust of "열쇠 변경 자동 적용" where this
//! device turned it on. The take uses the unlock's own password and touch
//! (`reauth_from_unlock`), opens the server's file with the touched key,
//! previews it (which judges the gate against exactly that file) and
//! writes it with the lib's adopt engine. What the phone cannot ask yet
//! (a fork, a result without security keys, key-file sync turned on or
//! off, keys left suspended, both passwords changed) is left to a PC, as
//! before: nothing is written then.
use goyo_vault::{
    fido::Touch,
    vault::{
        self, Acks, AdoptCheck, AdoptClass, AdoptPlan, ForkOption, GateAnswer, GateKind, GatePass,
        PassInForce, Reauth, Session, Source, UnionPassword, UnlockProof, keyfile::KeyFile,
    },
};

/// What a take still needs from the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// No gate (or the trust of auto-apply): only [받기].
    Nothing,
    G1,
    G2,
}

pub struct Take {
    proof: Option<UnlockProof>,
    touch: Touch,
    file: KeyFile,
    check: AdoptCheck,
    trusted: bool,
    reauth: Option<Reauth>,
    plan: Option<AdoptPlan>,
}

/// The server's file has another password: the text that asks for it.
pub const NEWPASS_OTHER: &str =
    "받을 열쇠 파일은 다른 비밀번호로 잠겨 있습니다. 그 기기에서 바꾼 새 비밀번호를 입력하세요.";
const ON_PC: &str = "이 변경은 휴대폰에서 아직 받을 수 없습니다. PC의 고요 금고에서 먼저 받은 뒤, 휴대폰에서 다시 여세요(PC가 받으면 이 휴대폰은 다음 동기화 때 그 결과를 받습니다).";
const OTHER_KEY: &str = "받을 열쇠 파일은 지금 연 보안 키로 열 수 없습니다. 그 열쇠 파일에 등록된 다른 보안 키로 금고를 다시 연 뒤 받으세요.";

impl Take {
    /// The take the unlock offers, if any: the snapshot as this session's
    /// view shows it, a plain successor (no fork).
    pub fn offer(s: &Session, proof: UnlockProof, touch: Touch) -> Option<Self> {
        let (file, seq) = s.login_candidate(&proof)?;
        let check = s.adopt_check(&file, Source::Server { seq }).ok()?;
        if check.fork || check.class != AdoptClass::Successor {
            return None;
        }
        let trusted = s.trusts(&check);
        Some(Self {
            proof: Some(proof),
            touch,
            file,
            check,
            trusted,
            reauth: None,
            plan: None,
        })
    }
    pub fn need(&self) -> Need {
        match (self.check.keys.gate, self.trusted) {
            (None, _) | (Some(_), true) => Need::Nothing,
            (Some(GateKind::G1), false) => Need::G1,
            (Some(GateKind::G2), false) => Need::G2,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.check.other.epoch
    }
    /// The gate answered (`answer`, None where none is needed), the
    /// server's file opened (with `other_password` when the unlock's does
    /// not open it) and previewed. Ok(None): the other password is needed.
    /// Ok(Some): the lines that say what [받기] does.
    pub fn preview(
        &mut self,
        s: &mut Session,
        answer: Option<GateAnswer>,
        other_password: Option<&str>,
    ) -> Result<Option<Vec<String>>, &'static str> {
        self.plan = None;
        if self.reauth.is_none() {
            let proof = self.proof.take().ok_or(vault::GATE_NOT_PENDING)?;
            self.reauth = Some(s.reauth_from_unlock(proof, &self.touch)?);
        }
        let r = self.reauth.as_ref().ok_or(vault::GATE_NOT_PENDING)?;
        // The other file's key: the unlock's, when it opens that file too.
        let opener = if self.file.needs_security_key() {
            if !r.key().is_some_and(|n| s.opens_other(&self.file, n)) {
                return Err(OTHER_KEY);
            }
            if self.touch.second_missing() {
                return Err(OTHER_KEY);
            }
            Some(&self.touch)
        } else {
            None
        };
        let opened = match s.adopt_open_with(r, &self.file, other_password, opener) {
            Ok(opened) => opened,
            Err(e) if e == goyo_vault::crypto::AUTH_ERROR && other_password.is_none() => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let (epoch, tag) = (self.check.other.epoch, self.check.other.tag);
        let pass = match (self.need(), answer) {
            (Need::Nothing, _) if self.check.keys.gate.is_none() => GatePass::none(&self.check),
            (Need::Nothing, _) => GatePass::Trusted { epoch, tag },
            (Need::G1, Some(GateAnswer::Code(code))) => GatePass::G1Passed { code, epoch, tag },
            (Need::G2, Some(GateAnswer::Pick(pick))) => GatePass::G2Passed { pick, epoch, tag },
            _ => return Err("코드를 입력하거나 잃어버린 키를 고르세요."),
        };
        let plan =
            s.adopt_preview_with(r, &self.file, opened, &self.check, pass, ForkOption::Both)?;
        let p = plan.preview();
        if p.password_only
            || p.keysync_on
            || p.keysync_off.is_some()
            || p.both_passwords
            || !p.suspend.is_empty()
            || p.own_pass.is_some()
        {
            return Err(ON_PC);
        }
        let mut what = Vec::new();
        let c = &p.change;
        if !c.removed.is_empty() {
            what.push(format!("보안 키 {} 제거", listed(&c.removed)));
        }
        if !c.added.is_empty() {
            what.push(format!(
                "이 휴대폰에서 처음 보는 보안 키 {} 추가",
                listed(&c.added)
            ));
        }
        if c.password {
            what.push("비밀번호 변경됨".to_owned());
        }
        if c.other || what.is_empty() {
            what.push("열쇠 설정 변경".to_owned());
        }
        let mut lines = vec![
            "이 열쇠 파일은 이 휴대폰의 열쇠 파일에서 이어진 새 버전입니다. 그대로 받습니다."
                .to_owned(),
            format!("바뀌는 것: {}", what.join(", ")),
            format!("받은 뒤의 열쇠 파일: 수정 {}", p.epoch),
        ];
        if let Some(code) = &p.code {
            lines.push(format!("받은 뒤의 열쇠 확인 코드: {}", code.show(p.epoch)));
        }
        if other_password.is_some() {
            lines.push("앞으로는 받은 열쇠 파일의 비밀번호로 엽니다.".to_owned());
        }
        self.plan = Some(plan);
        Ok(Some(lines))
    }
    /// [받기]: the write. The lines to show and whether the app must lock
    /// now (S-GAP-CHANGED).
    pub fn accept(mut self, s: &mut Session) -> Result<(Vec<String>, bool), &'static str> {
        let plan = self.plan.take().ok_or(vault::GATE_NOT_PENDING)?;
        let r = self.reauth.take().ok_or(vault::GATE_NOT_PENDING)?;
        let acks = Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: false,
            fork_option: ForkOption::Both,
            keysync_on: false,
        };
        let adopted = s.adopt(r, plan, Vec::new(), acks, vault::Consent::default(), false)?;
        let mut lines = vec![format!(
            "다른 기기의 열쇠 변경을 받았습니다. 열쇠 확인 코드 {}",
            adopted.code.show(adopted.state.epoch)
        )];
        lines.push(
            match adopted.password {
                PassInForce::Own => "앞으로도 이 휴대폰의 비밀번호로 엽니다.",
                PassInForce::Other => "앞으로는 받은 열쇠 파일의 비밀번호로 엽니다.",
            }
            .to_owned(),
        );
        if adopted.vault_pending {
            lines.push(
                "금고 파일은 아직 새 열쇠로 저장하지 못했습니다. 다음 저장 때 다시 합니다."
                    .to_owned(),
            );
        }
        if adopted.gap_kept {
            lines.push("금고 파일 저장이 끊겨 잠급니다. 다시 열면 이어서 처리합니다.".to_owned());
        }
        Ok((lines, adopted.gap_kept))
    }
}

fn listed(numbers: &[u8]) -> String {
    numbers
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
