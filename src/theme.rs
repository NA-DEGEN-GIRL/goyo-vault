//! Minimal monochrome theme: shared GDI resources and owner-drawn controls.
//! Everything here is reachable without borrowing `APP`, so child controls
//! keep their look while the app state is busy (Argon2, modal dialogs).
use crate::win::*;
use std::cell::Cell;
use zeroize::Zeroizing;

pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}
#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: u32,
    pub surface: u32,
    /// Active segment of a segmented control.
    pub raised: u32,
    pub border: u32,
    pub focus: u32,
    pub text: u32,
    pub muted: u32,
    pub faint: u32,
    pub pressed: u32,
    pub track: u32,
    /// Switch knob while off.
    pub knob: u32,
    pub danger: u32,
    pub unlocked: u32,
    /// Recommended option (e.g. turning on the OTP); text on it uses `bg`.
    pub accent: u32,
    pub accent_pressed: u32,
}
pub const LIGHT: Palette = Palette {
    bg: rgb(255, 255, 255),
    surface: rgb(244, 244, 245),
    raised: rgb(255, 255, 255),
    border: rgb(228, 228, 231),
    focus: rgb(82, 82, 91),
    text: rgb(24, 24, 27),
    muted: rgb(113, 113, 122),
    faint: rgb(161, 161, 170),
    pressed: rgb(63, 63, 70),
    track: rgb(212, 212, 216),
    knob: rgb(255, 255, 255),
    danger: rgb(185, 28, 28),
    unlocked: rgb(22, 163, 74),
    accent: rgb(21, 128, 61),
    accent_pressed: rgb(22, 101, 52),
};
pub const DARK: Palette = Palette {
    bg: rgb(18, 18, 20),
    surface: rgb(31, 31, 35),
    raised: rgb(58, 58, 64),
    border: rgb(48, 48, 54),
    focus: rgb(161, 161, 170),
    text: rgb(244, 244, 245),
    muted: rgb(161, 161, 170),
    faint: rgb(99, 99, 107),
    pressed: rgb(212, 212, 216),
    track: rgb(63, 63, 70),
    knob: rgb(212, 212, 216),
    danger: rgb(248, 113, 113),
    unlocked: rgb(74, 222, 128),
    accent: rgb(74, 222, 128),
    accent_pressed: rgb(34, 197, 94),
};

// Owner-drawn button variants, stored in the button's GWLP_USERDATA.
pub const PRIMARY: isize = 1;
pub const SECONDARY: isize = 2;
pub const GHOST: isize = 3;
pub const DANGER_GHOST: isize = 4;
pub const TAB: isize = 5;
pub const TAB_ON: isize = 6;
pub const TOGGLE: isize = 7;
pub const TOGGLE_ON: isize = 8;
pub const CHIP: isize = 9;
/// Quiet text-only action for secondary navigation.
pub const LINK: isize = 10;
/// Password reveal toggle: eye while masked, struck-through eye while shown.
pub const EYE: isize = 11;
pub const EYE_ON: isize = 12;
/// Filled green button for the recommended choice.
pub const ACCENT: isize = 13;
// Static label tones, stored the same way.
pub const TONE_TEXT: isize = 0;
pub const TONE_MUTED: isize = 1;
pub const TONE_DANGER: isize = 2;

pub const DT_CENTER: u32 = 0x1;
pub const DT_RIGHT: u32 = 0x2;
pub const DT_VCENTER: u32 = 0x4;
pub const DT_WORDBREAK: u32 = 0x10;
pub const DT_SINGLELINE: u32 = 0x20;
pub const DT_NOPREFIX: u32 = 0x800;
pub const DT_EDITCONTROL: u32 = 0x2000;
pub const DT_END_ELLIPSIS: u32 = 0x8000;
pub const LINE: u32 = DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;

pub struct Theme {
    pub scale: f32,
    /// Body, strong, small and title text: 맑은 고딕 for Korean, Segoe UI for
    /// English (Malgun Gothic draws a backslash as ₩). Hangul in English
    /// mode, such as entry names, falls back through Windows font linking.
    faces: [[isize; 4]; 2],
    pub code: isize,
    /// Segoe Fluent Icons glyphs (Windows 11 system font).
    pub icon: isize,
    /// The same icon font at control size.
    pub glyph: isize,
    dark: Cell<bool>,
    background: Cell<isize>,
}
impl Theme {
    fn new() -> Self {
        let scale = unsafe { GetDpiForSystem() } as f32 / 96.0;
        let font = |size: f32, weight: i32, face: &str| unsafe {
            CreateFontW(
                -(size * scale) as i32,
                0,
                0,
                0,
                weight,
                0,
                0,
                0,
                1,
                0,
                0,
                5,
                0,
                wide(face).as_ptr(),
            )
        };
        Self {
            scale,
            faces: ["맑은 고딕", "Segoe UI"].map(|face| {
                [
                    font(16.0, 400, face),
                    font(16.0, 700, face),
                    font(13.0, 400, face),
                    font(22.0, 700, face),
                ]
            }),
            code: font(22.0, 400, "Consolas"),
            icon: font(28.0, 400, "Segoe Fluent Icons"),
            glyph: font(16.0, 400, "Segoe Fluent Icons"),
            dark: Cell::new(true),
            background: Cell::new(unsafe { CreateSolidBrush(DARK.bg) }),
        }
    }
    fn face(&self, i: usize) -> isize {
        self.faces[crate::i18n::english() as usize][i]
    }
    pub fn body(&self) -> isize {
        self.face(0)
    }
    pub fn strong(&self) -> isize {
        self.face(1)
    }
    pub fn small(&self) -> isize {
        self.face(2)
    }
    pub fn title(&self) -> isize {
        self.face(3)
    }
    pub fn px(&self, n: i32) -> i32 {
        (n as f32 * self.scale) as i32
    }
    pub fn palette(&self) -> Palette {
        if self.dark.get() { DARK } else { LIGHT }
    }
}
impl Drop for Theme {
    fn drop(&mut self) {
        unsafe {
            for h in self.faces.into_iter().flatten().chain([
                self.code,
                self.icon,
                self.glyph,
                self.background.get(),
            ]) {
                DeleteObject(h);
            }
        }
    }
}
thread_local! {
    static THEME: Theme = Theme::new();
}
/// `None` only while thread-local storage is being torn down.
pub fn with<R>(f: impl FnOnce(&Theme) -> R) -> Option<R> {
    THEME.try_with(f).ok()
}
/// Current colours; dark is the default.
pub fn palette() -> Palette {
    with(Theme::palette).unwrap_or(DARK)
}
pub fn is_dark() -> bool {
    with(|t| t.dark.get()).unwrap_or(true)
}
/// Switches the palette. Callers repaint; the old brush is released here,
/// after the replacement exists, so WM_CTLCOLOR never returns a dead brush.
pub fn set_dark(dark: bool) {
    with(|t| unsafe {
        if t.dark.get() == dark {
            return;
        }
        t.dark.set(dark);
        let old = t
            .background
            .replace(CreateSolidBrush(if dark { DARK.bg } else { LIGHT.bg }));
        DeleteObject(old);
    });
}

pub unsafe fn fill(dc: isize, r: &Rect, color: u32) {
    unsafe {
        let brush = CreateSolidBrush(color);
        FillRect(dc, r, brush);
        DeleteObject(brush);
    }
}
/// Rounded rectangle; `fill: None` draws only the outline.
pub unsafe fn round(dc: isize, r: &Rect, radius: i32, fill: Option<u32>, border: Option<u32>) {
    unsafe {
        let brush = fill.map_or(0, |c| CreateSolidBrush(c));
        let pen = CreatePen(0, 1, border.or(fill).unwrap_or(palette().bg));
        let old_brush = SelectObject(dc, if brush != 0 { brush } else { GetStockObject(5) });
        let old_pen = SelectObject(dc, pen);
        RoundRect(dc, r.left, r.top, r.right, r.bottom, radius * 2, radius * 2);
        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        DeleteObject(pen);
        if brush != 0 {
            DeleteObject(brush);
        }
    }
}
#[cfg(test)]
thread_local! {
    /// Everything painted with text(), for the language tests.
    pub static PAINTED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
pub unsafe fn text(dc: isize, s: &str, r: &Rect, font: isize, color: u32, flags: u32) {
    #[cfg(test)]
    PAINTED.with(|p| p.borrow_mut().push(s.to_owned()));
    let w = secret_wide(s);
    let mut r = *r;
    unsafe {
        let old = SelectObject(dc, font);
        SetBkMode(dc, 1);
        SetTextColor(dc, color);
        DrawTextW(dc, w.as_ptr(), w.len() as i32 - 1, &mut r, flags);
        SelectObject(dc, old);
    }
}
pub unsafe fn text_width(dc: isize, s: &str, font: isize) -> i32 {
    let w = secret_wide(s);
    let mut size = Size::default();
    unsafe {
        let old = SelectObject(dc, font);
        GetTextExtentPoint32W(dc, w.as_ptr(), w.len() as i32 - 1, &mut size);
        SelectObject(dc, old);
    }
    size.cx
}
pub fn inset(r: &Rect, dx: i32, dy: i32) -> Rect {
    Rect {
        left: r.left + dx,
        top: r.top + dy,
        right: r.right - dx,
        bottom: r.bottom - dy,
    }
}

/// WM_CTLCOLOR* handler. Returns the background brush to use.
pub unsafe fn control_color(message: u32, dc: isize, control: Hwnd) -> Option<isize> {
    with(|t| unsafe {
        let tone = if message == 0x138 {
            GetWindowLongPtrW(control, -21)
        } else {
            TONE_TEXT
        };
        let p = t.palette();
        SetTextColor(
            dc,
            match tone {
                TONE_MUTED => p.muted,
                TONE_DANGER => p.danger,
                _ => p.text,
            },
        );
        SetBkColor(dc, p.bg);
        t.background.get()
    })
}

/// WM_DRAWITEM handler for owner-drawn buttons and list rows.
pub unsafe fn draw_item(item: &DrawItem) -> bool {
    with(|t| unsafe {
        match item.ctl_type {
            4 => draw_button(t, item),
            2 => draw_row(t, item),
            _ => return false,
        }
        true
    })
    .unwrap_or(false)
}

unsafe fn draw_button(t: &Theme, d: &DrawItem) {
    unsafe {
        let p = t.palette();
        let variant = GetWindowLongPtrW(d.item, -21);
        let pressed = d.state & 1 != 0;
        let disabled = d.state & 4 != 0;
        // ODS_FOCUS without ODS_NOFOCUSRECT: keyboard focus only.
        let focus = d.state & 0x10 != 0 && d.state & 0x200 == 0;
        let r = d.rect;
        let radius = t.px(8);
        let n = GetWindowTextLengthW(d.item).clamp(0, 256) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(d.item, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
        // Icon buttons keep a readable window text; the glyph is drawn instead.
        let label = match variant {
            EYE => "\u{E890}".to_owned(),    // Segoe Fluent Icons "View"
            EYE_ON => "\u{ED1A}".to_owned(), // "Hide"
            _ => String::from_utf16_lossy(&buf[..got]),
        };
        let on_surface = matches!(variant, TAB | TAB_ON);
        fill(d.dc, &r, if on_surface { p.surface } else { p.bg });
        let mut flags = DT_CENTER | LINE;
        let mut text_rect = r;
        let (color, font) = match variant {
            PRIMARY => {
                let c = if disabled {
                    p.track
                } else if pressed {
                    p.pressed
                } else {
                    p.text
                };
                round(d.dc, &r, radius, Some(c), None);
                (p.bg, t.strong())
            }
            ACCENT => {
                let c = if disabled {
                    p.track
                } else if pressed {
                    p.accent_pressed
                } else {
                    p.accent
                };
                round(d.dc, &r, radius, Some(c), None);
                (p.bg, t.strong())
            }
            SECONDARY => {
                round(
                    d.dc,
                    &r,
                    radius,
                    Some(if pressed { p.surface } else { p.bg }),
                    Some(p.border),
                );
                (if disabled { p.faint } else { p.text }, t.body())
            }
            GHOST | DANGER_GHOST => {
                if pressed {
                    round(d.dc, &r, radius, Some(p.surface), None);
                }
                let c = if disabled {
                    p.faint
                } else if variant == DANGER_GHOST {
                    p.danger
                } else {
                    p.text
                };
                (c, t.body())
            }
            TAB_ON => {
                round(d.dc, &r, radius, Some(p.raised), Some(p.border));
                (p.text, t.strong())
            }
            TAB => {
                if pressed {
                    round(d.dc, &r, radius, Some(p.border), None);
                }
                (p.muted, t.body())
            }
            LINK => (if pressed { p.text } else { p.muted }, t.small()),
            EYE | EYE_ON => {
                if pressed {
                    round(d.dc, &r, radius, Some(p.surface), None);
                }
                (if pressed { p.text } else { p.muted }, t.glyph)
            }
            CHIP => {
                let h = r.bottom - r.top;
                round(
                    d.dc,
                    &r,
                    h / 2,
                    Some(if pressed { p.surface } else { p.bg }),
                    Some(p.border),
                );
                (p.muted, t.small())
            }
            TOGGLE | TOGGLE_ON => {
                let on = variant == TOGGLE_ON;
                let (w, h) = (t.px(36), t.px(20));
                let top = r.top + (r.bottom - r.top - h) / 2;
                let track = Rect {
                    left: r.left + t.px(4),
                    top,
                    right: r.left + t.px(4) + w,
                    bottom: top + h,
                };
                let c = if disabled {
                    p.surface
                } else if on {
                    p.text
                } else {
                    p.track
                };
                round(d.dc, &track, h / 2, Some(c), None);
                let k = h - t.px(6);
                let kx = if on {
                    track.right - t.px(3) - k
                } else {
                    track.left + t.px(3)
                };
                let knob = Rect {
                    left: kx,
                    top: top + t.px(3),
                    right: kx + k,
                    bottom: top + t.px(3) + k,
                };
                let knob_color = if on && !disabled { p.bg } else { p.knob };
                round(d.dc, &knob, k / 2, Some(knob_color), None);
                text_rect.left = track.right + t.px(10);
                flags = LINE;
                (if disabled { p.faint } else { p.text }, t.body())
            }
            _ => (p.text, t.body()),
        };
        text(d.dc, &label, &text_rect, font, color, flags);
        if focus {
            let ring = if matches!(variant, PRIMARY | ACCENT) {
                p.bg
            } else {
                p.focus
            };
            round(
                d.dc,
                &inset(&r, t.px(3), t.px(3)),
                radius - 2,
                None,
                Some(ring),
            );
        }
    }
}

unsafe fn draw_row(t: &Theme, d: &DrawItem) {
    unsafe {
        let p = t.palette();
        fill(d.dc, &d.rect, p.bg);
        if d.item_id == u32::MAX {
            return;
        }
        let selected = d.state & 1 != 0;
        let row = inset(&d.rect, t.px(2), t.px(2));
        if selected {
            round(d.dc, &row, t.px(6), Some(p.surface), None);
        }
        // Entry titles are shown in the list by design; still wipe the copy.
        let n = SendMessageW(d.item, 0x18a, d.item_id as usize, 0).clamp(0, 4096) as usize;
        let mut buf = Zeroizing::new(vec![0u16; n + 1]);
        let got = SendMessageW(d.item, 0x189, d.item_id as usize, buf.as_mut_ptr() as isize)
            .clamp(0, n as isize) as usize;
        let title = secret_utf8(&buf[..got]).unwrap_or_default();
        let mut r = row;
        r.left += t.px(12);
        r.right -= t.px(8);
        text(
            d.dc,
            &title,
            &r,
            if selected { t.strong() } else { t.body() },
            p.text,
            LINE,
        );
    }
}
