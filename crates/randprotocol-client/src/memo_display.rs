//! One display rule for a memo — or anything else a stranger chose the text of — on every
//! surface the CLI prints it (spec 2026-09-26 §2.3, final review A).
//!
//! A memo is hostile input: anyone can pay a dust note carrying any memo to any public address,
//! and a `randpay:` link can carry any memo. So before a memo is shown, and **before it is
//! truncated**, [`sanitize`] rewrites it so it can never break a line, move the cursor, reorder
//! the text around it, hide characters, or pad itself out to push a fake line into view:
//!
//! - every C0 control (tab and newline included), DEL and every C1 control becomes U+FFFD;
//! - every format character (general category Cf: the bidi embeddings, overrides and isolates,
//!   LRM/RLM/ALM, the zero-width space/joiners, U+2060–U+2064, U+FEFF, the soft hyphen, …) and
//!   the line and paragraph separators U+2028/U+2029 become U+FFFD;
//! - every run of space separators (general category Zs: U+0020, U+00A0, U+2003, U+3000, …)
//!   collapses to one U+0020.
//!
//! Every replacement is a single character, so [`truncate`] — which counts characters of the
//! already-sanitised text — can never split an escape. The same rule, with the same U+FFFD, is in
//! the web UI (`ui/lib/memo.js`), iOS (`Memo.display`), Android (`Memo.display`) and the
//! website's `/account`.

/// The character every control, format character and line/paragraph separator becomes.
pub const REPLACEMENT: char = '\u{FFFD}';

/// General category Cf (Unicode 15.1), as inclusive ranges.
const FORMAT: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// General category Zs (Unicode 15.1).
fn is_space_separator(c: char) -> bool {
    matches!(c, '\u{0020}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

/// Whether `c` is replaced by [`REPLACEMENT`]: Cc (C0, DEL, C1), Cf, Zl and Zp.
fn is_neutralised(c: char) -> bool {
    let u = c as u32;
    c.is_control() || u == 0x2028 || u == 0x2029 || FORMAT.iter().any(|&(lo, hi)| (lo..=hi).contains(&u))
}

/// `text` as it may be shown: see the module comment. Pure; never fails.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space = false;
    for c in text.chars() {
        if is_space_separator(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
            continue;
        }
        in_space = false;
        out.push(if is_neutralised(c) { REPLACEMENT } else { c });
    }
    out
}

/// [`sanitize`]d `text`, cut to at most `max` characters with a trailing `…` when it was longer
/// (the `…` counts toward `max`). Sanitising comes first, so a cut can never split an escape or
/// leave half of a control sequence.
pub fn truncate(text: &str, max: usize) -> String {
    let clean = sanitize(text);
    if clean.chars().count() <= max {
        return clean;
    }
    let mut cut: String = clean.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The hostile memos every surface is tested with (final review A).
    pub(crate) fn hostile() -> Vec<String> {
        let tail = "to alice · fingerprint AAAA-AAAA-AAAA-AAAA · 1 RAND";
        vec![
            format!("x{}{tail}", "\u{3000}".repeat(120)),
            format!("x{}{tail}", " ".repeat(400)),
            format!("x{}{tail}", "\u{2003}".repeat(60)),
            format!("\r\x1b[2K{tail}"),
            format!("\n\nto alice\u{2028}{tail}\u{2029}"),
            format!("\u{202E}DNAR 1\u{202C} \u{2066}{tail}\u{2069}\u{200E}\u{200F}\u{061C}"),
            format!("a\u{200B}\u{200C}\u{200D}b\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}c\u{FEFF}d\u{00AD}e"),
            format!("\t{tail}\u{7f}\u{85}\u{9b}31m"),
        ]
    }

    /// Nothing that could break, move or reorder a line, hide a character, or pad the line out.
    pub(crate) fn assert_safe(shown: &str, from: &str) {
        for c in shown.chars() {
            assert!(!c.is_control(), "control {:?} in {shown:?} (from {from:?})", c);
            assert!(!is_neutralised(c), "format/separator {:?} in {shown:?} (from {from:?})", c);
            assert!(c == ' ' || !is_space_separator(c), "non-ASCII space {:?} in {shown:?} (from {from:?})", c);
        }
        assert!(!shown.contains("  "), "a run of spaces in {shown:?} (from {from:?})");
    }

    #[test]
    fn a_hostile_memo_shows_on_one_line_with_nothing_hidden_and_no_padding() {
        for m in hostile() {
            assert_safe(&sanitize(&m), &m);
        }
        let padded = format!("x{}to alice", "\u{3000}".repeat(120));
        assert_eq!(sanitize(&padded), "x to alice");
        assert_eq!(sanitize("\r\x1b[2Kto alice"), "\u{FFFD}\u{FFFD}[2Kto alice");
        assert_eq!(sanitize("a\u{202E}b"), "a\u{FFFD}b");
        assert_eq!(sanitize("lunch 🍜 for two"), "lunch 🍜 for two", "ordinary text is untouched");
    }

    #[test]
    fn truncation_comes_after_sanitising_and_never_splits_an_escape() {
        for m in hostile() {
            let t = truncate(&m, 24);
            assert_safe(&t, &m);
            assert!(t.chars().count() <= 24, "{t:?}");
        }
        // 400 spaces collapse first, so the cut shows the text after them, not a blank column.
        assert_eq!(truncate(&format!("x{}to alice", " ".repeat(400)), 24), "x to alice");
        assert_eq!(truncate("\x1b[2K\x1b[2K\x1b[2K\x1b[2K\x1b[2K\x1b[2K", 6), "\u{FFFD}[2K\u{FFFD}…");
        assert_eq!(truncate("short", 24), "short");
    }
}
