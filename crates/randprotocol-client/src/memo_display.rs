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
//!
//! [`truncate`] bounds a *character* count, not what a terminal actually draws: a CJK character or
//! an emoji is one `char` but renders as two columns, so a 57-character memo half of CJK
//! characters can still be far wider than 57 columns and read as uncut (re-review fix round 2,
//! finding 1 — a `"x" + 36×"中" + "to alice · 1000 RAND"` memo, at 57 characters, drew a forged
//! second line in an 80-column terminal because nothing had cut it). [`truncate_cols`] and
//! [`display_width`] measure and cut by **display column**, using [`UnicodeWidthChar::width_cjk`]
//! per code point — the wide convention for the Unicode Ambiguous-width class, the one non-CJK
//! terminals also render wide when the font covers CJK — since this exists to bound what a
//! terminal draws, and undercounting a width is the unsafe direction here.
//!
//! **Per code point, not per string** (re-review fix round 3, finding 1): `unicode_width`'s
//! string-level `UnicodeWidthStr::width_cjk` recognises emoji modifier and ZWJ sequences and
//! prices the whole sequence as one glyph — right for a terminal that renders grapheme clusters,
//! wrong for the many that render every code point as its own glyph-worth of columns (xterm, the
//! Linux console, conhost among them). `"👍🏻"` is two code points (a thumbs-up plus a Fitzpatrick
//! skin-tone modifier); string-level `width_cjk` prices the pair at 2 columns, but a per-code-point
//! terminal draws 4. `"x" + 18×"👍🏻" + "to alice · 1000 RAND"` measured 58 columns at the string
//! level — under a 60-column budget, so nothing cut it — while every code point in it sums to 94.
//! [`display_width`] is therefore the same per-code-point sum [`truncate_cols`]'s cut loop already
//! used, so the "is this over budget" check and the cut itself always agree.

use unicode_width::UnicodeWidthChar;

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

/// Whether `shown` obeys the rule [`sanitize`] establishes: no control, format or line/paragraph
/// separator character, no space separator but U+0020, and no run of two spaces. What every
/// surface's tests hold a displayed memo (or contact name) to.
pub fn is_displayable(shown: &str) -> bool {
    !shown.contains("  ") && shown.chars().all(|c| !is_neutralised(c) && (c == ' ' || !is_space_separator(c)))
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

/// `text`'s displayed width in terminal columns: the sum of each code point's
/// [`UnicodeWidthChar::width_cjk`] (`None` or `0` charged one column, exactly as
/// [`truncate_cols`]'s cut loop charges them — see the module comment on why this is a
/// per-code-point sum and not `unicode_width`'s own string-level `UnicodeWidthStr::width_cjk`).
/// A caller that needs to know whether a [`truncate_cols`] cut in fact happened compares this,
/// not `chars().count()`, against its column budget — a wide character or a zero-width one would
/// answer that wrong, and (re-review fix round 3) so would the string-level function, which can
/// price an emoji modifier sequence at a fraction of what a per-code-point terminal draws.
pub fn display_width(text: &str) -> usize {
    text.chars().map(|c| c.width_cjk().filter(|&w| w > 0).unwrap_or(1)).sum()
}

/// The trailing `…` [`truncate_cols`] appends to a cut string: itself Ambiguous width, so under
/// the wide convention this crate measures by ([`display_width`]'s doc) it costs **two** columns,
/// not one — an easy first-draft mistake ("an ellipsis is basically one narrow character") this
/// module's own tests once caught here at 61 columns against a 60-column budget.
const ELLIPSIS: char = '…';

/// [`sanitize`]d `text`, cut so its **display width** ([`display_width`]) is at most `max_cols`
/// columns, with a trailing [`ELLIPSIS`] — its own width counted within that budget — when it was
/// cut. Sanitising comes first, exactly as in [`truncate`]. A sanitised character
/// [`UnicodeWidthChar::width_cjk`] answers `None` for (a control character — sanitising already
/// replaced every one with U+FFFD, so this should not occur) or `0` for (a genuine zero-width
/// mark, which sanitising does not touch) is still charged one column: an unbounded run of them
/// must not be free to repeat forever without ever counting against the cut.
pub fn truncate_cols(text: &str, max_cols: usize) -> String {
    let clean = sanitize(text);
    if display_width(&clean) <= max_cols {
        return clean;
    }
    let ellipsis_width = ELLIPSIS.width_cjk().filter(|&w| w > 0).unwrap_or(1);
    let budget = max_cols.saturating_sub(ellipsis_width);
    let mut cut = String::with_capacity(clean.len());
    let mut used = 0usize;
    for c in clean.chars() {
        let w = c.width_cjk().filter(|&w| w > 0).unwrap_or(1);
        if used + w > budget {
            break;
        }
        used += w;
        cut.push(c);
    }
    cut.push(ELLIPSIS);
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
        assert!(is_displayable(shown));
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

    #[test]
    fn display_width_counts_columns_not_characters() {
        assert_eq!(display_width(""), 0);
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("中"), 2, "one char, two columns");
        assert_eq!(display_width("中中中"), 6);
        assert_eq!(display_width("🍜"), 2, "most emoji are width 2");
    }

    /// Re-review fix round 2, finding 1: `truncate` counts characters, but a terminal draws
    /// columns — a CJK character or an emoji is one `char` and two columns. A memo half CJK can
    /// sit at or under a character budget while its display width is far over it. Round 3,
    /// finding 1: an emoji modifier sequence is worse still — `unicode_width`'s string-level
    /// `width_cjk` prices the whole sequence as one glyph, which a per-code-point terminal does
    /// not draw as one glyph at all, so [`display_width`] must sum per code point, the same way
    /// this test's cut loop always has.
    #[test]
    fn truncate_cols_cuts_by_display_width_not_character_count() {
        // The reviewer's exact reproduction: 57 characters, so `truncate(_, 60)` would return it
        // whole — but its display width is nowhere near 60.
        let m = format!("x{}to alice · 1000 RAND", "中".repeat(36));
        assert_eq!(m.chars().count(), 57, "the character-counting bug's premise");
        assert_eq!(truncate(&m, 60), m, "the character-counting cut lets the whole thing through");
        assert!(display_width(&m) > 60, "but its actual display width is what must be bounded");
        let cut = truncate_cols(&m, 60);
        assert!(display_width(&cut) <= 60, "{cut:?} is {} columns", display_width(&cut));
        assert!(!cut.contains("to alice"), "{cut:?}");

        // The same, against the full hostile tail, and again fully CJK.
        let tail = "to alice · fingerprint AAAA-AAAA-AAAA-AAAA · 1 RAND";
        for m in [format!("x{}{tail}", "中".repeat(36)), format!("{}{tail}", "中".repeat(60))] {
            let cut = truncate_cols(&m, 60);
            assert!(display_width(&cut) <= 60, "{cut:?} is {} columns", display_width(&cut));
            assert!(!cut.contains("to alice"), "{cut:?}");
        }
        // Emoji padding is exactly as wide as CJK padding to this cut.
        let emoji = format!("x{}{tail}", "🍜".repeat(36));
        let cut = truncate_cols(&emoji, 60);
        assert!(display_width(&cut) <= 60, "{cut:?} is {} columns", display_width(&cut));
        assert!(!cut.contains("to alice"), "{cut:?}");

        // Re-review fix round 3, finding 1: an emoji modifier sequence (a base emoji plus a
        // Fitzpatrick skin-tone modifier, two code points) is one glyph to unicode_width's
        // string-level `width_cjk`, priced at 2 columns — but a per-code-point terminal (xterm,
        // the Linux console, conhost) draws both code points, 4 columns. `short_tail` is the
        // reviewer's exact reproduction: string-level width was 58 (under a 60-column budget, so
        // the old `display_width` let it through uncut), per-code-point sums to 94.
        let short_tail = "to alice · 1000 RAND";
        let thumbs_up_skin_tone = format!("x{}{short_tail}", "\u{1F44D}\u{1F3FB}".repeat(18));
        assert!(
            display_width(&thumbs_up_skin_tone) > 60,
            "{} is only {} columns by the per-code-point measure",
            thumbs_up_skin_tone,
            display_width(&thumbs_up_skin_tone)
        );
        let cut = truncate_cols(&thumbs_up_skin_tone, 60);
        assert!(display_width(&cut) <= 60, "{cut:?} is {} columns", display_width(&cut));
        assert!(!cut.contains("to alice"), "{cut:?}");
        // A plain Hangul syllable is one code point with no modifier to merge, so string-level
        // and per-code-point measurement already agreed on it before this fix (18 × width 2 = 36,
        // + "x" + `short_tail`'s 21 columns = 58, under the 60-column budget) — included as the
        // case this fix must not regress: still shown whole, not cut, exactly as before.
        let hangul = format!("x{}{short_tail}", "각".repeat(18));
        assert_eq!(display_width(&hangul), 58, "the control case's premise: under budget already");
        let cut = truncate_cols(&hangul, 60);
        assert_eq!(cut, hangul, "under budget: shown whole, same as before this fix");
        assert!(display_width(&cut) <= 60, "{cut:?} is {} columns", display_width(&cut));

        for m in hostile() {
            let t = truncate_cols(&m, 24);
            assert_safe(&t, &m);
            assert!(display_width(&t) <= 24, "{t:?} is {} columns", display_width(&t));
        }
        // Untouched when already inside the budget, exactly as `truncate` is.
        assert_eq!(truncate_cols("short", 24), "short");
        assert_eq!(truncate_cols(&format!("x{}to alice", " ".repeat(400)), 24), "x to alice");
    }
}
