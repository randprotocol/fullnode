//! Program file formats: raw little-endian words (`.bin`), the M4.3 image container `rand-guest
//! build` emits (also `.bin`), and `{ "base_pc", "words" }` JSON.

use crate::isa::{Program, IMAGE_MAGIC};

/// A `.bin` is either the M4.3 image container (`isa::Program::from_flat_image`'s layout: a
/// six-word header starting with [`IMAGE_MAGIC`], then text, then data — what `rand-guest build`
/// produces for a guest with a data segment) or, as before, raw little-endian words loaded from
/// base 0. The two are told apart by the first word: `IMAGE_MAGIC` (`0x444e_4152`, `b"RAND"` read
/// little-endian) never decodes as an RV32 instruction, so a raw program can never begin with it
/// and there is no ambiguity — a file that starts with the magic word but is not a well-formed
/// container is reported as a container error, not silently reinterpreted as raw words.
///
/// A file shorter than 4 bytes or not a multiple of 4 keeps today's raw-word error: the magic
/// check itself needs a whole first word to read.
pub fn program_from_bytes(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() % 4 != 0 {
        return Err("program bytes must be a multiple of 4".into());
    }
    if bytes.len() >= 4 {
        let first = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if first == IMAGE_MAGIC {
            return Program::from_flat_image(bytes).map_err(|e| format!("{e:?}"));
        }
    }
    Ok(Program { base_pc: 0, words: bytes.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect() })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProgramJson {
    base_pc: u32,
    words: Vec<u32>,
}

pub fn program_from_json(s: &str) -> Result<Program, String> {
    let p: ProgramJson = serde_json::from_str(s).map_err(|e| e.to_string())?;
    if p.base_pc % 4 != 0 {
        return Err("base_pc must be word aligned".into());
    }
    Ok(Program { base_pc: p.base_pc, words: p.words })
}

pub fn program_to_json(p: &Program) -> String {
    serde_json::to_string_pretty(&ProgramJson { base_pc: p.base_pc, words: p.words.clone() }).expect("serializes")
}

pub fn program_to_bytes(p: &Program) -> Vec<u8> {
    p.words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let p = Program { base_pc: 8, words: vec![0x13, 0x73, 0xdeadbeef] };
        assert_eq!(program_from_json(&program_to_json(&p)).unwrap(), p);
        let raw = program_from_bytes(&program_to_bytes(&p)).unwrap();
        assert_eq!(raw.words, p.words);
        assert_eq!(raw.base_pc, 0);
        assert!(program_from_bytes(&[1, 2, 3]).is_err());
        assert!(program_from_json(r#"{"base_pc": 2, "words": []}"#).is_err());
    }

    /// A raw `.bin` that does not begin with [`crate::isa::IMAGE_MAGIC`] loads exactly as it
    /// always has: words from base 0. `0x444e_4152` ("RAND" little-endian) is not itself a
    /// decodable RV32 instruction (the brief's own reasoning for why the two files can never be
    /// confused), so this is any ordinary raw word list, not a special case of one.
    #[test]
    fn a_raw_non_container_bin_still_loads_from_base_0() {
        let words = [0x13u32, 0x73, 0xdead_beef];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_ne!(words[0], crate::isa::IMAGE_MAGIC);
        let p = program_from_bytes(&bytes).unwrap();
        assert_eq!(p.base_pc, 0);
        assert_eq!(p.words, words);
    }

    /// The M4.3 image container (`Program::from_flat_image`'s own layout: header, text, data) is
    /// what `rand-guest build` emits and what the prover loads a compiled guest with. A wallet
    /// reading the same file through `program_from_bytes` has to land on the exact same
    /// `Program` — same `base_pc`, same words, same `hc` — or a deployed program would not be the
    /// one `rand-guest` reported.
    #[test]
    fn program_from_bytes_recognises_the_image_container_by_its_magic_word() {
        const EVM_BIN: &[u8] = include_bytes!("../guests-compiled/bin/evm.bin");
        let want = crate::guests::compiled::evm();
        let got = program_from_bytes(EVM_BIN).expect("evm.bin is a committed, known-good image");
        assert_eq!(got.base_pc, want.base_pc);
        assert_eq!(got.words, want.words);
        assert_eq!(got.digest(), want.digest());
    }

    /// A file that starts with the magic word but is otherwise malformed (here: shorter than the
    /// header) is reported as an image-loading error, not silently reinterpreted as raw words —
    /// `0x444e_4152` can never appear as a raw program's first word (it does not decode as an
    /// RV32 instruction), so there is no ambiguity to fall back from.
    #[test]
    fn a_truncated_container_is_an_error_not_a_silent_raw_load() {
        let bytes: Vec<u8> = crate::isa::IMAGE_MAGIC.to_le_bytes().to_vec();
        assert!(program_from_bytes(&bytes).is_err());
    }
}
