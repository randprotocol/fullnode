//! Program file formats: raw little-endian words (`.bin`) and `{ "base_pc", "words" }` JSON.

use crate::isa::Program;

pub fn program_from_bytes(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() % 4 != 0 {
        return Err("program bytes must be a multiple of 4".into());
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
}
