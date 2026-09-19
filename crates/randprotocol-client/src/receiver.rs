//! Short addresses, the wallet's half (spec §§9, 11): turning any address string into the keys a
//! payment is sealed to, without telling the node who is being paid.
//!
//! A direct (`trnd1q…`) or legacy (`rand1…`) address carries the keys and needs no network at
//! all (W-1). A short address (`trnd1s…`) carries only the receiver id, so the wallet fetches
//! the registry — the whole of it while it is small, a bucket of at least `K_MIN` records once
//! it is not (W-4, W-10) — and never a single id (W-7). Whatever comes back is re-hashed and
//! compared with the id before it is used (W-5): a lying node can make a payment fail, never
//! go to the wrong keys. Resolved records are immutable, so they are cached for good (W-6).

use crate::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::address::{self, pk_is_canonical, Decoded, ReceiverId};
use randprotocol_core::notes::{word8_from_bytes, ShieldedAddress, KEM_EK_BYTES};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// W-9, verbatim.
pub const NOT_REGISTERED: &str =
    "This short address is not registered yet. Ask the recipient for their full address (rnd1q...).";

/// Where a wallet keeps the records it has resolved: `<key>.receivers.json`.
pub fn cache_path(key: &Path) -> PathBuf {
    let mut s = key.as_os_str().to_os_string();
    s.push(".receivers.json");
    PathBuf::from(s)
}

/// id (hex) -> the direct address. Records never change, so an entry never goes stale.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Cache(BTreeMap<String, String>);

impl Cache {
    pub fn load(path: &Path) -> Cache {
        std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?).with_context(|| format!("writing {}", path.display()))
    }
}

/// F-7: the FIPS 203 encapsulation-key check (the modulus check) before a key is first used.
/// The ledger does not make it (C-4); a malformed key harms only whoever pays it, which is why
/// the wallet does.
pub fn check_encapsulation_key(kem_ek: &[u8]) -> Result<()> {
    type Ek = ml_kem::ml_kem_768::EncapsulationKey;
    let key = ml_kem::kem::Key::<Ek>::try_from(kem_ek).map_err(|_| anyhow!("encapsulation key is not {KEM_EK_BYTES} bytes"))?;
    Ek::new(&key).map(|_| ()).map_err(|_| anyhow!("encapsulation key fails the FIPS 203 modulus check"))
}

/// The keys `s` pays, resolving a short address through `rpc` (and `cache`) when it is one.
pub async fn resolve(rpc: &RpcClient, cache: &mut Cache, s: &str) -> Result<ShieldedAddress> {
    let id = match address::decode(s).map_err(|e| anyhow!("{e}")).context("invalid address")? {
        Decoded::Direct(a) | Decoded::Legacy(a) => {
            check_encapsulation_key(&a.kem_ek)?;
            return Ok(a);
        }
        Decoded::Short(id) => id,
    };
    if let Some(direct) = cache.0.get(&id.to_hex()) {
        // Re-verified on every use: the cache file is only as trustworthy as the disk it is on.
        let a = ShieldedAddress::parse(direct).map_err(|e| anyhow!("{e}"))?;
        if ReceiverId::of_address(&a) == id {
            return Ok(a);
        }
    }
    let records = fetch_candidates(rpc, &id).await?;
    let found = records.iter().find(|r| r.0 == id).ok_or_else(|| anyhow!(NOT_REGISTERED))?;
    let a = verify(&id, found)?;
    cache.0.insert(id.to_hex(), a.to_string());
    Ok(a)
}

/// W-5: the returned record must hash to the id, carry a canonical `pk` and a usable key.
fn verify(id: &ReceiverId, r: &(ReceiverId, ShieldedAddress)) -> Result<ShieldedAddress> {
    let a = &r.1;
    if ReceiverId::of_address(a) != *id {
        bail!("the node returned a record that does not hash to {} — treat that endpoint as hostile and use another", id.to_hex());
    }
    if !pk_is_canonical(&a.pk) {
        bail!("the registered record for {} has a non-canonical pk", id.to_hex());
    }
    check_encapsulation_key(&a.kem_ek)?;
    Ok(a.clone())
}

/// The records a wallet may ask for when it wants `id`: the whole registry below `K_MIN`, else
/// the id's bucket at the width every thin wallet uses (W-4). Never the id alone (W-7).
async fn fetch_candidates(rpc: &RpcClient, id: &ReceiverId) -> Result<Vec<(ReceiverId, ShieldedAddress)>> {
    let info = rpc.call("rand_getReceiverInfo", json!([])).await?;
    if !info["enabled"].as_bool().unwrap_or(false) {
        bail!("this chain has no receiver registry, so short addresses cannot be paid on it; ask for the full address");
    }
    let bits = info["bits"].as_u64().context("rand_getReceiverInfo has no bits")? as u8;
    let rows: Vec<Value> = if bits == 0 {
        let mut all = Vec::new();
        let mut from = 0u64;
        loop {
            let page = rpc.call("rand_getReceivers", json!([from])).await?;
            let recs = page["records"].as_array().cloned().unwrap_or_default();
            if recs.is_empty() {
                break;
            }
            from = page["next_seq"].as_u64().context("rand_getReceivers has no next_seq")?;
            all.extend(recs);
        }
        all
    } else {
        let prefix = bucket_prefix(id, bits);
        let v = rpc.call("rand_getReceiverBucket", json!([hex::encode(prefix), bits])).await?;
        v["records"].as_array().cloned().unwrap_or_default()
    };
    rows.iter().map(record_of).collect()
}

/// The first `bits` bits of `id`, in `ceil(bits / 8)` bytes with the unused low bits zero.
pub fn bucket_prefix(id: &ReceiverId, bits: u8) -> Vec<u8> {
    let n = (bits as usize).div_ceil(8);
    let mut p = id.0[..n].to_vec();
    if bits % 8 != 0 {
        p[n - 1] &= 0xffu8 << (8 - bits % 8);
    }
    p
}

fn record_of(v: &Value) -> Result<(ReceiverId, ShieldedAddress)> {
    let bytes = |k: &str| -> Result<Vec<u8>> { hex::decode(v[k].as_str().with_context(|| format!("record has no {k}"))?).map_err(Into::into) };
    let id: [u8; 32] = bytes("id")?.try_into().map_err(|_| anyhow!("record id is not 32 bytes"))?;
    let pk = word8_from_bytes(&bytes("pk")?).context("record pk is not 32 bytes")?;
    Ok((ReceiverId(id), ShieldedAddress { pk, kem_ek: bytes("kem_ek")? }))
}

/// Whether `id` is in the registry, asked the private way (the same fetch a payer makes).
pub async fn is_registered(rpc: &RpcClient, id: &ReceiverId) -> Result<bool> {
    Ok(fetch_candidates(rpc, id).await?.iter().any(|r| r.0 == *id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_prefixes_zero_the_unused_bits() {
        let id = ReceiverId([0xff; 32]);
        assert_eq!(bucket_prefix(&id, 0), Vec::<u8>::new());
        assert_eq!(bucket_prefix(&id, 3), vec![0xe0]);
        assert_eq!(bucket_prefix(&id, 8), vec![0xff]);
        assert_eq!(bucket_prefix(&id, 12), vec![0xff, 0xf0]);
    }

    #[test]
    fn a_record_that_does_not_hash_to_the_id_is_refused() {
        let a = ShieldedAddress { pk: [1; 8], kem_ek: vec![0; KEM_EK_BYTES] };
        let other = ReceiverId([7; 32]);
        let err = verify(&other, &(other, a)).unwrap_err().to_string();
        assert!(err.contains("hostile"), "{err}");
    }
}
