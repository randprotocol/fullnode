//! `rand-node bridge-gov …` (BRG-14) as the built binary runs it against a loopback RPC fake:
//! the message every signer compares, one signer's line, and the assembled submission, for a PQ
//! guardian rotation, a pause-key rotation and a cancel — with and without proof of possession.
//! Chain 14, no proofs.

mod fakerpc;

use fakerpc::*;
use randprotocol_core::{Action, BindingDomain};
use randprotocol_node::bridge_gov_tool as tool;
use serde_json::{json, Value};

fn bridge_node(
    guardians: &[&Signer],
    pause: Option<&Signer>,
    nonce: u64,
    possession: bool,
    rules_v2: bool,
) -> (String, Calls) {
    let state = json!({
        "enabled": true,
        "rules_v2": if rules_v2 { json!({ "global_mint_cap_per_window": 1000, "cap_window_secs": 86400 }) } else { Value::Null },
        "rotation_nonce": nonce,
        "pq_guardians": guardians.iter().map(|g| g.public.clone()).collect::<Vec<_>>(),
        "pause_key": pause.map(|p| json!(p.public)).unwrap_or(Value::Null),
        "rotation_rules": { "needs_possession": possession },
    });
    chain14(move |m, _| (m == "rand_getBridgeState").then(|| state.clone()))
}

fn pk(s: &Signer) -> randprotocol_core::PublicKey {
    randprotocol_core::PublicKey::from_hex(&s.public).unwrap()
}

#[test]
fn rotate_pq_message_is_what_the_tool_builds_and_every_signer_prints_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, g1, new0, new1) = (
        signer(dir.path(), "g0"),
        signer(dir.path(), "g1"),
        signer(dir.path(), "n0"),
        signer(dir.path(), "n1"),
    );
    let (url, _) = bridge_node(&[&g0, &g1], None, 3, false, true);
    let msg = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        &new0.public,
        "--new-key",
        &new1.public,
        "--rpc",
        &url,
    ]);
    assert!(msg.ok, "{}", msg.err);
    let want = tool::rotation_message(
        &BindingDomain::ChainId,
        14,
        3,
        &tool::Rotation::Pq(vec![pk(&new0), pk(&new1)]),
    );
    assert_eq!(msg.out.trim(), hex::encode(want));
    assert!(
        msg.err.contains("chain 14 rotation_nonce 3") && !msg.err.contains("possession"),
        "{}",
        msg.err
    );

    // A key file also names a new key (`@path`), and a different set is a different message.
    let by_file = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        &format!("@{}", new0.key.display()),
        "--new-key",
        &new1.public,
        "--rpc",
        &url,
    ]);
    assert_eq!(by_file.out, msg.out);
    let other = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        &new1.public,
        "--new-key",
        &new0.public,
        "--rpc",
        &url,
    ]);
    assert_ne!(other.out, msg.out, "the order of the new set is signed");
    let bad = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        "zz",
        "--rpc",
        &url,
    ]);
    assert!(
        !bad.ok && bad.err.contains("not a Dilithium2 public key or key file"),
        "{}",
        bad.err
    );
}

#[test]
fn rotate_pq_is_signed_by_the_guardians_and_submitted_as_the_v1_action() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, g1, new0) = (
        signer(dir.path(), "g0"),
        signer(dir.path(), "g1"),
        signer(dir.path(), "n0"),
    );
    let (url, calls) = bridge_node(&[&g0, &g1], None, 3, false, true);
    let sign = |g: &Signer, index: &str| {
        node(&[
            "bridge-gov",
            "rotate-pq",
            "sign",
            "--new-key",
            &new0.public,
            "--key",
            g.key.to_str().unwrap(),
            "--index",
            index,
            "--rpc",
            &url,
        ])
    };
    let (s0, s1) = (sign(&g0, "0"), sign(&g1, "1"));
    assert!(s0.ok && s1.ok, "{}{}", s0.err, s1.err);
    assert!(s0.out.starts_with("0:") && s1.out.starts_with("1:"));
    let mixed = sign(&g0, "1");
    assert!(
        !mixed.ok
            && mixed
                .err
                .contains("this key file is not the key at index 1"),
        "{}",
        mixed.err
    );
    let beyond = sign(&g0, "5");
    assert!(
        !beyond.ok && beyond.err.contains("there is no key at index 5"),
        "{}",
        beyond.err
    );

    let quorum = format!("{}\n{} # comment\n", s1.out.trim(), s0.out.trim());
    let qfile = dir.path().join("quorum.txt");
    std::fs::write(&qfile, &quorum).unwrap();
    let sub = node(&[
        "bridge-gov",
        "rotate-pq",
        "submit",
        "--new-key",
        &new0.public,
        "--quorum",
        &format!("@{}", qfile.display()),
        "--rpc",
        &url,
        "--no-wait",
    ]);
    assert!(sub.ok, "{}", sub.err);
    assert!(
        sub.out.contains(&format!(
            "submitted PQ guardian rotation {}",
            "ef".repeat(32)
        )),
        "{}",
        sub.out
    );
    let Action::RotatePqGuardians {
        new_pq_guardians,
        nonce,
        pq_signatures,
    } = &sent(&calls)[0].action
    else {
        panic!("{:?}", sent(&calls)[0].action)
    };
    assert_eq!((new_pq_guardians.len(), *nonce), (1, 3));
    assert_eq!(
        pq_signatures.iter().map(|s| s.index).collect::<Vec<_>>(),
        vec![0, 1],
        "sorted into index order"
    );

    let dup = node(&[
        "bridge-gov",
        "rotate-pq",
        "submit",
        "--new-key",
        &new0.public,
        "--quorum",
        &format!("{} {}", s0.out.trim(), s0.out.trim()),
        "--rpc",
        &url,
    ]);
    assert!(
        !dup.ok && dup.err.contains("signer index 0 appears twice"),
        "{}",
        dup.err
    );
    let junk = node(&[
        "bridge-gov",
        "rotate-pq",
        "submit",
        "--new-key",
        &new0.public,
        "--quorum",
        "nonsense",
        "--rpc",
        &url,
    ]);
    assert!(
        !junk.ok && junk.err.contains("expected index:signature-hex"),
        "{}",
        junk.err
    );
    // This chain takes no possession proof, so one is refused.
    let poss = node(&[
        "bridge-gov",
        "rotate-pq",
        "submit",
        "--new-key",
        &new0.public,
        "--quorum",
        s0.out.trim(),
        "--possession",
        "0:00",
        "--rpc",
        &url,
    ]);
    assert!(
        !poss.ok
            && poss
                .err
                .contains("does not take a proof of possession: drop --possession"),
        "{}",
        poss.err
    );
    assert_eq!(sent(&calls).len(), 1);
}

#[test]
fn a_chain_that_needs_possession_takes_each_new_keys_own_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, n0, n1) = (
        signer(dir.path(), "g0"),
        signer(dir.path(), "n0"),
        signer(dir.path(), "n1"),
    );
    let (url, calls) = bridge_node(&[&g0], None, 0, true, true);
    let new: Vec<String> = [
        "--new-key",
        n0.public.as_str(),
        "--new-key",
        n1.public.as_str(),
        "--rpc",
        url.as_str(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let run = |head: Vec<&str>, tail: &[&str]| {
        let mut all: Vec<String> = head.iter().map(|s| s.to_string()).collect();
        all.extend(new.iter().cloned());
        all.extend(tail.iter().map(|s| s.to_string()));
        let args: Vec<&str> = all.iter().map(String::as_str).collect();
        node(&args)
    };
    let msg = run(vec!["bridge-gov", "rotate-pq", "message"], &[]);
    assert!(msg.err.contains("(possession required)"), "{}", msg.err);
    let quorum = run(
        vec!["bridge-gov", "rotate-pq", "sign"],
        &["--key", g0.key.to_str().unwrap(), "--index", "0"],
    );
    // A possession signer signs as the new key at its index.
    let p0 = run(
        vec!["bridge-gov", "rotate-pq", "sign"],
        &[
            "--key",
            n0.key.to_str().unwrap(),
            "--index",
            "0",
            "--possession",
        ],
    );
    let p1 = run(
        vec!["bridge-gov", "rotate-pq", "sign"],
        &[
            "--key",
            n1.key.to_str().unwrap(),
            "--index",
            "1",
            "--possession",
        ],
    );
    assert!(
        quorum.ok && p0.ok && p1.ok,
        "{}{}{}",
        quorum.err,
        p0.err,
        p1.err
    );
    let wrong = run(
        vec!["bridge-gov", "rotate-pq", "sign"],
        &[
            "--key",
            n1.key.to_str().unwrap(),
            "--index",
            "0",
            "--possession",
        ],
    );
    assert!(
        !wrong.ok
            && wrong
                .err
                .contains("this key file is not the key at index 0"),
        "{}",
        wrong.err
    );

    let without = run(
        vec!["bridge-gov", "rotate-pq", "submit"],
        &["--quorum", quorum.out.trim()],
    );
    assert!(
        !without.ok
            && without
                .err
                .contains("requires a proof of possession: pass --possession"),
        "{}",
        without.err
    );
    let poss = format!("{} {}", p0.out.trim(), p1.out.trim());
    let ok = run(
        vec!["bridge-gov", "rotate-pq", "submit"],
        &[
            "--quorum",
            quorum.out.trim(),
            "--possession",
            &poss,
            "--no-wait",
        ],
    );
    assert!(ok.ok, "{}", ok.err);
    assert!(
        matches!(sent(&calls)[0].action, Action::RotatePqGuardiansV2 { .. }),
        "{:?}",
        sent(&calls)[0].action
    );
    let short = run(
        vec!["bridge-gov", "rotate-pq", "submit"],
        &["--quorum", quorum.out.trim(), "--possession", p0.out.trim()],
    );
    assert!(
        !short.ok
            && short
                .err
                .contains("possession lines must be exactly one per new key"),
        "{}",
        short.err
    );
    // A possession line signed by the wrong key is named before anything is sent.
    let swapped = format!(
        "0:{} {}",
        p1.out.trim().split_once(':').unwrap().1,
        p1.out.trim()
    );
    let forged = run(
        vec!["bridge-gov", "rotate-pq", "submit"],
        &["--quorum", quorum.out.trim(), "--possession", &swapped],
    );
    assert!(
        !forged.ok
            && forged
                .err
                .contains("possession signature 0 does not verify under new key 0"),
        "{}",
        forged.err
    );
    assert_eq!(sent(&calls).len(), 1);
}

#[test]
fn a_pause_key_rotation_names_exactly_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, pause, new_pause, extra) = (
        signer(dir.path(), "g0"),
        signer(dir.path(), "pause"),
        signer(dir.path(), "np"),
        signer(dir.path(), "x"),
    );
    let (url, calls) = bridge_node(&[&g0], Some(&pause), 1, false, true);
    let two = node(&[
        "bridge-gov",
        "rotate-pause",
        "message",
        "--new-key",
        &new_pause.public,
        "--new-key",
        &extra.public,
        "--rpc",
        &url,
    ]);
    assert!(
        !two.ok
            && two
                .err
                .contains("a pause-key rotation names exactly one --new-key"),
        "{}",
        two.err
    );
    let msg = node(&[
        "bridge-gov",
        "rotate-pause",
        "message",
        "--new-key",
        &new_pause.public,
        "--rpc",
        &url,
    ]);
    assert_eq!(
        msg.out.trim(),
        hex::encode(tool::rotation_message(
            &BindingDomain::ChainId,
            14,
            1,
            &tool::Rotation::Pause(pk(&new_pause))
        ))
    );
    let sig = node(&[
        "bridge-gov",
        "rotate-pause",
        "sign",
        "--new-key",
        &new_pause.public,
        "--key",
        g0.key.to_str().unwrap(),
        "--index",
        "0",
        "--rpc",
        &url,
    ]);
    assert!(sig.ok, "{}", sig.err);
    let sub = node(&[
        "bridge-gov",
        "rotate-pause",
        "submit",
        "--new-key",
        &new_pause.public,
        "--quorum",
        sig.out.trim(),
        "--rpc",
        &url,
        "--no-wait",
    ]);
    assert!(
        sub.ok && sub.out.contains("submitted pause-key rotation"),
        "{}{}",
        sub.out,
        sub.err
    );
    assert!(matches!(
        sent(&calls)[0].action,
        Action::RotatePauseKey { .. }
    ));
}

#[test]
fn a_cancel_is_signed_by_the_pause_key_and_submitted() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, pause, other) = (
        signer(dir.path(), "g0"),
        signer(dir.path(), "pause"),
        signer(dir.path(), "other"),
    );
    let (url, calls) = bridge_node(&[&g0], Some(&pause), 7, false, true);
    for kind in ["pq", "pause"] {
        let s = node(&[
            "bridge-gov",
            "cancel-rotation",
            "sign",
            "--kind",
            kind,
            "--key",
            pause.key.to_str().unwrap(),
            "--rpc",
            &url,
        ]);
        assert!(
            s.ok && s.out.starts_with("0:"),
            "{kind}: {}{}",
            s.out,
            s.err
        );
        let sub = node(&[
            "bridge-gov",
            "cancel-rotation",
            "submit",
            "--kind",
            kind,
            "--signature",
            s.out.trim(),
            "--rpc",
            &url,
            "--no-wait",
        ]);
        assert!(
            sub.ok && sub.out.contains("submitted rotation cancel"),
            "{kind}: {}{}",
            sub.out,
            sub.err
        );
    }
    let txs = sent(&calls);
    let kinds: Vec<u8> = txs
        .iter()
        .map(|t| match &t.action {
            Action::CancelRotation { kind, nonce, .. } => {
                assert_eq!(*nonce, 7);
                *kind
            }
            a => panic!("{a:?}"),
        })
        .collect();
    assert_eq!(kinds.len(), 2);
    assert_ne!(kinds[0], kinds[1], "the kind is in the action");
    let wrong = node(&[
        "bridge-gov",
        "cancel-rotation",
        "sign",
        "--kind",
        "pq",
        "--key",
        other.key.to_str().unwrap(),
        "--rpc",
        &url,
    ]);
    assert!(
        !wrong.ok
            && wrong
                .err
                .contains("this key file is not the key at index 0"),
        "{}",
        wrong.err
    );
    let bad_kind = node(&[
        "bridge-gov",
        "cancel-rotation",
        "sign",
        "--kind",
        "both",
        "--key",
        pause.key.to_str().unwrap(),
        "--rpc",
        &url,
    ]);
    assert!(!bad_kind.ok);
    let bad_sig = node(&[
        "bridge-gov",
        "cancel-rotation",
        "submit",
        "--kind",
        "pq",
        "--signature",
        "0:zz",
        "--rpc",
        &url,
    ]);
    assert!(
        !bad_sig.ok && bad_sig.err.contains("the cancel signature is not hex"),
        "{}",
        bad_sig.err
    );
    let short = node(&[
        "bridge-gov",
        "cancel-rotation",
        "submit",
        "--kind",
        "pq",
        "--signature",
        "00",
        "--rpc",
        &url,
    ]);
    assert!(
        !short.ok && short.err.contains("not a Dilithium2 signature"),
        "{}",
        short.err
    );
}

#[test]
fn a_chain_without_a_bridge_or_without_rotation_rules_has_no_rotations() {
    let dir = tempfile::tempdir().unwrap();
    let (g0, new0) = (signer(dir.path(), "g0"), signer(dir.path(), "n0"));
    let (none, _) =
        chain14(|m, _| (m == "rand_getBridgeState").then(|| json!({ "enabled": false })));
    let r = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        &new0.public,
        "--rpc",
        &none,
    ]);
    assert!(
        !r.ok && r.err.contains("this chain has no bridge"),
        "{}",
        r.err
    );
    let (v1, _) = bridge_node(&[&g0], None, 0, false, false);
    let r = node(&[
        "bridge-gov",
        "rotate-pq",
        "message",
        "--new-key",
        &new0.public,
        "--rpc",
        &v1,
    ]);
    assert!(
        !r.ok
            && r.err
                .contains("this chain has no bridge rules v2: it has no rotations"),
        "{}",
        r.err
    );
}
