use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    mem,
};

use mx_bls_rs::*;

fn secret_key_deserialize_hex_str(x: &str) -> SecretKey {
    SecretKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn public_key_deserialize_hex_str(x: &str) -> G2 {
    G2::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn signature_deserialize_hex_str(x: &str) -> G1 {
    G1::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn signature_serialize_to_hex_str(x: &G1) -> String {
    hex::encode(x.serialize().unwrap_or_else(|err| panic!("Error: {}", err)))
}

#[test]
fn test_are_all_msg_different() {
    assert!(are_all_msg_different("abcdefgh".as_bytes(), 2));
    assert!(!are_all_msg_different("abcdabgh".as_bytes(), 2));
}

macro_rules! serialize_test {
    ($t:ty, $x:expr) => {
        let buf = $x
            .serialize()
            .unwrap_or_else(|err| panic!("Error: {}", err));
        let mut y: $t = <$t>::default();
        assert!(y.deserialize(&buf));
        assert_eq!($x, y);

        let z = <$t>::from_serialized(&buf);
        assert_eq!($x, z.unwrap());
    };
}

#[test]
fn test_sign_serialize() {
    assert_eq!(mem::size_of::<SecretKey>(), 32);
    assert_eq!(mem::size_of::<G1>(), 48 * 3);
    assert_eq!(mem::size_of::<G2>(), 48 * 2 * 3);

    let msg = "abc".as_bytes();
    let mut sk = SecretKey::default();
    sk.set_by_csprng();
    let pk = sk.get_public_key();
    let sig = sk.sign(msg);

    assert!(sig.verify(pk, msg));
    serialize_test! {SecretKey, sk};
    serialize_test! {G2, pk};
    serialize_test! {G1, sig};
}

#[test]
fn test_aggregate() {
    let f = File::open("tests/aggregate.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sigs: Vec<G1> = Vec::new();

    for l in file.lines() {
        let line = l.unwrap();
        let elements: Vec<&str> = line.split_whitespace().collect();
        match elements[0] {
            "sig" => sigs.push(signature_deserialize_hex_str(elements[1])),
            "out" => {
                let out = signature_deserialize_hex_str(elements[1]);
                let mut agg = G1::default();
                agg.aggregate(&sigs);
                sigs.clear();
                assert_eq!(agg, out);
            }
            _ => (),
        }
    }
}

fn one_test_sign(sk_hex: &str, msg: &str, sig_hex: &str) {
    let sk = secret_key_deserialize_hex_str(sk_hex);
    let pk = sk.get_public_key();
    let msg = msg.as_bytes();
    let sig = sk.sign(msg);

    assert!(sig.verify(pk, msg));
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

#[test]
fn test_sign() {
    let f = File::open("tests/sign.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sk_hex = String::new();
    let mut msg = String::new();

    for s in file.lines() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "sec" => sk_hex = v[1].to_string(),
            "msg" => msg = v[1].to_string(),
            "out" => {
                let sig_hex = v[1].to_string();
                one_test_sign(&sk_hex, &msg, &sig_hex);
            }
            _ => (),
        }
    }
}

#[test]
fn test_fast_aggregate_verify() {
    let f = File::open("tests/fast_aggregate_verify.txt").unwrap();
    let file = BufReader::new(&f);

    let mut pubs: Vec<G2> = Vec::new();
    let mut sig = G1::default();
    let mut msg: Vec<u8> = Vec::new();

    for l in file.lines() {
        let line = l.unwrap();
        let elements: Vec<&str> = line.split_whitespace().collect();
        match elements[0] {
            "pub" => pubs.push(public_key_deserialize_hex_str(elements[1])),
            "msg" => {
                msg = elements[1].into();
            }
            "sig" => {
                let err = sig.deserialize(&hex::decode(elements[1]).unwrap());
                if !err {
                    continue;
                }
            }
            "out" => {
                let out = elements[1] == "true";
                assert_eq!(sig.fast_aggregate_verify(&pubs, &msg), out);
                pubs.clear();
            }
            _ => (),
        }
    }
}

#[test]
fn test_signature_with_dummy_key() {
    let sk = SecretKey::from_hex_str("1").unwrap();
    let sig = sk.sign("asdf".as_bytes());

    let sig_hex = "283ae6bd67b23ee056888f2b119beac4224b6bece92553913a03a8fec53b68c37fae3d9315b58468d2cdae05bf236298";
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

/// return true if `size`-byte splitted `msgs` are different each other
/// * `msgs` - an array that `size`-byte messages are concatenated
/// * `size` - length of one message
fn are_all_msg_different(msgs: &[u8], size: usize) -> bool {
    let n = msgs.len() / size;
    assert!(msgs.len() == n * size);

    let mut set = HashSet::new();
    for i in 0..n {
        let msg = &msgs[i * size..(i + 1) * size];
        if set.contains(msg) {
            return false;
        }
        set.insert(msg);
    }

    true
}
