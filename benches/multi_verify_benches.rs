extern crate criterion;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use mx_bls_rs::{SecretKey, G1, G2};

const MSG_SIZE: usize = 32;

fn make_multi_sig(n: usize, msg_size: usize) -> (Vec<G2>, Vec<G1>, Vec<u8>) {
    let mut public_keys: Vec<G2> = Vec::new();
    let mut signatures: Vec<G1> = Vec::new();
    let mut msgs: Vec<u8> = Vec::new();
    msgs.resize_with(n * msg_size, Default::default);
    for i in 0..n {
        let mut sec: SecretKey = SecretKey::default();
        sec.set_by_csprng();
        public_keys.push(sec.get_public_key());
        msgs[msg_size * i] = i as u8;
        let sig = sec.sign(&msgs[i * msg_size..(i + 1) * msg_size]);
        signatures.push(sig);
    }
    (public_keys, signatures, msgs)
}

pub fn naive_multi_verify(sigs: &[G1], pubs: &[G2], msgs: &[u8]) -> bool {
    let n = sigs.len();
    if n == 0 {
        return false;
    }
    for i in 0..n {
        if !sigs[i].verify(pubs[i], &msgs[i * MSG_SIZE..(i + 1) * MSG_SIZE]) {
            return false;
        }
    }

    true
}

fn multi_verify(c: &mut Criterion) {
    let (pubs, sigs, msgs) = make_multi_sig(400, MSG_SIZE);

    let mut group = c.benchmark_group("multi_verify");
    group.bench_function("Naive", |b| {
        b.iter(|| {
            black_box(naive_multi_verify(&sigs, &pubs, &msgs));
        })
    });

    group.sample_size(10);
    group.finish();
}

criterion_group!(benches, multi_verify);
criterion_main!(benches);
