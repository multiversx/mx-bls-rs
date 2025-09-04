use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use mx_bls_rs::{SecretKey, G1, G2};

const N: usize = 128;

fn signing(c: &mut Criterion) {
    let mut secret_key = SecretKey::default();
    secret_key.set_by_csprng();

    let msg = "abc".as_bytes();
    let public_key = secret_key.get_public_key();
    let sign = secret_key.sign(msg);

    let mut group = c.benchmark_group("signing");
    group.bench_function("Create a Signature", |b| {
        b.iter(|| {
            black_box(secret_key.sign(msg));
        })
    });

    group.bench_function("Verify a Signature", |b| {
        b.iter(|| {
            black_box(sign.verify(public_key, msg));
        })
    });

    group.sample_size(10);
    group.finish();
}

fn compression(c: &mut Criterion) {
    let mut secret_key = SecretKey::default();
    secret_key.set_by_csprng();

    let msg = "abc".as_bytes();
    let sign = secret_key.sign(msg);

    let mut group = c.benchmark_group("compression");
    group.bench_function("Serialize a Signature", |b| {
        b.iter(|| {
            black_box(sign.serialize().unwrap());
        })
    });

    let s = sign.serialize().unwrap();
    group.bench_function("Decompress a Signature", |b| {
        b.iter(|| {
            black_box(G1::from_serialized(&s).unwrap());
        })
    });

    group.sample_size(10);
    group.finish();
}

fn aggregation(c: &mut Criterion) {
    let mut secret_key = SecretKey::default();
    secret_key.set_by_csprng();

    let public_key = secret_key.get_public_key();
    let msg = "hello".as_bytes();
    let signature = secret_key.sign(msg);
    assert!(signature.verify(public_key, msg));

    let mut public_keys = [G2::default(); N];
    let mut signatures = [G1::default(); N];

    let mut msgs: Vec<u8> = vec![0; 32 * N];
    for i in 0..N {
        secret_key.set_by_csprng();
        public_keys[i] = secret_key.get_public_key();
        msgs[32 * i] = i as u8;
        signatures[i] = secret_key.sign(&msgs[32 * i..32 * (i + 1)]);
    }

    let mut agg_sig = signatures[0];
    let mut agg_pub = public_keys[0];
    for i in 1..N {
        agg_sig.add_assign(signatures[i]);
        agg_pub.add_assign(public_keys[i]);
    }

    let mut tmp_agg_sig = signatures[0];

    let mut group = c.benchmark_group("aggregation");
    group.bench_function("Aggregate 128 Signatures", |b| {
        b.iter(|| {
            {
                for signature in signatures.iter().take(N).skip(1) {
                    tmp_agg_sig.add_assign(*signature);
                }
            };
            black_box(());
        })
    });

    let mut tmp_agg_pub = public_keys[0];
    group.bench_function("Aggregate 128 Public Keys", |b| {
        b.iter(|| {
            {
                for public_key in public_keys.iter().take(N).skip(1) {
                    tmp_agg_pub.add_assign(*public_key)
                }
            };
            black_box(());
        })
    });

    group.bench_function("Verify 128 Public Keys and 128 Messages", |b| {
        b.iter(|| {
            black_box(agg_sig.fast_aggregate_verify(&public_keys, &msgs));
        })
    });

    group.sample_size(10);
    group.finish();
}

criterion_group!(benches, signing, compression, aggregation);
criterion_main!(benches);
