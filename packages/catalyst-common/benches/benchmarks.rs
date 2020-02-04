#[macro_use] extern crate criterion;

use criterion::black_box;
use criterion::Criterion;
use catalyst_common::constants;
use catalyst_common::std_signature;
use catalyst_common::keys;




pub fn sign_benchmark(c: &mut Criterion) {
    let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
    let mut public_key: [u8; constants::PUBLIC_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
    let private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];

    let message = b"Message 1 2 3";
    let context = b"Context 1 2 3";
    c.bench_function("sign ed25519ph", |b| {
        b.iter(|| {
            std_signature::sign(
                black_box(&mut sig),
                black_box(&mut public_key),
                black_box(&private_key),
                black_box(message),
                black_box(context),
            )
        })
    });
}

pub fn verify_benchmark(c: &mut Criterion) {
    let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
    let mut public_key: [u8; constants::PUBLIC_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
    let private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];

    let message = b"Message 1 2 3";
    let context = b"Context 1 2 3";

    std_signature::sign(
        &mut sig,
        &mut public_key,
        &private_key,
        message,
        context,
    );
    keys::publickey_from_private(&mut public_key, &private_key);

    c.bench_function("verify ed25519ph", |b| {
        b.iter(|| {
            std_signature::verify(
                black_box(&mut sig),
                black_box(&public_key),
                black_box(message),
                black_box(context),
            )
        })
    });
}

criterion_group!(benchmarks, sign_benchmark, verify_benchmark);
criterion_main!(benchmarks);
