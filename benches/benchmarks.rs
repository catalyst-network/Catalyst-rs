#[macro_use]
extern crate criterion;
extern crate catalystffi;

use criterion::Criterion;
use criterion::black_box;

use catalystffi::ffi;
use catalystffi::constants;
use catalystffi::keys;

pub fn sign_benchmark(c: &mut Criterion) {

    let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];

    let mut private_key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
    keys::generate_key(&mut private_key).unwrap();

    let mut public_key: [u8;constants::PUBLIC_KEY_LENGTH] = [0;constants::PUBLIC_KEY_LENGTH];

    let message = String::from("Message 1 2 3");
    let context = String::from("Context 1 2 3");
    c.bench_function("sign ed25519ph", |b| b.iter(|| ffi::std_sign(
        black_box(&mut out_sig), 
        black_box(&mut public_key),
        black_box(&private_key), 
        black_box(message.as_ptr()), 
        black_box(message.len()), 
        black_box(context.as_ptr()), 
        black_box(context.len())))
    );
}

pub fn verify_benchmark(c: &mut Criterion) {

    let mut sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];

    let mut private_key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
    keys::generate_key(&mut private_key).unwrap();

    let mut public_key: [u8;constants::PUBLIC_KEY_LENGTH] = [0;constants::PUBLIC_KEY_LENGTH];

    let message = String::from("Message 1 2 3");
    let context = String::from("Context 1 2 3");

    ffi::std_sign(&mut sig, &mut public_key, &private_key, message.as_ptr(), message.len(), context.as_ptr(), context.len()); 
    keys::publickey_from_private(&mut public_key, &private_key).unwrap();

    let mut is_verified: [u8;1] = [0;1];

    c.bench_function("verify ed25519ph", |b| b.iter(|| ffi::std_verify(
        black_box(&mut sig), 
        black_box(&public_key), 
        black_box(message.as_ptr()), 
        black_box(message.len()), 
        black_box(context.as_ptr()), 
        black_box(context.len()),
        black_box(&mut is_verified)))
    );
}

criterion_group!(benchmarks, sign_benchmark, verify_benchmark);
criterion_main!(benchmarks);