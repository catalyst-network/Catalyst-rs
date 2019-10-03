#[macro_use]
extern crate criterion;
extern crate catalystffi;

use criterion::Criterion;
use criterion::black_box;

use catalystffi::ffi;
use catalystffi::{SecretKey, PublicKey, Signature};
use catalystffi::constants;
use catalystffi::keys;

pub fn criterion_benchmark(c: &mut Criterion) {

    let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];

    let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
    keys::generate_key(&mut key).unwrap();

    let message = String::from("You are a sacrifice article that I cut up rough now");
    let context = String::from("Context 1 2 3");
    c.bench_function("fib 20", |b| b.iter(|| ffi::std_sign(
        black_box(&mut out_sig), 
        black_box(&key), 
        black_box(message.as_ptr()), 
        black_box(message.len()), 
        black_box(context.as_ptr()), 
        black_box(context.len())))
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);