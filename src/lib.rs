use std::os::raw::c_char;
use std::ffi::CString;
use rand::{thread_rng, Rng};
use std::mem;

extern crate curve25519_dalek;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: usize,
}


#[repr(C)]
pub struct FFIBytes64 {    
    bytes: [u8; 64]
}

pub extern fn free_buf(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}



#[no_mangle]
pub extern "C" fn key_gen(out_key: &mut [u8;32]) {
    thread_rng().fill(out_key);
    //println!("array occupies {} bytes", mem::size_of_val(&byte_array));
}






