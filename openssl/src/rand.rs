//! Utilities for secure random number generation.
//!
//! # Examples
//!
//! To generate a buffer with cryptographically strong bytes:
//!
//! ```
//! use openssl::rand::rand_bytes;
//!
//! let mut buf = [0; 256];
//! rand_bytes(&mut buf).unwrap();
//! ```
use ffi;
use libc::*;

use error::ErrorStack;
use {cvt, cvt_p};

/// Fill buffer with cryptographically strong pseudo-random bytes.
///
/// This corresponds to [`RAND_bytes`].
///
/// # Examples
///
/// To generate a buffer with cryptographically strong bytes:
///
/// ```
/// use openssl::rand::rand_bytes;
///
/// let mut buf = [0; 256];
/// rand_bytes(&mut buf).unwrap();
/// ```
///
/// [`RAND_bytes`]: https://www.openssl.org/docs/man1.1.0/crypto/RAND_bytes.html
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        assert!(buf.len() <= c_int::max_value() as usize);
        cvt(ffi::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int)).map(|_| ())
    }
}

/// Controls random device file descriptor behavior.
///
/// Requires OpenSSL 1.1.1 or newer.
///
/// This corresponds to [`RAND_keep_random_devices_open`].
///
/// [`RAND_keep_random_devices_open`]: https://www.openssl.org/docs/manmaster/man3/RAND_keep_random_devices_open.html
#[cfg(ossl111)]
pub fn keep_random_devices_open(keep: bool) {
    unsafe {
        ffi::RAND_keep_random_devices_open(keep as c_int);
    }
}

static mut ENTROPY_INPUT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

static mut NONCE: [u8; 8] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];

static mut TEST_SEED: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];

#[allow(dead_code)]
extern "C" fn get_entropy(
    drbg: *mut ffi::RAND_DRBG,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: size_t,
    max_len: size_t,
    predict_resist: c_int,
) -> size_t {
    unsafe { *pout = ENTROPY_INPUT.as_mut_ptr() };
    32
}

#[allow(dead_code)]
extern "C" fn get_nonce(
    drbg: *mut ffi::RAND_DRBG,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: size_t,
    max_len: size_t,
) -> size_t {
    unsafe { *pout = NONCE.as_mut_ptr() };
    8
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::RAND_DRBG;
    fn drop = ffi::RAND_DRBG_free;

    pub struct RandDRBG;

    pub struct RandDRBGRef;
}

impl RandDRBG {
    pub fn new() -> Result<RandDRBG, ErrorStack> {
        unsafe {
            // Initialise AES-128 CTR DRBG
            let drbg = cvt_p(ffi::RAND_DRBG_new(904, 0, std::ptr::null_mut())).map(RandDRBG)?;
            ffi::RAND_DRBG_set_reseed_interval(drbg.0, 0);
            ffi::RAND_DRBG_set_reseed_time_interval(drbg.0, 0);
            ffi::RAND_DRBG_set_callbacks(drbg.0, Some(get_entropy), None, Some(get_nonce), None);
            ffi::RAND_DRBG_instantiate(drbg.0, std::ptr::null_mut(), 0);

            return Ok(drbg);
        }
    }

    pub fn generate(&self, buf: &mut [u8]) {
        unsafe {
            ffi::RAND_DRBG_generate(self.0, buf.as_mut_ptr(), buf.len(), 0, std::ptr::null(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).unwrap();
    }
}
