use libc::*;
use ossl_typ::RAND_DRBG;

extern "C" {
    // Object liftetime functions
    pub fn RAND_DRBG_new(type_: c_int, flags: c_uint, parent: *mut RAND_DRBG) -> *mut RAND_DRBG;
    pub fn RAND_DRBG_instantiate(
        drbg: *mut RAND_DRBG,
        pers: *const c_uchar,
        perslen: size_t,
    ) -> c_int;
    pub fn RAND_DRBG_uninstantiate(drbg: *mut RAND_DRBG) -> c_int;
    pub fn RAND_DRBG_free(drbg: *mut RAND_DRBG);

    // Object "use" functions
    pub fn RAND_DRBG_generate(
        drbg: *mut RAND_DRBG,
        out: *mut c_uchar,
        outlen: size_t,
        prediction_resistance: c_int,
        adin: *const c_uchar,
        adinlen: size_t,
    ) -> c_int;

    pub fn RAND_DRBG_bytes(drbg: *mut RAND_DRBG, out: *mut c_uchar, outlen: size_t) -> c_int;

    pub fn RAND_DRBG_set_reseed_interval(drbg: *mut RAND_DRBG, interval: c_uint) -> c_int;
    pub fn RAND_DRBG_set_reseed_time_interval(drbg: *mut RAND_DRBG, interval: time_t) -> c_int;

    pub fn RAND_DRBG_set_callbacks(
        drbg: *mut RAND_DRBG,
        get_entropy: unsafe extern "C" fn(
            drbg: *mut RAND_DRBG,
            pout: *mut *mut c_uchar,
            entropy: c_int,
            min_len: size_t,
            max_len: size_t,
            prediction_resistance: c_int,
        ) -> size_t,
        cleanup_entropy: unsafe extern "C" fn(
            drbg: *mut RAND_DRBG,
            out: *mut c_uchar,
            outlen: size_t,
        ),
        get_nonce: unsafe extern "C" fn(
            drbg: *mut RAND_DRBG,
            pout: *mut *mut c_uchar,
            entropy: c_int,
            min_len: size_t,
            max_len: size_t,
        ) -> size_t,
        cleanup_nonce: unsafe extern "C" fn(
            drbg: *mut RAND_DRBG,
            out: *mut c_uchar,
            outlen: size_t,
        ),
    ) -> c_int;
}

extern "C" {
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;

    #[cfg(ossl111)]
    pub fn RAND_keep_random_devices_open(keep: c_int);

    pub fn RAND_status() -> c_int;
}
