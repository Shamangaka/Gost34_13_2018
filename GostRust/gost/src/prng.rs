use std::sync::atomic::{AtomicU32, Ordering};

static X: AtomicU32 = AtomicU32::new(1);

pub fn init(ix: u32) {
    X.store(ix, Ordering::Relaxed);
}

/// ISO/IEC 9899:201x p347 (http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf)
/// return (x = (1103515245 * x + 12345)) >> 16;
/// Arithmetic is modulo 2^32 (the previous version overflowed, which panics in debug builds).
pub fn rnext() -> u8 {
    let x = X
        .load(Ordering::Relaxed)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    X.store(x, Ordering::Relaxed);
    (x >> 16) as u8
}
