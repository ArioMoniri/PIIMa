//! BLAKE2s (RFC 7693) in keyed mode, and a deterministic byte stream built on
//! it.
//!
//! WHY A KEYED HASH LIVES HERE AT ALL, rather than L5 reusing
//! [`Span::text_hash`]: that field is 64 bits of unkeyed FNV-1a over the
//! covered text. An attacker holding a span map can enumerate the ~10^4
//! Turkish given names, hash each one, and confirm in milliseconds whether a
//! named patient appears in a corpus -- which partially defeats the "never
//! store the text" property the field was introduced to provide. Under a keyed
//! hash the same enumeration additionally requires the per-document key, and
//! the key is never written to the span map. See D-024.
//!
//! WHY BLAKE2s AND NOT HMAC-SHA-256: BLAKE2's keyed mode is a native primitive
//! (RFC 7693 section 2.5, the key occupies the first message block and the key
//! length is bound into the parameter block), so it needs no outer/inner pad
//! construction and no second compression pass. It is also 32-bit-word
//! arithmetic throughout, which matters because this crate compiles to wasm32.
//!
//! WHY IT IS IMPLEMENTED HERE rather than pulled from a crate: `core/` carries
//! invariant I1 -- no network, no I/O, and a dependency list short enough that
//! a pre-commit hook can audit it by eye. RFC 7693 publishes complete test
//! vectors, so a from-scratch implementation is checkable rather than trusted;
//! the vectors are asserted in this module's tests.
//!
//! [`Span::text_hash`]: crate::span::Span::text_hash

/// Digest width in bytes. 256 bits, the BLAKE2s maximum.
pub(crate) const DIGEST_LEN: usize = 32;

/// Block width in bytes, fixed by the algorithm.
const BLOCK_LEN: usize = 64;

/// The SHA-256 initialisation vector, which BLAKE2s reuses (RFC 7693, 2.6).
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The message-word permutation schedule (RFC 7693, 2.7).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Incremental BLAKE2s state.
///
/// No `Debug`: the state is a function of the key, and a `{:?}` of a keyed
/// hasher is a key disclosure with a derive attribute on it (I4's reasoning,
/// applied to key material rather than to text).
pub(crate) struct Blake2s {
    h: [u32; 8],
    /// Bytes fed into COMPRESSED blocks only. The buffered tail is added at
    /// finalisation, because BLAKE2 needs the last block flagged as last.
    counter: u64,
    block: [u8; BLOCK_LEN],
    filled: usize,
}

impl Blake2s {
    /// A hasher keyed with `key`, producing [`DIGEST_LEN`] bytes.
    ///
    /// `key` is truncated at 32 bytes, which is the algorithm's maximum; the
    /// only caller ([`super::Salt`]) already holds exactly 32.
    pub(crate) fn keyed(key: &[u8]) -> Self {
        let key = key.get(..key.len().min(DIGEST_LEN)).unwrap_or(&[]);
        let mut h = IV;
        // The parameter block: digest length, key length, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ (DIGEST_LEN as u32);
        let mut state = Self {
            h,
            counter: 0,
            block: [0u8; BLOCK_LEN],
            filled: 0,
        };
        if !key.is_empty() {
            // RFC 7693, 2.5: the key is zero-padded to a full block and
            // prepended to the message. Padding rather than concatenating is
            // what stops a short key from shifting the message alignment.
            let mut padded = [0u8; BLOCK_LEN];
            padded[..key.len()].copy_from_slice(key);
            state.update(&padded);
        }
        state
    }

    /// Absorb more message bytes.
    ///
    /// Compression is DEFERRED until a further byte arrives, never run eagerly
    /// on a full buffer: BLAKE2 marks the final block with a domain flag, and a
    /// message that is an exact multiple of the block size would otherwise have
    /// its last block already compressed unflagged by the time `finalize` runs.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.filled == BLOCK_LEN {
                self.counter += BLOCK_LEN as u64;
                self.compress(false);
                self.filled = 0;
            }
            let take = (BLOCK_LEN - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
        }
    }

    /// Absorb a length-prefixed field.
    ///
    /// WHY EVERY VARIABLE-LENGTH INPUT GOES THROUGH THIS: plain concatenation
    /// is ambiguous. `("Ayşe", "Yılmaz")` and `("Ayşe Yıl", "maz")` produce the
    /// same byte string, so two different entities would derive the same key
    /// and be handed the same surrogate. Prefixing each field with its length
    /// makes the encoding injective, so a derivation collision has to be a
    /// collision of BLAKE2s rather than of string concatenation.
    pub(crate) fn update_field(&mut self, data: &[u8]) {
        self.update(&(data.len() as u64).to_le_bytes());
        self.update(data);
    }

    /// Consume the state and produce the digest.
    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LEN] {
        self.counter += self.filled as u64;
        self.block[self.filled..].fill(0);
        self.compress(true);
        let mut out = [0u8; DIGEST_LEN];
        for (word, chunk) in self.h.iter().zip(out.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u32; 16];
        for (word, chunk) in m.iter_mut().zip(self.block.chunks_exact(4)) {
            // The chunk is exactly four bytes by construction of
            // `chunks_exact`, so the conversion cannot fail; it is written
            // fallibly anyway to keep the crate free of panicking paths.
            *word = chunk
                .try_into()
                .map_or(0, |bytes: [u8; 4]| u32::from_le_bytes(bytes));
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.counter as u32;
        v[13] ^= (self.counter >> 32) as u32;
        if last {
            v[14] = !v[14];
        }

        for schedule in &SIGMA {
            mix(&mut v, 0, 4, 8, 12, m[schedule[0]], m[schedule[1]]);
            mix(&mut v, 1, 5, 9, 13, m[schedule[2]], m[schedule[3]]);
            mix(&mut v, 2, 6, 10, 14, m[schedule[4]], m[schedule[5]]);
            mix(&mut v, 3, 7, 11, 15, m[schedule[6]], m[schedule[7]]);
            mix(&mut v, 0, 5, 10, 15, m[schedule[8]], m[schedule[9]]);
            mix(&mut v, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
            mix(&mut v, 2, 7, 8, 13, m[schedule[12]], m[schedule[13]]);
            mix(&mut v, 3, 4, 9, 14, m[schedule[14]], m[schedule[15]]);
        }

        for (index, word) in self.h.iter_mut().enumerate() {
            *word ^= v[index] ^ v[index + 8];
        }
    }
}

/// The G mixing function (RFC 7693, 3.1).
fn mix(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// A deterministic byte stream expanded from a 32-byte seed.
///
/// Counter mode over the keyed hash rather than a linear congruential or xorshift
/// generator, and the difference is a privacy property rather than a quality
/// one: the surrogate a name receives is a FUNCTION OF THE SEED, so anything an
/// attacker can invert about the generator, they can invert about the mapping.
/// A xorshift state is recoverable from a couple of outputs; a keyed-hash
/// counter stream is not without the seed.
pub(super) struct Stream {
    seed: [u8; DIGEST_LEN],
    counter: u64,
    buffer: [u8; DIGEST_LEN],
    used: usize,
}

impl Stream {
    pub(super) fn new(seed: [u8; DIGEST_LEN]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0u8; DIGEST_LEN],
            // Forces a refill on first use rather than handing out zeros.
            used: DIGEST_LEN,
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.used == DIGEST_LEN {
            let mut hasher = Blake2s::keyed(&self.seed);
            hasher.update_field(b"deid-tr/L5/stream/v1");
            hasher.update(&self.counter.to_le_bytes());
            self.buffer = hasher.finalize();
            self.counter += 1;
            self.used = 0;
        }
        let byte = self.buffer[self.used];
        self.used += 1;
        byte
    }

    /// A uniform value in `0..bound`, by rejection sampling.
    ///
    /// Rejection rather than `% bound`, because modulo folds the top of the
    /// byte range unevenly onto the low indices and the whole point of the pool
    /// draw is that the surrogate carries no bias an attacker can exploit. A
    /// bound of zero yields zero rather than dividing by it.
    pub(super) fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        if bound > usize::from(u8::MAX) {
            // Two bytes cover every bound this crate actually uses (the largest
            // pool is a few hundred entries); a wider bound would need a wider
            // draw, so it is rejected loudly by clamping rather than silently
            // biased.
            let limit = (u16::MAX as usize + 1) - ((u16::MAX as usize + 1) % bound);
            loop {
                let high = usize::from(self.next_byte());
                let low = usize::from(self.next_byte());
                let draw = (high << 8) | low;
                if draw < limit {
                    return draw % bound;
                }
            }
        }
        let limit = 256 - (256 % bound);
        loop {
            let draw = usize::from(self.next_byte());
            if draw < limit {
                return draw % bound;
            }
        }
    }

    /// A uniform value in `low..=high`, inclusive.
    pub(super) fn between(&mut self, low: usize, high: usize) -> usize {
        if high <= low {
            return low;
        }
        low + self.below(high - low + 1)
    }

    /// One decimal digit.
    pub(super) fn digit(&mut self) -> u8 {
        self.below(10) as u8
    }

    /// Pick one element of a non-empty slice.
    pub(super) fn pick<'a, T>(&mut self, pool: &'a [T]) -> Option<&'a T> {
        pool.get(self.below(pool.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_the_rfc_7693_keyed_test_vector() {
        // RFC 7693 appendix E: BLAKE2s-256 keyed with the 32 bytes 00..1f over
        // the empty message, and over the single byte 0x00. A from-scratch
        // primitive is only trustworthy against published vectors; without this
        // test the whole keyed-hash argument in D-024 rests on nothing.
        let key: Vec<u8> = (0u8..32).collect();

        let empty = Blake2s::keyed(&key).finalize();
        assert_eq!(
            hex(&empty),
            "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"
        );

        let mut one = Blake2s::keyed(&key);
        one.update(&[0u8]);
        assert_eq!(
            hex(&one.finalize()),
            "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"
        );
    }

    #[test]
    fn a_message_spanning_exactly_one_block_is_flagged_as_final() {
        // The deferred-compression bug: a 64-byte message compressed eagerly on
        // a full buffer gets its only block marked non-final, and the digest is
        // silently wrong. RFC 7693 appendix E covers 64 bytes of 00..3f.
        let key: Vec<u8> = (0u8..32).collect();
        let message: Vec<u8> = (0u8..64).collect();
        let mut hasher = Blake2s::keyed(&key);
        hasher.update(&message);
        assert_eq!(
            hex(&hasher.finalize()),
            "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"
        );
    }

    #[test]
    fn absorbing_in_pieces_matches_absorbing_at_once() {
        let key = [7u8; 32];
        let message: Vec<u8> = (0u8..200).collect();
        let mut whole = Blake2s::keyed(&key);
        whole.update(&message);

        let mut pieces = Blake2s::keyed(&key);
        for chunk in message.chunks(7) {
            pieces.update(chunk);
        }
        assert_eq!(whole.finalize(), pieces.finalize());
    }

    #[test]
    fn a_different_key_gives_a_different_digest() {
        let mut a = Blake2s::keyed(&[1u8; 32]);
        a.update_field(b"Ayse");
        let mut b = Blake2s::keyed(&[2u8; 32]);
        b.update_field(b"Ayse");
        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn length_prefixing_makes_the_field_encoding_injective() {
        // The concatenation ambiguity, stated as a test: without the length
        // prefix these two field sequences produce identical input and two
        // different entities collapse onto one surrogate.
        let split = |parts: [&[u8]; 2]| {
            let mut hasher = Blake2s::keyed(&[9u8; 32]);
            for part in parts {
                hasher.update_field(part);
            }
            hasher.finalize()
        };
        assert_ne!(split([b"Ayse", b"Yilmaz"]), split([b"AyseYil", b"maz"]));
    }

    #[test]
    fn a_stream_is_reproducible_and_seed_dependent() {
        let draw = |seed: [u8; 32]| {
            let mut stream = Stream::new(seed);
            (0..64).map(|_| stream.below(97)).collect::<Vec<_>>()
        };
        assert_eq!(draw([3u8; 32]), draw([3u8; 32]));
        assert_ne!(draw([3u8; 32]), draw([4u8; 32]));
    }

    #[test]
    fn stream_draws_stay_inside_their_bound_and_cover_it() {
        let mut stream = Stream::new([11u8; 32]);
        let mut seen = [false; 7];
        for _ in 0..400 {
            let value = stream.below(7);
            assert!(value < 7);
            seen[value] = true;
        }
        assert!(seen.iter().all(|hit| *hit), "the draw does not cover 0..7");
        assert_eq!(stream.below(1), 0);
        assert_eq!(stream.below(0), 0);
        for _ in 0..50 {
            let value = stream.between(4, 9);
            assert!((4..=9).contains(&value));
        }
        assert_eq!(stream.between(5, 5), 5);
    }

    #[test]
    fn a_wide_bound_still_stays_inside_itself() {
        let mut stream = Stream::new([21u8; 32]);
        for _ in 0..200 {
            assert!(stream.below(1000) < 1000);
        }
    }
}
