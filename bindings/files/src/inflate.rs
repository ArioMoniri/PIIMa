//! RFC 1951 DEFLATE decompression, and RFC 1950 zlib framing.
//!
//! DECOMPRESSION ONLY. There is no compressor here and there is not meant to
//! be: every container this crate writes emits its streams uncompressed (a PDF
//! stream with no `/Filter`, a zip entry with method `0`). That is a
//! deliberate asymmetry -- we must be able to read what a hospital's export
//! tool produced, but nothing forces us to produce it, and a redaction tool
//! that emits plainly-readable objects is a redaction tool whose output a
//! reviewer can audit with `strings`.
//!
//! Written out rather than taken from `miniz_oxide`/`flate2` because neither
//! is in this workspace's Cargo.lock; see the header of `Cargo.toml` for why
//! acquiring one is a release-gate problem rather than a preference.
//!
//! The decoder follows the structure of Mark Adler's reference `puff.c`:
//! canonical Huffman tables as symbol-count-per-length plus a symbol list,
//! decoded one bit at a time. It is not the fastest possible shape and does
//! not need to be -- clinical documents are kilobytes to a few megabytes, and
//! a table-driven decoder is materially harder to review.

/// A malformed compressed stream.
///
/// No variant carries stream CONTENT (I4): a DEFLATE stream inside a PDF is
/// page text, so a decoder that put the offending bytes in its error message
/// would put clinical text into a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InflateError {
    /// The bit stream ended in the middle of a symbol.
    #[error("the compressed stream ended mid-symbol")]
    Truncated,
    /// A stored block's length and its one's-complement disagree.
    #[error("a stored block's length check failed")]
    StoredLengthMismatch,
    /// Block type 3 is reserved and never valid.
    #[error("the compressed stream used the reserved block type")]
    ReservedBlockType,
    /// A code was read that the current Huffman table does not define.
    #[error("the compressed stream contained an undefined Huffman code")]
    InvalidCode,
    /// A length/literal or distance code outside the defined range.
    #[error("the compressed stream used an out-of-range length or distance code")]
    InvalidSymbol,
    /// A back-reference pointed before the start of the output.
    #[error("the compressed stream referenced output that does not exist")]
    DistanceTooFar,
    /// The zlib wrapper's two header bytes are not a DEFLATE stream.
    #[error("the stream is not zlib-wrapped DEFLATE")]
    NotZlib,
    /// Output grew past the caller's ceiling.
    ///
    /// A bound rather than a trust: a 40-byte object can declare a stream that
    /// expands to gigabytes, and a de-identification tool that a malformed
    /// input can OOM is a denial-of-service surface on a clinical machine.
    #[error("the decompressed stream exceeded the size limit")]
    TooLarge,
}

/// Ceiling on a single decompressed stream, in bytes.
///
/// 256 MiB: far above any real page content stream or `word/document.xml`, far
/// below "the machine falls over".
pub const MAX_OUTPUT: usize = 256 * 1024 * 1024;

struct BitReader<'a> {
    data: &'a [u8],
    /// Index of the next byte to load.
    byte: usize,
    /// Bits held but not yet consumed, LSB-first.
    bit_buffer: u32,
    /// How many bits `bit_buffer` currently holds.
    bit_count: u32,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte: 0,
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn bits(&mut self, want: u32) -> Result<u32, InflateError> {
        while self.bit_count < want {
            let next = *self.data.get(self.byte).ok_or(InflateError::Truncated)?;
            self.byte += 1;
            self.bit_buffer |= u32::from(next) << self.bit_count;
            self.bit_count += 8;
        }
        let value = self.bit_buffer & ((1u32 << want) - 1);
        self.bit_buffer >>= want;
        self.bit_count -= want;
        Ok(value)
    }

    fn bit(&mut self) -> Result<u32, InflateError> {
        self.bits(1)
    }

    /// Drop the partial byte and return the aligned byte position.
    fn align(&mut self) -> usize {
        let whole = self.bit_count / 8;
        self.bit_buffer = 0;
        self.bit_count = 0;
        self.byte - whole as usize
    }
}

/// A canonical Huffman table: how many symbols share each code length, and the
/// symbols themselves in canonical order.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Self {
        let mut counts = [0u16; 16];
        for &length in lengths {
            counts[usize::from(length)] += 1;
        }
        // Length 0 means "symbol unused"; it must not take a slot in the
        // canonical ordering or every code after it shifts.
        counts[0] = 0;
        let mut offsets = [0u16; 16];
        for length in 1..16 {
            offsets[length] = offsets[length - 1] + counts[length - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let slot = usize::from(offsets[usize::from(length)]);
                offsets[usize::from(length)] += 1;
                if let Some(cell) = symbols.get_mut(slot) {
                    // Truncation is impossible: `lengths` is at most 320 long
                    // in every DEFLATE table, far below u16::MAX.
                    *cell = symbol as u16;
                }
            }
        }
        Self { counts, symbols }
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, InflateError> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for length in 1..16 {
            code |= reader.bit()? as i32;
            let count = i32::from(self.counts[length]);
            if code - count < first {
                let slot = usize::try_from(index + (code - first))
                    .map_err(|_| InflateError::InvalidCode)?;
                return self
                    .symbols
                    .get(slot)
                    .copied()
                    .ok_or(InflateError::InvalidCode);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::InvalidCode)
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Decompress a raw DEFLATE stream.
///
/// # Errors
///
/// [`InflateError`] when the stream is malformed or expands past
/// [`MAX_OUTPUT`].
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, InflateError> {
    let mut reader = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = reader.bit()?;
        match reader.bits(2)? {
            0 => stored_block(&mut reader, &mut out)?,
            1 => {
                let (literals, distances) = fixed_tables();
                block(&mut reader, &literals, &distances, &mut out)?;
            }
            2 => {
                let (literals, distances) = dynamic_tables(&mut reader)?;
                block(&mut reader, &literals, &distances, &mut out)?;
            }
            _ => return Err(InflateError::ReservedBlockType),
        }
        if last == 1 {
            return Ok(out);
        }
    }
}

/// Decompress a zlib-wrapped DEFLATE stream (`/FlateDecode`'s actual framing).
///
/// Real PDFs are not consistently well-formed here, so a stream whose header
/// does not check is retried as raw DEFLATE rather than refused. That is a
/// leniency about INPUT only; nothing about the output changes.
///
/// # Errors
///
/// [`InflateError`] when neither framing decodes.
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, InflateError> {
    let (Some(&cmf), Some(&flg)) = (data.first(), data.get(1)) else {
        return Err(InflateError::NotZlib);
    };
    let header_ok = cmf & 0x0f == 8 && (u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0;
    if header_ok {
        if let Ok(out) = inflate(&data[2..]) {
            return Ok(out);
        }
    }
    inflate(data)
}

fn stored_block(reader: &mut BitReader<'_>, out: &mut Vec<u8>) -> Result<(), InflateError> {
    let start = reader.align();
    let data = reader.data;
    let read16 = |at: usize| -> Result<usize, InflateError> {
        let low = *data.get(at).ok_or(InflateError::Truncated)?;
        let high = *data.get(at + 1).ok_or(InflateError::Truncated)?;
        Ok(usize::from(low) | (usize::from(high) << 8))
    };
    let len = read16(start)?;
    let nlen = read16(start + 2)?;
    if len != (!nlen) & 0xffff {
        return Err(InflateError::StoredLengthMismatch);
    }
    let body = data
        .get(start + 4..start + 4 + len)
        .ok_or(InflateError::Truncated)?;
    push_bounded(out, body)?;
    reader.byte = start + 4 + len;
    Ok(())
}

fn push_bounded(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), InflateError> {
    if out.len() + bytes.len() > MAX_OUTPUT {
        return Err(InflateError::TooLarge);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lengths = [0u8; 288];
    for (symbol, slot) in lengths.iter_mut().enumerate() {
        *slot = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    (Huffman::new(&lengths), Huffman::new(&[5u8; 30]))
}

fn dynamic_tables(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), InflateError> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let hlit = reader.bits(5)? as usize + 257;
    let hdist = reader.bits(5)? as usize + 1;
    let hclen = reader.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::InvalidSymbol);
    }
    let mut code_lengths = [0u8; 19];
    for &slot in ORDER.iter().take(hclen) {
        code_lengths[slot] = reader.bits(3)? as u8;
    }
    let code_table = Huffman::new(&code_lengths);

    let mut lengths = vec![0u8; hlit + hdist];
    let mut index = 0usize;
    while index < lengths.len() {
        let symbol = code_table.decode(reader)?;
        match symbol {
            0..=15 => {
                lengths[index] = symbol as u8;
                index += 1;
            }
            16 => {
                let previous = index
                    .checked_sub(1)
                    .and_then(|i| lengths.get(i).copied())
                    .ok_or(InflateError::InvalidSymbol)?;
                let repeat = reader.bits(2)? as usize + 3;
                for _ in 0..repeat {
                    if index >= lengths.len() {
                        return Err(InflateError::InvalidSymbol);
                    }
                    lengths[index] = previous;
                    index += 1;
                }
            }
            17 | 18 => {
                let repeat = if symbol == 17 {
                    reader.bits(3)? as usize + 3
                } else {
                    reader.bits(7)? as usize + 11
                };
                index = index
                    .checked_add(repeat)
                    .filter(|end| *end <= lengths.len())
                    .ok_or(InflateError::InvalidSymbol)?;
            }
            _ => return Err(InflateError::InvalidSymbol),
        }
    }
    let (literal_lengths, distance_lengths) = lengths.split_at(hlit);
    Ok((
        Huffman::new(literal_lengths),
        Huffman::new(distance_lengths),
    ))
}

fn block(
    reader: &mut BitReader<'_>,
    literals: &Huffman,
    distances: &Huffman,
    out: &mut Vec<u8>,
) -> Result<(), InflateError> {
    loop {
        let symbol = literals.decode(reader)?;
        match symbol {
            0..=255 => push_bounded(out, &[symbol as u8])?,
            256 => return Ok(()),
            257..=285 => {
                let slot = usize::from(symbol) - 257;
                let extra = LENGTH_EXTRA
                    .get(slot)
                    .copied()
                    .ok_or(InflateError::InvalidSymbol)?;
                let base = LENGTH_BASE
                    .get(slot)
                    .copied()
                    .ok_or(InflateError::InvalidSymbol)?;
                let length = usize::from(base) + reader.bits(extra)? as usize;

                let distance_symbol = usize::from(distances.decode(reader)?);
                let distance_extra = DISTANCE_EXTRA
                    .get(distance_symbol)
                    .copied()
                    .ok_or(InflateError::InvalidSymbol)?;
                let distance_base = DISTANCE_BASE
                    .get(distance_symbol)
                    .copied()
                    .ok_or(InflateError::InvalidSymbol)?;
                let distance = usize::from(distance_base) + reader.bits(distance_extra)? as usize;
                if distance == 0 || distance > out.len() {
                    return Err(InflateError::DistanceTooFar);
                }
                if out.len() + length > MAX_OUTPUT {
                    return Err(InflateError::TooLarge);
                }
                // Byte at a time, because a back-reference may overlap the
                // output it is producing -- that is how DEFLATE encodes runs.
                let mut from = out.len() - distance;
                for _ in 0..length {
                    let byte = out[from];
                    out.push(byte);
                    from += 1;
                }
            }
            _ => return Err(InflateError::InvalidSymbol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `"deid"` as a stored (uncompressed) DEFLATE block: BFINAL=1, BTYPE=00.
    const STORED: &[u8] = &[0x01, 0x04, 0x00, 0xfb, 0xff, b'd', b'e', b'i', b'd'];

    #[test]
    fn a_stored_block_round_trips() {
        assert_eq!(inflate(STORED).expect("stored block"), b"deid");
    }

    #[test]
    fn a_corrupt_stored_length_is_refused_rather_than_guessed() {
        let mut broken = STORED.to_vec();
        broken[3] = 0x00;
        assert_eq!(inflate(&broken), Err(InflateError::StoredLengthMismatch));
    }

    #[test]
    fn the_reserved_block_type_is_refused() {
        // BFINAL=1, BTYPE=11 -> 0b111 in the low three bits.
        assert_eq!(inflate(&[0x07]), Err(InflateError::ReservedBlockType));
    }

    #[test]
    fn a_truncated_stream_errors_instead_of_returning_a_short_result() {
        assert_eq!(inflate(&[0x01, 0x04]), Err(InflateError::Truncated));
    }

    #[test]
    fn a_fixed_huffman_block_decodes() {
        // "aaaaa" under fixed Huffman: literal 'a', then a length-4 match at
        // distance 1. Produced by hand so the test does not need a compressor.
        // 'a' = 0x61 -> fixed code 0x30+0x61 = 0x91, 8 bits, MSB-first.
        let mut bits: Vec<u8> = Vec::new();
        let mut push = |value: u32, count: u32, msb_first: bool| {
            for i in 0..count {
                let bit = if msb_first {
                    (value >> (count - 1 - i)) & 1
                } else {
                    (value >> i) & 1
                };
                bits.push(bit as u8);
            }
        };
        push(1, 1, false); // BFINAL
        push(1, 2, false); // BTYPE = 01, fixed
        push(0x91, 8, true); // literal 'a'
        push(0x01, 7, true); // length code 257 -> length 3
        push(0x00, 5, true); // distance code 0 -> distance 1
        push(0x00, 7, true); // end of block
        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        for (index, bit) in bits.iter().enumerate() {
            bytes[index / 8] |= bit << (index % 8);
        }
        assert_eq!(inflate(&bytes).expect("fixed block"), b"aaaa");
    }

    #[test]
    fn zlib_framing_is_stripped_when_the_header_checks() {
        let mut framed = vec![0x78, 0x01];
        framed.extend_from_slice(STORED);
        assert_eq!(zlib_decompress(&framed).expect("zlib"), b"deid");
    }

    #[test]
    fn a_raw_deflate_stream_survives_the_zlib_entry_point() {
        // Producers in the wild emit `/FlateDecode` data with no zlib header.
        // Refusing it would mean refusing documents that every reader opens.
        assert_eq!(zlib_decompress(STORED).expect("raw"), b"deid");
    }

    #[test]
    fn an_empty_stream_is_not_zlib() {
        assert_eq!(zlib_decompress(&[]), Err(InflateError::NotZlib));
    }
}
