//! The minimum PKZIP needed to open and rewrite an Office Open XML package.
//!
//! Reads STORED and DEFLATE entries; writes STORED only. See `Cargo.toml` for
//! why the `zip` crate is not a dependency, and `inflate.rs` for why emitting
//! uncompressed output is a feature rather than a shortcut.
//!
//! ENTRY ORDER IS PRESERVED and `[Content_Types].xml` stays first, because
//! several Office readers assume it. Nothing else about the package is
//! reordered: a redactor that also reorganises the container makes the diff
//! between "what we changed" and "what the tool churned" unreadable.

use crate::inflate::zlib_decompress;

/// A malformed or unsupported zip container.
///
/// No variant carries entry CONTENT (I4). Entry NAMES are carried: a part name
/// inside a `.docx` is `word/document.xml`, structural and author-independent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZipError {
    /// No end-of-central-directory record was found.
    #[error("the file is not a zip container")]
    NotAZip,
    /// A header ran past the end of the file.
    #[error("the zip container is truncated")]
    Truncated,
    /// A compression method other than STORED or DEFLATE.
    #[error("zip entry '{name}' uses an unsupported compression method")]
    UnsupportedMethod {
        /// The part name, e.g. `word/document.xml`.
        name: String,
    },
    /// The entry decompressed, and then did not match its recorded CRC.
    #[error("zip entry '{name}' failed its checksum")]
    ChecksumMismatch {
        /// The part name.
        name: String,
    },
    /// The entry could not be decompressed.
    #[error("zip entry '{name}' could not be decompressed")]
    Decompress {
        /// The part name.
        name: String,
    },
    /// A part name that escapes the archive root.
    ///
    /// A `..` segment in an entry name is the zip-slip path traversal, and a
    /// tool that walks a package from an untrusted hospital export must refuse
    /// it even though this crate never writes an entry to disk by its own name.
    #[error("zip entry '{name}' has an unsafe path")]
    UnsafePath {
        /// The offending part name.
        name: String,
    },
}

/// One decompressed member of the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The part name, e.g. `word/document.xml`.
    pub name: String,
    /// The decompressed bytes.
    pub data: Vec<u8>,
}

const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_CENTRAL: u32 = 0x0605_4b50;

fn u16_at(data: &[u8], at: usize) -> Result<u16, ZipError> {
    let bytes = data.get(at..at + 2).ok_or(ZipError::Truncated)?;
    Ok(u16::from(bytes[0]) | (u16::from(bytes[1]) << 8))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, ZipError> {
    let bytes = data.get(at..at + 4).ok_or(ZipError::Truncated)?;
    Ok(u32::from(bytes[0])
        | (u32::from(bytes[1]) << 8)
        | (u32::from(bytes[2]) << 16)
        | (u32::from(bytes[3]) << 24))
}

/// Read every entry in a zip container, in central-directory order.
///
/// # Errors
///
/// [`ZipError`] when the container is not a zip, is truncated, uses a
/// compression method this crate does not implement, or fails a CRC.
pub fn read(data: &[u8]) -> Result<Vec<Entry>, ZipError> {
    let eocd = find_end_of_central_directory(data).ok_or(ZipError::NotAZip)?;
    let count = usize::from(u16_at(data, eocd + 10)?);
    let mut offset = u32_at(data, eocd + 16)? as usize;

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(data, offset)? != CENTRAL_HEADER {
            return Err(ZipError::Truncated);
        }
        let method = u16_at(data, offset + 10)?;
        let crc = u32_at(data, offset + 16)?;
        let compressed_len = u32_at(data, offset + 20)? as usize;
        let name_len = usize::from(u16_at(data, offset + 28)?);
        let extra_len = usize::from(u16_at(data, offset + 30)?);
        let comment_len = usize::from(u16_at(data, offset + 32)?);
        let local_offset = u32_at(data, offset + 42)? as usize;
        let name_bytes = data
            .get(offset + 46..offset + 46 + name_len)
            .ok_or(ZipError::Truncated)?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        if name.split('/').any(|part| part == "..") || name.starts_with('/') {
            return Err(ZipError::UnsafePath { name });
        }

        if u32_at(data, local_offset)? != LOCAL_HEADER {
            return Err(ZipError::Truncated);
        }
        // The local header's own name/extra lengths are authoritative for
        // where the payload starts; the central directory's are not, and a
        // container where they disagree is exactly where a parser confusion
        // bug lives.
        let local_name_len = usize::from(u16_at(data, local_offset + 26)?);
        let local_extra_len = usize::from(u16_at(data, local_offset + 28)?);
        let start = local_offset + 30 + local_name_len + local_extra_len;
        let payload = data
            .get(start..start + compressed_len)
            .ok_or(ZipError::Truncated)?;

        let decoded = match method {
            0 => payload.to_vec(),
            8 => {
                zlib_decompress(payload).map_err(|_| ZipError::Decompress { name: name.clone() })?
            }
            _ => return Err(ZipError::UnsupportedMethod { name }),
        };
        if crc32(&decoded) != crc {
            return Err(ZipError::ChecksumMismatch { name });
        }
        entries.push(Entry {
            name,
            data: decoded,
        });
        offset += 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

/// Write entries back out as a STORED-only container.
#[must_use]
pub fn write(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for entry in entries {
        let local_offset = out.len();
        let name = entry.name.as_bytes();
        let crc = crc32(&entry.data);
        // `data` cannot exceed u32 in practice for an OOXML part; saturating
        // rather than truncating keeps a pathological input from producing a
        // header that claims a length it does not have.
        let size = u32::try_from(entry.data.len()).unwrap_or(u32::MAX);

        out.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method STORED
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(u16::try_from(name.len()).unwrap_or(u16::MAX)).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.data);

        directory.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes()); // version made by
        directory.extend_from_slice(&20u16.to_le_bytes()); // version needed
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&(u16::try_from(name.len()).unwrap_or(u16::MAX)).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes()); // extra
        directory.extend_from_slice(&0u16.to_le_bytes()); // comment
        directory.extend_from_slice(&0u16.to_le_bytes()); // disk
        directory.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        directory.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        directory
            .extend_from_slice(&(u32::try_from(local_offset).unwrap_or(u32::MAX)).to_le_bytes());
        directory.extend_from_slice(name);
    }

    let directory_offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
    let directory_size = u32::try_from(directory.len()).unwrap_or(u32::MAX);
    let count = u16::try_from(entries.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&directory);
    out.extend_from_slice(&END_OF_CENTRAL.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // directory start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

fn find_end_of_central_directory(data: &[u8]) -> Option<usize> {
    // Scanned backwards because the record is at the end and its own offset is
    // not recorded anywhere. 22 is its fixed size; the comment may follow.
    let start = data.len().checked_sub(22)?;
    (0..=start)
        .rev()
        .find(|&at| u32_at(data, at) == Ok(END_OF_CENTRAL))
}

/// CRC-32 (IEEE 802.3), computed bitwise.
///
/// No 256-entry table: the packages this touches are megabytes at most, and a
/// twelve-line function is worth more here than the speed of a table nobody
/// checks.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_published_check_value() {
        // The RFC 1952 check value for "123456789".
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_written_container_reads_back_identically() {
        let entries = vec![
            Entry {
                name: "[Content_Types].xml".to_owned(),
                data: b"<Types/>".to_vec(),
            },
            Entry {
                name: "word/document.xml".to_owned(),
                data: "<w:t>Ayşe</w:t>".as_bytes().to_vec(),
            },
        ];
        let bytes = write(&entries);
        let round_tripped = read(&bytes).expect("round trip");
        assert_eq!(round_tripped.len(), 2);
        assert_eq!(round_tripped[0].name, "[Content_Types].xml");
        assert_eq!(round_tripped[1].data, "<w:t>Ayşe</w:t>".as_bytes());
    }

    #[test]
    fn a_non_zip_is_refused_rather_than_parsed_as_an_empty_package() {
        assert_eq!(read(b"%PDF-1.7\n"), Err(ZipError::NotAZip));
    }

    #[test]
    fn a_corrupted_entry_fails_its_checksum_instead_of_yielding_wrong_bytes() {
        let entries = vec![Entry {
            name: "a.xml".to_owned(),
            data: b"hello".to_vec(),
        }];
        let mut bytes = write(&entries);
        let at = bytes
            .windows(5)
            .position(|w| w == b"hello")
            .expect("payload");
        bytes[at] = b'j';
        assert_eq!(
            read(&bytes),
            Err(ZipError::ChecksumMismatch {
                name: "a.xml".to_owned()
            })
        );
    }

    #[test]
    fn a_traversing_part_name_is_refused() {
        let entries = vec![Entry {
            name: "../../etc/passwd".to_owned(),
            data: b"x".to_vec(),
        }];
        let bytes = write(&entries);
        assert_eq!(
            read(&bytes),
            Err(ZipError::UnsafePath {
                name: "../../etc/passwd".to_owned()
            })
        );
    }
}
