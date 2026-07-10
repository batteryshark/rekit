// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rekit contributors

use std::fmt;

pub const MAGIC_LEN: usize = 8;
pub const MIN_HEADER_LEN: usize = 0x70;
pub const DEX_HEADER_LEN: usize = 0x70;
pub const CDEX_HEADER_LEN: usize = 0x88;
pub const MAX_IMAGE_LEN: usize = 1024 * 1024 * 1024;

const DEX_VERSIONS: [&[u8; 3]; 6] = [b"035", b"037", b"038", b"039", b"040", b"041"];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImageKind {
    Dex,
    CompactDex,
}

impl ImageKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::CompactDex => "cdex",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub kind: ImageKind,
    pub file_size: usize,
    pub header_size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderError(&'static str);

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, HeaderError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(HeaderError("truncated header"))?
        .try_into()
        .map_err(|_| HeaderError("truncated header"))?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn image_kind(data: &[u8]) -> Option<ImageKind> {
    let magic = data.get(..MAGIC_LEN)?;
    if magic[..4] == *b"dex\n"
        && magic[7] == 0
        && DEX_VERSIONS
            .iter()
            .any(|version| magic[4..7] == version[..])
    {
        Some(ImageKind::Dex)
    } else if magic == b"cdex001\0" {
        Some(ImageKind::CompactDex)
    } else {
        None
    }
}

fn range_fits(offset: u32, count: u32, width: u32, file_size: usize) -> bool {
    if count == 0 {
        return offset == 0;
    }
    if offset == 0 {
        return false;
    }
    let Some(length) = count.checked_mul(width) else {
        return false;
    };
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    end as usize <= file_size
}

/// Performs structural checks that are safe for decrypted, possibly modified
/// in-memory images. Checksums and signatures are intentionally not enforced:
/// runtimes and instrumentation can legitimately make them stale.
pub fn validate_header(data: &[u8]) -> Result<Header, HeaderError> {
    if data.len() < MIN_HEADER_LEN {
        return Err(HeaderError("truncated header"));
    }

    let kind = image_kind(data).ok_or(HeaderError("unsupported magic or version"))?;
    let file_size = u32_at(data, 32)? as usize;
    let header_size = u32_at(data, 36)? as usize;
    let expected_header_size = match kind {
        ImageKind::Dex => DEX_HEADER_LEN,
        ImageKind::CompactDex => CDEX_HEADER_LEN,
    };

    if header_size != expected_header_size {
        return Err(HeaderError("invalid header size"));
    }
    if file_size < header_size {
        return Err(HeaderError("file is smaller than its header"));
    }
    if file_size > MAX_IMAGE_LEN {
        return Err(HeaderError("image exceeds the safety size limit"));
    }
    if u32_at(data, 40)? != 0x1234_5678 {
        return Err(HeaderError("unsupported endian tag"));
    }

    let link_size = u32_at(data, 44)?;
    let link_off = u32_at(data, 48)?;
    if !range_fits(link_off, link_size, 1, file_size) {
        return Err(HeaderError("invalid link section bounds"));
    }

    let map_off = u32_at(data, 52)? as usize;
    if map_off < header_size || map_off.checked_add(4).map_or(true, |end| end > file_size) {
        return Err(HeaderError("invalid map offset"));
    }

    // Fixed-width identifier tables in the common DEX/CompactDex header.
    for (size_off, item_width, message) in [
        (56, 4, "invalid string-id section bounds"),
        (64, 4, "invalid type-id section bounds"),
        (72, 12, "invalid proto-id section bounds"),
        (80, 8, "invalid field-id section bounds"),
        (88, 8, "invalid method-id section bounds"),
        (96, 32, "invalid class-def section bounds"),
    ] {
        let count = u32_at(data, size_off)?;
        let offset = u32_at(data, size_off + 4)?;
        if !range_fits(offset, count, item_width, file_size) {
            return Err(HeaderError(message));
        }
    }

    let data_size = u32_at(data, 104)?;
    let data_off = u32_at(data, 108)?;
    if !range_fits(data_off, data_size, 1, file_size) {
        return Err(HeaderError("invalid data section bounds"));
    }

    Ok(Header {
        kind,
        file_size,
        header_size,
    })
}

pub fn magic_offsets(data: &[u8]) -> Vec<(usize, ImageKind)> {
    if data.len() < MAGIC_LEN {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for offset in 0..=data.len() - MAGIC_LEN {
        if let Some(kind) = image_kind(&data[offset..offset + MAGIC_LEN]) {
            matches.push((offset, kind));
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header(kind: ImageKind, file_size: usize) -> Vec<u8> {
        let header_size = match kind {
            ImageKind::Dex => DEX_HEADER_LEN,
            ImageKind::CompactDex => CDEX_HEADER_LEN,
        };
        let mut header = vec![0u8; header_size];
        header[..8].copy_from_slice(match kind {
            ImageKind::Dex => b"dex\n039\0",
            ImageKind::CompactDex => b"cdex001\0",
        });
        header[32..36].copy_from_slice(&(file_size as u32).to_le_bytes());
        header[36..40].copy_from_slice(&(header_size as u32).to_le_bytes());
        header[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        header[52..56].copy_from_slice(&(header_size as u32).to_le_bytes());
        header[104..108].copy_from_slice(&((file_size - header_size) as u32).to_le_bytes());
        header[108..112].copy_from_slice(&(header_size as u32).to_le_bytes());
        header
    }

    #[test]
    fn accepts_structurally_valid_dex() {
        let header = valid_header(ImageKind::Dex, 0x400);
        assert_eq!(
            validate_header(&header),
            Ok(Header {
                kind: ImageKind::Dex,
                file_size: 0x400,
                header_size: DEX_HEADER_LEN,
            })
        );
    }

    #[test]
    fn accepts_structurally_valid_compact_dex() {
        let header = valid_header(ImageKind::CompactDex, 0x500);
        assert_eq!(
            validate_header(&header).unwrap().kind,
            ImageKind::CompactDex
        );
    }

    #[test]
    fn rejects_unsupported_versions_and_impossible_bounds() {
        let mut header = valid_header(ImageKind::Dex, 0x400);
        header[4..7].copy_from_slice(b"999");
        assert_eq!(
            validate_header(&header).unwrap_err().to_string(),
            "unsupported magic or version"
        );

        let mut header = valid_header(ImageKind::Dex, 0x400);
        header[56..60].copy_from_slice(&2u32.to_le_bytes());
        header[60..64].copy_from_slice(&0x3fcu32.to_le_bytes());
        assert_eq!(
            validate_header(&header).unwrap_err().to_string(),
            "invalid string-id section bounds"
        );
    }

    #[test]
    fn rejects_false_positive_size_fields() {
        let mut header = valid_header(ImageKind::Dex, 0x400);
        header[36..40].copy_from_slice(&0x71u32.to_le_bytes());
        assert_eq!(
            validate_header(&header).unwrap_err().to_string(),
            "invalid header size"
        );

        let mut header = valid_header(ImageKind::Dex, 0x400);
        header[32..36].copy_from_slice(&0x60u32.to_le_bytes());
        assert_eq!(
            validate_header(&header).unwrap_err().to_string(),
            "file is smaller than its header"
        );
    }

    #[test]
    fn scanner_finds_unaligned_dex_and_cdex_magic() {
        let mut bytes = vec![0xaa; 31];
        bytes.extend_from_slice(b"dex\n038\0");
        bytes.extend_from_slice(&[0xbb; 5]);
        bytes.extend_from_slice(b"cdex001\0");
        assert_eq!(
            magic_offsets(&bytes),
            vec![(31, ImageKind::Dex), (44, ImageKind::CompactDex)]
        );
    }
}
