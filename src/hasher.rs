use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::entropy::{accumulate_frequencies, finalize_entropy};

pub struct FileHashResult {
    pub sha256: String,
    pub size_bytes: u64,
    pub entropy: f64,
}

/// Reads a file in buffered 64KB chunks, simultaneously calculating its
/// SHA-256 cryptographic digest and Shannon entropy in a single streaming pass.
pub fn hash_and_measure_file(path: &Path) -> Result<FileHashResult, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(65536, file);

    let mut hasher = Sha256::new();
    let mut byte_counts = [0u64; 256];
    let mut buffer = [0u8; 65536];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        hasher.update(chunk);
        accumulate_frequencies(chunk, &mut byte_counts);
        total_bytes += bytes_read as u64;
    }

    let hash_bytes = hasher.finalize();
    let mut sha256_hex = String::with_capacity(64);
    for b in hash_bytes {
        use std::fmt::Write;
        let _ = write!(&mut sha256_hex, "{:02x}", b);
    }

    let entropy = finalize_entropy(&byte_counts, total_bytes);

    Ok(FileHashResult {
        sha256: sha256_hex,
        size_bytes: total_bytes,
        entropy,
    })
}
