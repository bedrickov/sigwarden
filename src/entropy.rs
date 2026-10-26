#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    ZeroOrHomogeneous,
    StructuredText,
    NativeExecutableCode,
    HighEntropyEncryptedOrPacked,
}

impl EntropyClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntropyClass::ZeroOrHomogeneous => "Homogeneous / Sparse",
            EntropyClass::StructuredText => "Structured Plaintext / Source",
            EntropyClass::NativeExecutableCode => "Native Executable Code",
            EntropyClass::HighEntropyEncryptedOrPacked => "High-Entropy Encrypted / Packed",
        }
    }
}

/// Computes Shannon entropy (0.0 to 8.0 bits/byte) from a byte slice
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy.clamp(0.0, 8.0)
}

/// Accumulates frequency counts into existing 256-element array for streaming calculation
pub fn accumulate_frequencies(chunk: &[u8], counts: &mut [u64; 256]) {
    for &b in chunk {
        counts[b as usize] += 1;
    }
}

/// Finalizes entropy calculation from accumulated frequency counts
pub fn finalize_entropy(counts: &[u64; 256], total_bytes: u64) -> f64 {
    if total_bytes == 0 {
        return 0.0;
    }

    let total = total_bytes as f64;
    let mut entropy = 0.0;

    for &count in counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy.clamp(0.0, 8.0)
}

pub fn classify_entropy(entropy: f64) -> EntropyClass {
    if entropy < 0.25 {
        EntropyClass::ZeroOrHomogeneous
    } else if entropy < 4.8 {
        EntropyClass::StructuredText
    } else if entropy < 6.85 {
        EntropyClass::NativeExecutableCode
    } else {
        EntropyClass::HighEntropyEncryptedOrPacked
    }
}

/// Checks if file entropy exhibited a classic Ransomware encryption spike
/// e.g. previously structured text or code (< 6.2) jumped to near-random ciphertext (> 7.4)
pub fn is_ransomware_spike(prev_entropy: f64, curr_entropy: f64) -> bool {
    prev_entropy < 6.2 && curr_entropy >= 7.35 && (curr_entropy - prev_entropy) >= 1.5
}
