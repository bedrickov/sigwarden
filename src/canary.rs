use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

pub const CANARY_FILENAME: &str = ".sigwarden_canary.tripwire";
const CANARY_MAGIC_SEED: &[u8] = b"SIGWARDEN_CANARY_TRIPWIRE_V1_DO_NOT_MODIFY_0x9942FA10";

#[derive(Debug, PartialEq, Eq)]
pub enum CanaryStatus {
    Intact,
    ModifiedOrEncrypted,
    Deleted,
    NotInstalled,
}

pub fn get_canary_path(dir: &Path) -> PathBuf {
    dir.join(CANARY_FILENAME)
}

pub fn get_expected_canary_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(CANARY_MAGIC_SEED);
    let hash_bytes = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in hash_bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Deploys an anti-ransomware canary decoy file into the target directory
pub fn deploy_canary(dir: &Path) -> io::Result<PathBuf> {
    let canary_path = get_canary_path(dir);
    let mut file = fs::File::create(&canary_path)?;
    file.write_all(CANARY_MAGIC_SEED)?;
    file.flush()?;

    Ok(canary_path)
}

/// Verifies whether the canary file remains intact or was encrypted/modified
pub fn verify_canary(dir: &Path) -> CanaryStatus {
    let canary_path = get_canary_path(dir);
    if !canary_path.exists() {
        return CanaryStatus::NotInstalled;
    }

    match fs::read(&canary_path) {
        Ok(data) => {
            if data == CANARY_MAGIC_SEED {
                CanaryStatus::Intact
            } else {
                CanaryStatus::ModifiedOrEncrypted
            }
        }
        Err(_) => CanaryStatus::ModifiedOrEncrypted,
    }
}
