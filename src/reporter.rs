use std::fs::File;
use std::io;
use crate::types::{ScanReport, Severity};

pub struct Reporter {
    pub use_color: bool,
}

impl Reporter {
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    fn color_code(&self, sev: Severity) -> &'static str {
        if !self.use_color {
            return "";
        }
        match sev {
            Severity::Critical => "\x1b[1;31m", // Bold Red
            Severity::High => "\x1b[31m",       // Red
            Severity::Medium => "\x1b[33m",     // Yellow
            Severity::Low => "\x1b[36m",        // Cyan
            Severity::Info => "\x1b[37m",       // White
        }
    }

    fn reset(&self) -> &'static str {
        if self.use_color {
            "\x1b[0m"
        } else {
            ""
        }
    }

    fn bold(&self) -> &'static str {
        if self.use_color {
            "\x1b[1m"
        } else {
            ""
        }
    }

    pub fn print_banner(&self) {
        if self.use_color {
            print!("\x1b[35m\x1b[1m");
        }
        println!(
            r#"
   ____ _      __      __               __          
  / __/(_)__ _/ /  __ / /___ __________/ /__ ___    
 _\ \ / / _ `/ _ \/ // / _ `/ __/ _  / -_) _ \   
/___//_/\_, /_//_/\_,_/\_,_/_/  \_,_/\__/_//_/   
       /___/                                     
"#
        );
        if self.use_color {
            print!("\x1b[0m");
        }
        println!(" Cryptographic File Integrity, Anti-Ransomware Canary & Tamper Auditor (Rust)");
        println!(" Zero-Alloc SHA-256 • Shannon Entropy • Canary Decoy Tripwire • Manifest Delta\n");
    }

    pub fn print_report(&self, report: &ScanReport) {
        println!("======================================================================");
        println!("{} AUDIT SUMMARY REPORT{}", self.bold(), self.reset());
        println!("----------------------------------------------------------------------");
        println!("  Target Directory : {}", report.target_directory);
        println!(
            "  Files Scanned    : {} ({} bytes)",
            report.stats.total_files_scanned, report.stats.total_bytes_scanned
        );
        println!("  Scan Duration    : {} ms", report.stats.duration_ms);
        println!(
            "  Integrity Status : {} Clean, {} Modified, {} Added, {} Deleted",
            report.stats.clean_files,
            report.stats.modified_files,
            report.stats.added_files,
            report.stats.deleted_files
        );

        if report.stats.ransomware_alerts > 0 {
            println!(
                "  Security Alarms  : {}\x1b[1;31m[CRITICAL] {} Ransomware Entropy Spike(s) Detected!\x1b[0m",
                self.bold(),
                report.stats.ransomware_alerts
            );
        }
        if report.stats.canary_alerts > 0 {
            println!(
                "  Canary Tripwires : {}\x1b[1;31m[CRITICAL] {} Canary Trap Triggered!\x1b[0m",
                self.bold(),
                report.stats.canary_alerts
            );
        }
        println!("======================================================================\n");

        if report.findings.is_empty() {
            println!(
                "{}[+] All files matched cryptographic baseline with 100% integrity. No tampering detected.{}\n",
                if self.use_color { "\x1b[32m" } else { "" },
                self.reset()
            );
            return;
        }

        println!("{}--- [ TAMPER & SECURITY FINDINGS ] -----------------------------------{}", self.bold(), self.reset());

        for (idx, f) in report.findings.iter().enumerate() {
            println!(
                "\n[{}] {}[{}] {}{} {}: {}{}",
                idx + 1,
                self.color_code(f.severity),
                f.severity.as_str(),
                self.reset(),
                self.bold(),
                f.rule_id,
                f.title,
                self.reset()
            );
            println!("    File Path: {}", f.path);
            println!("    Details  : {}", f.description);

            if let (Some(prev), Some(curr)) = (&f.previous_hash, &f.current_hash) {
                println!("    Baseline : {}", prev);
                println!("    Current  : {}", curr);
            }
            if let (Some(prev_e), Some(curr_e)) = (f.previous_entropy, f.current_entropy) {
                println!(
                    "    Entropy  : {:.3} -> {:.3} bits/byte",
                    prev_e, curr_e
                );
            }
        }
        println!();
    }

    pub fn export_json(&self, report: &ScanReport, path: &str) -> io::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, report)?;
        Ok(())
    }
}
