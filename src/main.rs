use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use sigwarden_core::*;

fn print_help() {
    println!(
        r#"SigWarden - Cryptographic File Integrity, Anti-Ransomware Canary & Tamper Auditor

Usage:
  sigwarden baseline [dir] [--out <baseline.json>]
  sigwarden verify [dir] --baseline <baseline.json> [options]
  sigwarden canary deploy [dir]
  sigwarden canary check [dir]
  sigwarden entropy <text_string>
  sigwarden entropy --file <file_path>
  sigwarden rules
  sigwarden --help

Options:
  --baseline <path>       Baseline manifest JSON file to verify against
  --out <path>            Output path for generated baseline JSON
  --fail-on <level>       Exit code 1 if findings at or above: LOW, MEDIUM, HIGH, CRITICAL
  --json <path>           Export structured scan audit report to JSON
  --no-canary             Skip checking canary decoy tripwires
  --no-color              Disable ANSI coloring in output
  -h, --help              Show this help message
"#
    );
}

fn print_rules() {
    println!(
        r#"
Catalog of SigWarden Detection Rules:
--------------------------------------------------------------------------------------
ID      SEVERITY   CATEGORY            DESCRIPTION
--------------------------------------------------------------------------------------
SW-001  CRITICAL   RansomwareAttack    Sudden Shannon Entropy Spike into Ciphertext Realm
SW-002  HIGH       FileTampering       Cryptographic SHA-256 Digest Mismatch
SW-003  CRITICAL   CanaryTripwire      Decoy Anti-Ransomware Canary Modified or Deleted
SW-004  MEDIUM     UnauthorizedFile    Untracked / Injected File Created After Baseline
SW-005  MEDIUM     FileIntegrity       Tracked File Deleted from Target Directory
--------------------------------------------------------------------------------------
"#
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return ExitCode::SUCCESS;
    }

    let command = args[1].as_str();
    if command == "--help" || command == "-h" || command == "help" {
        print_help();
        return ExitCode::SUCCESS;
    }

    if command == "rules" {
        print_rules();
        return ExitCode::SUCCESS;
    }

    let use_color = !args.iter().any(|a| a == "--no-color");
    let reporter = Reporter::new(use_color);

    if command == "canary" {
        if args.len() < 3 {
            eprintln!("[-] Error: subcommands are 'deploy' or 'check'.");
            return ExitCode::FAILURE;
        }
        let sub = args[2].as_str();
        let target_dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
        let path = Path::new(target_dir);

        reporter.print_banner();
        if sub == "deploy" {
            match deploy_canary(path) {
                Ok(p) => {
                    println!("[+] Successfully deployed anti-ransomware canary tripwire at: {:?}", p);
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("[-] Failed to deploy canary: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        } else if sub == "check" {
            let status = verify_canary(path);
            match status {
                CanaryStatus::Intact => {
                    println!("[+] Canary tripwire is intact. No unauthorized tampering detected.");
                    return ExitCode::SUCCESS;
                }
                CanaryStatus::ModifiedOrEncrypted => {
                    eprintln!("[\x1b[1;31mCRITICAL\x1b[0m] Canary tripwire was MODIFIED or ENCRYPTED!");
                    return ExitCode::FAILURE;
                }
                CanaryStatus::Deleted => {
                    eprintln!("[\x1b[1;31mCRITICAL\x1b[0m] Canary tripwire was DELETED!");
                    return ExitCode::FAILURE;
                }
                CanaryStatus::NotInstalled => {
                    println!("[*] No canary tripwire found in directory: {:?}", path);
                    return ExitCode::SUCCESS;
                }
            }
        }
    }

    if command == "entropy" {
        if args.len() < 3 {
            eprintln!("[-] Error: provide a string or --file <path> to calculate entropy.");
            return ExitCode::FAILURE;
        }
        let data = if args[2] == "--file" && args.len() >= 4 {
            match fs::read(&args[3]) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[-] Failed to read file: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        } else {
            args[2].as_bytes().to_vec()
        };

        let ent = calculate_entropy(&data);
        let class = classify_entropy(ent);

        println!("\n[Shannon Entropy Analysis]");
        println!("  Input Size     : {} bytes", data.len());
        println!("  Shannon Entropy: {:.4} / 8.0000 bits/byte", ent);
        println!("  Classification : {}", class.as_str());
        println!();
        return ExitCode::SUCCESS;
    }

    if command == "baseline" {
        let mut target_dir = ".";
        let mut out_path = ".sigwarden-baseline.json";

        let mut i = 2;
        while i < args.len() {
            if args[i] == "--out" && i + 1 < args.len() {
                out_path = &args[i + 1];
                i += 2;
            } else if !args[i].starts_with("--") {
                target_dir = &args[i];
                i += 1;
            } else {
                i += 1;
            }
        }

        reporter.print_banner();
        println!("[*] Generating cryptographic baseline for directory: {}", target_dir);
        match Scanner::generate_baseline(Path::new(target_dir)) {
            Ok(manifest) => {
                match fs::File::create(out_path) {
                    Ok(f) => {
                        let _ = serde_json::to_writer_pretty(f, &manifest);
                        println!(
                            "[+] Baseline successfully generated: {} files, {} bytes tracked.",
                            manifest.total_files, manifest.total_bytes
                        );
                        println!("[+] Manifest saved to: {}", out_path);
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        eprintln!("[-] Failed to write baseline file: {}", e);
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] Baseline generation failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    if command == "verify" {
        let mut target_dir = ".";
        let mut baseline_path = None;
        let mut json_out = None;
        let mut fail_on = Severity::High;
        let mut check_canary = true;

        let mut i = 2;
        while i < args.len() {
            if args[i] == "--baseline" && i + 1 < args.len() {
                baseline_path = Some(args[i + 1].clone());
                i += 2;
            } else if args[i] == "--json" && i + 1 < args.len() {
                json_out = Some(args[i + 1].clone());
                i += 2;
            } else if args[i] == "--fail-on" && i + 1 < args.len() {
                fail_on = Severity::from_str(&args[i + 1]);
                i += 2;
            } else if args[i] == "--no-canary" {
                check_canary = false;
                i += 1;
            } else if !args[i].starts_with("--") {
                target_dir = &args[i];
                i += 1;
            } else {
                i += 1;
            }
        }

        let baseline_file = match baseline_path {
            Some(p) => p,
            None => {
                eprintln!("[-] Error: --baseline <path.json> is required for verification.");
                return ExitCode::FAILURE;
            }
        };

        reporter.print_banner();
        println!("[*] Loading baseline from: {}", baseline_file);
        let manifest_data = match fs::read_to_string(&baseline_file) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[-] Failed to read baseline file: {}", e);
                return ExitCode::FAILURE;
            }
        };

        let manifest: BaselineManifest = match serde_json::from_str(&manifest_data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[-] Corrupted baseline JSON format: {}", e);
                return ExitCode::FAILURE;
            }
        };

        let mut config = ScanConfig::default();
        config.check_canary = check_canary;

        println!("[*] Auditing directory '{}' against cryptographic manifest...", target_dir);
        match Scanner::verify_baseline(Path::new(target_dir), &manifest, &config) {
            Ok(report) => {
                reporter.print_report(&report);

                if let Some(json_path) = json_out {
                    if let Err(e) = reporter.export_json(&report, &json_path) {
                        eprintln!("[-] Failed to export JSON: {}", e);
                    } else {
                        println!("[+] JSON audit report exported to: {}", json_path);
                    }
                }

                // Check fail threshold
                let should_fail = report.findings.iter().any(|f| f.severity >= fail_on);
                if should_fail {
                    return ExitCode::FAILURE;
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[-] Verification error: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    print_help();
    ExitCode::SUCCESS
}
