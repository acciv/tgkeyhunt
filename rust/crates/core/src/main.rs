use std::env;
use std::fs;
use std::path::Path;
use std::process;

use tgkeyhunt_core::{report_json, scan_dir, scan_text, Report};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "scan" {
        eprintln!("usage: tgkeyhunt scan <file|dir>");
        process::exit(1);
    }

    let path = Path::new(&args[2]);
    let result = if path.is_dir() {
        scan_dir(path)
    } else if path.is_file() {
        match fs::read(path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let name = path.to_string_lossy().to_string();
                Ok(Report {
                    scanned_files: 1,
                    skipped_files: 0,
                    findings: scan_text(&text, &name),
                })
            }
            Err(error) => Err(format!("cannot read {}: {}", path.display(), error)),
        }
    } else {
        Err(format!("path does not exist: {}", path.display()))
    };

    match result {
        Ok(report) => println!("{}", report_json(&report)),
        Err(error) => {
            eprintln!("error: {}", error);
            process::exit(1);
        }
    }
}
