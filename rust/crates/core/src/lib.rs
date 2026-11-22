//! Локальный аудит утечек токенов Telegram Bot API.
//! Никаких запросов к сети и никакой проверки ключей.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 1_000_000;
const SKIP_DIRS: [&str; 4] = [".git", "target", "node_modules", "__pycache__"];

/// Один кандидат на утекший токен. Секрет в структуру не попадает.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub bot_id: String,
    pub secret_length: usize,
    pub entropy: f64,
    pub confidence: String,
    pub reason: String,
}

/// Итог сканирования.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub findings: Vec<Finding>,
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// Энтропия Шеннона, битов на символ, с округлением до двух знаков.
pub fn entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u8, usize> = HashMap::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_insert(0) += 1;
    }
    let total = value.len() as f64;
    let mut sum = 0.0;
    for count in counts.values() {
        let p = *count as f64 / total;
        sum -= p * p.log2();
    }
    (sum * 100.0).round() / 100.0
}

fn classify(secret_length: usize, value: f64) -> (&'static str, &'static str) {
    if secret_length == 35 && value >= 4.0 {
        ("high", "exact length and high entropy")
    } else if value >= 3.5 {
        ("medium", "token-like length and entropy")
    } else {
        ("low", "weak entropy or unusual length")
    }
}

fn position(text: &str, offset: usize) -> (usize, usize) {
    let prefix = &text[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = match prefix.rfind('\n') {
        Some(index) => offset - index,
        None => offset + 1,
    };
    (line, column)
}

/// Ищет токены в тексте одного файла.
pub fn scan_text(text: &str, file: &str) -> Vec<Finding> {
    let bytes = text.as_bytes();
    let mut findings = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() || (index > 0 && is_allowed(bytes[index - 1])) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let id_length = index - start;
        if id_length < 6 || id_length > 12 || index >= bytes.len() || bytes[index] != b':' {
            continue;
        }
        let bot_id = text[start..index].to_string();
        index += 1;

        let secret_start = index;
        while index < bytes.len() && is_allowed(bytes[index]) {
            index += 1;
        }
        let secret_length = index - secret_start;
        if secret_length < 30 || secret_length > 50 {
            continue;
        }

        let secret = &text[secret_start..index];
        let value = entropy(secret);
        let (confidence, reason) = classify(secret_length, value);
        let (line, column) = position(text, start);
        findings.push(Finding {
            file: file.to_string(),
            line,
            column,
            bot_id,
            secret_length,
            entropy: value,
            confidence: confidence.to_string(),
            reason: reason.to_string(),
        });
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings
}

fn walk(root: &Path, dir: &Path, report: &mut Report) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|error| format!("cannot read {}: {}", dir.display(), error))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    paths.sort();

    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if path.is_dir() {
            if SKIP_DIRS.contains(&name) {
                continue;
            }
            walk(root, &path, report)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("cannot stat {}: {}", path.display(), error))?;
        if metadata.len() > MAX_FILE_BYTES {
            report.skipped_files += 1;
            continue;
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read {}: {}", path.display(), error))?;
        if bytes.contains(&0) {
            report.skipped_files += 1;
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        report.findings.extend(scan_text(&text, &relative));
        report.scanned_files += 1;
    }
    Ok(())
}

/// Сканирует каталог рекурсивно.
pub fn scan_dir(path: &Path) -> Result<Report, String> {
    if !path.is_dir() {
        return Err(format!("not a directory: {}", path.display()));
    }
    let mut report = Report {
        scanned_files: 0,
        skipped_files: 0,
        findings: Vec::new(),
    };
    walk(path, path, &mut report)?;
    report
        .findings
        .sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)).then(a.column.cmp(&b.column)));
    Ok(report)
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Сериализует отчёт. Полные секреты в вывод не попадают.
pub fn report_json(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"scanned_files\": {},\n", report.scanned_files));
    out.push_str(&format!("  \"skipped_files\": {},\n", report.skipped_files));
    out.push_str("  \"findings\": [");
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("\n    {\n");
        out.push_str(&format!("      \"file\": {},\n", json_string(&finding.file)));
        out.push_str(&format!("      \"line\": {},\n", finding.line));
        out.push_str(&format!("      \"column\": {},\n", finding.column));
        out.push_str(&format!("      \"bot_id\": {},\n", json_string(&finding.bot_id)));
        out.push_str(&format!("      \"secret_length\": {},\n", finding.secret_length));
        out.push_str(&format!("      \"entropy\": {:.2},\n", finding.entropy));
        out.push_str(&format!("      \"confidence\": {},\n", json_string(&finding.confidence)));
        out.push_str(&format!("      \"reason\": {}\n", json_string(&finding.reason)));
        out.push_str("    }");
    }
    if !report.findings.is_empty() {
        out.push('\n');
    }
    out.push_str("  ]\n}");
    out
}

/// C ABI: сканирует текст и возвращает JSON-отчёт.
#[no_mangle]
pub extern "C" fn th_scan_text(
    text: *const c_char,
    file: *const c_char,
    out_json: *mut *mut c_char,
    out_len: *mut c_int,
) -> c_int {
    if text.is_null() || file.is_null() || out_json.is_null() || out_len.is_null() {
        return 1;
    }
    unsafe {
        let text = match CStr::from_ptr(text).to_str() {
            Ok(value) => value,
            Err(_) => return 1,
        };
        let file = match CStr::from_ptr(file).to_str() {
            Ok(value) => value,
            Err(_) => return 1,
        };
        let report = Report {
            scanned_files: 1,
            skipped_files: 0,
            findings: scan_text(text, file),
        };
        let json = report_json(&report);
        let value = match CString::new(json) {
            Ok(value) => value,
            Err(_) => return 1,
        };
        *out_len = value.as_bytes().len() as c_int;
        *out_json = value.into_raw();
    }
    0
}

/// C ABI: освобождает строку из th_scan_text.
#[no_mangle]
pub extern "C" fn th_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    fn fake_secret() -> String {
        let mut value = String::from("FAKE");
        for i in 0..31 {
            value.push(ALPHABET[(i * 7 + 11) % ALPHABET.len()] as char);
        }
        assert_eq!(value.len(), 35);
        value
    }

    #[test]
    fn entropy_is_zero_for_repeats_and_one_for_two_symbols() {
        assert_eq!(entropy("aaaa"), 0.0);
        assert_eq!(entropy("abab"), 1.0);
        assert_eq!(entropy(""), 0.0);
    }

    #[test]
    fn classification_uses_length_and_entropy() {
        assert_eq!(classify(35, 4.2).0, "high");
        assert_eq!(classify(40, 3.6).0, "medium");
        assert_eq!(classify(35, 2.0).0, "low");
        assert_eq!(classify(35, 4.2).1, "exact length and high entropy");
    }

    #[test]
    fn scan_text_finds_candidates_with_line_and_column() {
        let secret = fake_secret();
        let text = format!(
            "prefix token=123456789:{} end\nlogin: 987654321:{}",
            secret,
            "a".repeat(35)
        );
        let findings = scan_text(&text, "examples/fixture.txt");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].bot_id, "123456789");
        assert_eq!(findings[0].secret_length, 35);
        assert_eq!(findings[0].confidence, "high");
        assert_eq!(findings[1].line, 2);
        assert_eq!(findings[1].bot_id, "987654321");
        assert_eq!(findings[1].confidence, "low");
    }

    #[test]
    fn scan_text_respects_boundaries_and_length() {
        let secret = fake_secret();
        let short_id = format!("12345:{}", secret);
        let long_secret = format!("123456789:{}{}", secret, "X".repeat(20));
        let glued = format!("x123456789:{}", secret);
        let joined = format!("{}\n{}\n{}\n123456789:{}", short_id, long_secret, glued, secret);
        let findings = scan_text(&joined, "boundaries.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn report_never_contains_the_secret() {
        let secret = fake_secret();
        let text = format!("123456789:{}", secret);
        let report = Report {
            scanned_files: 1,
            skipped_files: 0,
            findings: scan_text(&text, "fake.txt"),
        };
        let json = report_json(&report);
        assert!(!json.contains(&secret));
        assert!(json.contains("\"bot_id\": \"123456789\""));
        assert!(json.contains("\"confidence\": \"high\""));
    }

    #[test]
    fn scan_dir_skips_ignored_directories_and_sorts_results() {
        let root = std::env::temp_dir().join(format!("tgkeyhunt-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("app")).unwrap();
        fs::write(root.join(".git/config"), format!("123456789:{}", fake_secret())).unwrap();
        fs::write(root.join("app/b.txt"), format!("987654321:{}", fake_secret())).unwrap();
        fs::write(root.join("app/a.txt"), format!("123123123:{}", fake_secret())).unwrap();
        fs::write(root.join("app/binary.bin"), b"\0\0\0").unwrap();

        let report = scan_dir(&root).unwrap();
        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].file, "app/a.txt");
        assert_eq!(report.findings[1].file, "app/b.txt");
        fs::remove_dir_all(&root).unwrap();
    }
}
