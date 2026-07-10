// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rekit contributors

#[cfg(any(target_os = "linux", test))]
mod dex;
#[cfg(any(target_os = "linux", test))]
mod maps;
#[cfg(any(target_os = "linux", test))]
mod sha256;

#[cfg(target_os = "linux")]
mod linux;

use std::env;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(any(target_os = "linux", test))]
use std::fs::{self, OpenOptions};
#[cfg(any(target_os = "linux", test))]
use std::io::{self, Write};
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use dex::ImageKind;
#[cfg(target_os = "linux")]
use dex::{magic_offsets, validate_header, MAGIC_LEN, MIN_HEADER_LEN};

#[cfg(target_os = "linux")]
use linux::RemoteProcess;

const DEFAULT_OUTPUT: &str = "/data/local/tmp/rekit-dex-dump";
#[cfg(target_os = "linux")]
const SCAN_CHUNK: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const READ_FAILURE_STEP: usize = 4096;

#[derive(Debug, Eq, PartialEq)]
struct Options {
    pid: i32,
    output: PathBuf,
}

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} -p PID [-o DIRECTORY]\n\
         \n\
         Attach to a rooted Android process and dump structurally valid DEX and\n\
         CompactDex images from its readable memory mappings.\n\
         \n\
         Options:\n\
           -p, --pid PID          target process ID\n\
           -o, --output DIR       dump directory (default: {DEFAULT_OUTPUT})\n\
           -h, --help             show this help"
    )
}

fn parse_options(args: impl IntoIterator<Item = String>) -> Result<Option<Options>, String> {
    let mut args = args.into_iter();
    let program = args.next().unwrap_or_else(|| "dex-dumper".to_owned());
    let mut pid = None;
    let mut output = PathBuf::from(DEFAULT_OUTPUT);

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!("{}", usage(&program));
                return Ok(None);
            }
            "-p" | "--pid" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value\n\n{}", usage(&program)))?;
                let parsed = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid PID: {value}"))?;
                if parsed <= 0 {
                    return Err(format!("invalid PID: {value}"));
                }
                pid = Some(parsed);
            }
            "-o" | "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value\n\n{}", usage(&program)))?;
                if value.is_empty() {
                    return Err("output directory must not be empty".to_owned());
                }
                output = PathBuf::from(value);
            }
            _ => {
                return Err(format!(
                    "unknown argument: {argument}\n\n{}",
                    usage(&program)
                ))
            }
        }
    }

    let pid = pid.ok_or_else(|| format!("missing required -p PID\n\n{}", usage(&program)))?;
    Ok(Some(Options { pid, output }))
}

#[cfg(any(target_os = "linux", test))]
fn write_dump(
    output: &Path,
    kind: ImageKind,
    contents: &[u8],
    digest_hex: &str,
    sequence: usize,
) -> io::Result<(PathBuf, bool)> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::create_dir_all(output)?;
    let final_path = output.join(format!("{}-{}.dex", kind.label(), digest_hex));
    if final_path.exists() {
        return Ok((final_path, false));
    }

    let temporary = output.join(format!(".dex-dumper-{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let write_result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);

        // hard_link is an atomic, no-overwrite publication step. If a dump
        // with the same digest appeared concurrently, retain the existing one.
        match fs::hard_link(&temporary, &final_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temporary);
    Ok((final_path, write_result?))
}

#[cfg(target_os = "linux")]
fn scan_process(options: &Options) -> Result<usize, String> {
    let process = RemoteProcess::attach(options.pid).map_err(|error| {
        format!(
            "could not attach to PID {}: {error} (root and ptrace permission are required)",
            options.pid
        )
    })?;
    let regions = process
        .regions()
        .map_err(|error| format!("could not read target memory map: {error}"))?;
    if regions.is_empty() {
        return Err("target has no readable memory mappings".to_owned());
    }

    fs::create_dir_all(&options.output)
        .map_err(|error| format!("could not create {}: {error}", options.output.display()))?;

    let mut scan_buffer = vec![0u8; SCAN_CHUNK];
    let mut candidate_addresses = HashSet::<usize>::new();
    let mut content_hashes = HashSet::<[u8; 32]>::new();
    let mut dumped = 0usize;

    for region in regions {
        eprintln!(
            "scanning 0x{:x}-0x{:x} ({} KiB)",
            region.start,
            region.end,
            region.len() / 1024
        );
        let mut cursor = region.start;
        let mut overlap = Vec::<u8>::new();
        while cursor < region.end {
            let requested = (region.end - cursor).min(SCAN_CHUNK);
            let count = match process.read_some(cursor, &mut scan_buffer[..requested]) {
                Ok(0) => {
                    cursor = cursor.saturating_add(READ_FAILURE_STEP).min(region.end);
                    overlap.clear();
                    continue;
                }
                Ok(count) => count,
                Err(_) => {
                    cursor = cursor.saturating_add(READ_FAILURE_STEP).min(region.end);
                    overlap.clear();
                    continue;
                }
            };

            let combined_base = cursor.saturating_sub(overlap.len());
            let mut combined = Vec::with_capacity(overlap.len() + count);
            combined.extend_from_slice(&overlap);
            combined.extend_from_slice(&scan_buffer[..count]);

            for (relative, _kind) in magic_offsets(&combined) {
                let address = match combined_base.checked_add(relative) {
                    Some(address) => address,
                    None => continue,
                };
                if !candidate_addresses.insert(address) || !region.contains(address, MIN_HEADER_LEN)
                {
                    continue;
                }
                let header_bytes = match process.read_exact(address, MIN_HEADER_LEN) {
                    Ok(header) => header,
                    Err(_) => continue,
                };
                let header = match validate_header(&header_bytes) {
                    Ok(header) => header,
                    Err(_) => continue,
                };
                if !region.contains(address, header.file_size) {
                    continue;
                }
                let image = match process.read_exact(address, header.file_size) {
                    Ok(image) => image,
                    Err(error) => {
                        eprintln!("could not read candidate at 0x{address:x}: {error}");
                        continue;
                    }
                };

                // Revalidate the copied bytes before writing. The process is
                // stopped, but this also protects against partial/corrupt reads.
                if validate_header(&image).ok() != Some(header) {
                    continue;
                }
                let digest = sha256::digest(&image);
                if !content_hashes.insert(digest) {
                    continue;
                }
                let digest_hex = sha256::hex(&digest);
                let (path, created) =
                    write_dump(&options.output, header.kind, &image, &digest_hex, dumped)
                        .map_err(|error| format!("could not write dump: {error}"))?;
                if created {
                    dumped += 1;
                    println!(
                        "dumped {} bytes from 0x{address:x} to {}",
                        image.len(),
                        path.display()
                    );
                } else {
                    eprintln!("already exists: {}", path.display());
                }
            }

            let overlap_length = (MAGIC_LEN - 1).min(combined.len());
            overlap.clear();
            overlap.extend_from_slice(&combined[combined.len() - overlap_length..]);
            cursor = cursor.saturating_add(count);
        }
    }

    println!("completed: {dumped} unique image(s) written");
    Ok(dumped)
}

#[cfg(not(target_os = "linux"))]
fn scan_process(_options: &Options) -> Result<usize, String> {
    Err("dex-dumper must run on Android/Linux; this host build is for tests only".to_owned())
}

fn run() -> Result<(), String> {
    let Some(options) = parse_options(env::args())? else {
        return Ok(());
    };
    scan_process(&options).map(|_| ())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dex-dumper: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_pid_and_output() {
        let options = parse_options([
            "dex-dumper".to_owned(),
            "--pid".to_owned(),
            "42".to_owned(),
            "--output".to_owned(),
            "/tmp/out".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            options,
            Options {
                pid: 42,
                output: PathBuf::from("/tmp/out"),
            }
        );
    }

    #[test]
    fn rejects_missing_and_nonpositive_pid() {
        assert!(parse_options(["dex-dumper".to_owned()]).is_err());
        assert!(parse_options(["dex-dumper".to_owned(), "-p".to_owned(), "0".to_owned()]).is_err());
    }

    #[test]
    fn publishes_content_once_without_overwriting() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "rekit-dex-dumper-test-{}-{nonce}",
            std::process::id()
        ));
        let contents = b"test dex contents";
        let digest = sha256::hex(&sha256::digest(contents));

        let (path, created) = write_dump(&directory, ImageKind::Dex, contents, &digest, 0).unwrap();
        assert!(created);
        assert_eq!(fs::read(&path).unwrap(), contents);

        let (same_path, created) =
            write_dump(&directory, ImageKind::Dex, b"different", &digest, 1).unwrap();
        assert!(!created);
        assert_eq!(same_path, path);
        assert_eq!(fs::read(&path).unwrap(), contents);

        fs::remove_dir_all(directory).unwrap();
    }
}
