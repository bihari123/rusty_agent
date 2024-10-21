#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs;
#[cfg(target_os = "windows")]
use std::process::Command;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiskInfoError {
    #[error("File IO error: {0}")]
    FileIOError(#[from] std::io::Error),
    #[error("Error while parsing int information: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[error("Couldn't parse disk stats properly")]
    ParseDiskStatError,
    #[error("Couldn't parse string from utf-8: {0}")]
    StringFromUtfError(#[from] std::string::FromUtf8Error),
    #[cfg(target_os = "windows")]
    #[error("Powershell command failed to run")]
    PowerShellExecutionFail,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_process_disk_stats() -> Result<(u64, u64), DiskInfoError> {
    let pid = std::process::id() as usize;
    let io_file = format!("/proc/{pid}/io");
    let io_contents = fs::read_to_string(io_file)?;

    let mut read_bytes: Option<u64> = None;
    let mut write_bytes: Option<u64> = None;

    for line in io_contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "read_bytes:" => read_bytes = Some(parts[1].parse()?),
                "write_bytes:" => write_bytes = Some(parts[1].parse()?),
                _ => (),
            }
        }
    }

    if let (Some(rb), Some(wb)) = (read_bytes, write_bytes) {
        Ok((rb, wb))
    } else {
        Err(DiskInfoError::ParseDiskStatError)
    }
}

#[cfg(target_os = "windows")]
pub fn get_process_disk_stats() -> Result<(u64, u64), DiskInfoError> {
    let process_id = std::process::id().to_string();

    // Create a PowerShell script to get disk I/O stats
    let ps_script = format!(
        "Get-Process -Id {} | ForEach-Object {{ $_.Name, (Get-Counter -Counter '\\Process({0})\\IO Read Bytes/sec' -ErrorAction SilentlyContinue).CounterSamples.CookedValue, (Get-Counter -Counter '\\Process({0})\\IO Write Bytes/sec' -ErrorAction SilentlyContinue).CounterSamples.CookedValue }}",
        process_id
    );

    // Execute the PowerShell script
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(&ps_script)
        .output()?;

    if output.status.success() {
        let output_str = String::from_utf8(output.stdout)?;

        // Initialize variables to store read_bytes and write_bytes
        let mut read_bytes: u64 = 0;
        let mut write_bytes: u64 = 0;

        // Split the PowerShell output into lines
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 3 {
                let read_str = parts[1];
                let write_str = parts[2];

                // Parse read_bytes and write_bytes as u64
                if let Ok(read_val) = read_str.parse::<u64>() {
                    read_bytes = read_val;
                }
                if let Ok(write_val) = write_str.parse::<u64>() {
                    write_bytes = write_val;
                }
            }
        }
        return Ok((read_bytes, write_bytes));
    } else {
        return Err(DiskInfoError::PowerShellExecutionFail);
    }
}
