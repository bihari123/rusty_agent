use std::process::Command;
// use crate::utils::MyError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryInfoError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Insufficient memory usage info to fetch")]
    InsufficientMemoryUsageInfo,
    #[error("Insufficient memory info to fetch")]
    InsufficientMemoryInfo,
    #[error("Cannot parse string from utf-8 value: {0}")]
    StringFromUtfError(#[from] std::string::FromUtf8Error),
    #[error("Error while parsing int value: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_memory() -> Result<u64, MemoryInfoError> {
    let output = Command::new("ps")
        .arg("-p")
        .arg(format!("{}", std::process::id()))
        .arg("-o")
        .arg("rss,vsz")
        .output()?;

    let output_str = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = output_str.split('\n').collect();
    if lines.len() < 2 {
        return Err(MemoryInfoError::InsufficientMemoryInfo);
    }

    // The memory usage is in the second line
    let mem_usage = lines[1].split_whitespace().collect::<Vec<&str>>();
    if mem_usage.len() < 2 {
        return Err(MemoryInfoError::InsufficientMemoryUsageInfo);
    }

    let rss_kb = mem_usage[0].parse::<u64>()?;
    if let Ok(vsz_kb) = mem_usage[1].parse::<u64>() {
        // println!("Resident Set Size (RSS): {} KB", rss_kb);
        // println!("Virtual Memory Size (VSZ): {} KB", vsz_kb);

        Ok(rss_kb + vsz_kb)
    } else {
        Ok(rss_kb)
    }
}

#[cfg(target_os = "windows")]
pub fn get_memory() -> Result<u64, MemoryInfoError> {
    let output = Command::new("tasklist")
        .arg("/fi")
        .arg(format!("PID eq {}", std::process::id()))
        .arg("/fo")
        .arg("csv")
        .output()?;

    let output_str = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = output_str.lines().collect();
    if lines.len() < 2 {
        return Err(MemoryInfoError::InsufficientMemoryInfo);
    }

    // The memory usage is in the second line (CSV format)
    let columns: Vec<&str> = lines[1].split(',').collect();
    if columns.len() < 4 {
        return Err(MemoryInfoError::InsufficientMemoryUsageInfo);
    }

    let mem_kb = columns[4].trim().replace(",", "").parse::<u64>()?;
    let rss_memory = mem_kb;

    if let Ok(vsz_kb) = columns[3].trim().replace(",", "").parse::<u64>() {
        let virtual_memory = vsz_kb;
        let total_memory_usage = rss_memory + virtual_memory;
        return Ok(total_memory_usage);
    } else {
        return Ok(rss_memory);
    }
}
