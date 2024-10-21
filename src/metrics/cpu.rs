#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(any(target_os = "unix", target_os = "linux"))]
use std::{fs, io};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CPUError {
    #[cfg(target_os = "windows")]
    #[error("There was insufficient CPU info available.")]
    InsufficientCPUInfo,
    #[cfg(target_os = "windows")]
    #[error("Error while parsing float number: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),
    #[error("Ran into IO error while fetching CPU info: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Couldn't get string from utf-8: {0}")]
    StringFromUtf8Error(#[from] std::string::FromUtf8Error),
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[error("Error while parsing integer number: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
}

#[cfg(target_os = "windows")]
pub fn get_cpu_usage() -> Result<f32, CPUError> {
    // let _process_id = std::process::id();

    // Get CPU usage using WMIC
    let output = Command::new("wmic")
        .arg("path")
        .arg("win32_perfformatteddata_perfproc_process")
        .arg("get")
        .arg("PercentProcessorTime")
        .arg("/format:csv")
        .output()?;

    let output_str = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = output_str.split('\n').collect();
    if lines.len() >= 2 {
        let cpu_usage_str = lines[1].trim();
        let cpu_usage = cpu_usage_str.parse::<f32>()?;
        return Ok(cpu_usage);
    } else {
        return Err(CPUError::InsufficientCPUInfo);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_cpu_usage() -> Result<f32, CPUError> {
    let process_id = std::process::id();

    #[allow(unused_assignments)]
    let mut prev_cpu_total: u64 = 0;
    #[allow(unused_assignments)]
    let mut prev_cpu_process: u64 = 0;

    // Get initial CPU stats
    let initial_stats = get_process_cpu_stats(process_id)?;
    prev_cpu_total = initial_stats.0;
    prev_cpu_process = initial_stats.1;
    /*
        // Sleep for a moment to calculate CPU usage
        sleep(Duration::from_secs(1));

        // Get CPU stats after sleeping
        let current_stats = get_process_cpu_stats(process_id).expect("Failed to get current CPU stats");
        let cpu_total_diff = current_stats.0 - prev_cpu_total;
        let cpu_process_diff = current_stats.1 - prev_cpu_process;
    */
    // Calculate CPU usage percentage
    // let cpu_usage = (cpu_process_diff as f64 / cpu_total_diff as f64) * 100.0;

    let cpu_usage = (prev_cpu_process as f32 / prev_cpu_total as f32) * 100.0;
    Ok(cpu_usage)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_process_cpu_stats(process_id: u32) -> Result<(u64, u64), CPUError> {
    let stat_file = format!("/proc/{process_id}/stat");
    let stat_contents = fs::read_to_string(stat_file)?;

    let fields: Vec<&str> = stat_contents.split_whitespace().collect();
    if fields.len() < 17 {
        return Err(CPUError::IOError(io::Error::new(
            io::ErrorKind::Other,
            "Invalid /proc/<pid>/stat format",
        )));
    }
    let utime: u64 = fields[13].parse()?;
    let stime: u64 = fields[14].parse()?;
    let cutime: u64 = fields[15].parse()?;
    let cstime: u64 = fields[16].parse()?;

    let total_time = utime + stime + cutime + cstime;

    Ok((total_time, utime))
}
