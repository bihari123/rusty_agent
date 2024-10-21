use super::cpu::get_cpu_usage;
use super::disk::get_process_disk_stats;
use super::memory::get_memory;
use super::os::{get_kernel_version, get_os_name, get_os_version};
use crate::{http::MetricResponse, utils};
use sqlite::State;
use std::process::Command;
use std::sync::mpsc::Sender;
use thiserror::Error;
use utils::encrypt::{get_database_decrypted, EncryptionError};

#[derive(Error, Debug)]
pub enum MetricInfoError {
    #[error("Error while querying sqlite: {0}")]
    SqliteError(#[from] sqlite::Error),
    #[error("Error while performing database encryption operations: {0}")]
    EncryptionError(#[from] EncryptionError),
}

pub fn get_agent_metric(sender: Sender<i32>) -> Result<MetricResponse, MetricInfoError> {
    // memory and cpu percentage
    //
    let memory_in_mb = match get_memory() {
        Ok(memory_in_kb) => (memory_in_kb / 1024) as f32,
        Err(_) => 0.0,
    };
    let cpu_usage = get_cpu_usage().unwrap_or_default();
    let (disk_usage, _) = get_process_disk_stats().unwrap_or_default();
    let up_time: u64 = 0;

    let os_name = get_os_name().unwrap_or_default();
    let kernel_version = get_kernel_version().unwrap_or_default();
    let os_version = get_os_version().unwrap_or_default();

    // Execute the rustc command with the --version flag
    let rust_version = match Command::new("rustc").arg("--version").output() {
        Ok(output) => {
            // Check if the command executed successfully
            if output.status.success() {
                // Retrieve the stdout as a string
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                // Print an error message if the command failed
                eprintln!("Failed to retrieve Rust compiler version ");
                String::from("Not Found")
            }
        }
        Err(_) => String::from("Not Found"),
    };

    let mut jobs: Vec<String> = vec![];

    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let query = "SELECT * FROM scheduled_jobs";
    let mut statement = db.conn.prepare(query)?;
    while matches!(statement.next(), Ok(State::Row)) {
        jobs.push(
            statement
                .read::<String, _>("script_name")
                .unwrap_or_else(|_| String::new()),
        );
    }

    let mut port: u16 = 0;

    let query = "SELECT * FROM server_config WHERE param_name = \'server_port\'";
    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {
        let global_value = statement
            .read::<String, _>("global_value")
            .unwrap_or_else(|_| String::new());
        let local_value = statement
            .read::<String, _>("local_value")
            .unwrap_or_else(|_| String::new());

        let final_value: String;
        if !local_value.is_empty() {
            final_value = local_value;
        } else {
            final_value = global_value;
        }

        port = final_value.parse().unwrap_or(0);
    }

    let metric = MetricResponse {
        memory: memory_in_mb,
        cpu_usage,
        rust_version,
        os_version,
        os_name,
        kernel_version,
        jobs,
        port,
        disk_usage: disk_usage as f32,
        up_time,
    };

    Ok(metric)
}
