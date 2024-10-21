use std::{fs, path::Path, process::Command, sync::mpsc::Sender};
use thiserror::Error;

use crate::exec::sqlite::get_node_app_config;

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error("File IO error: {0}")]
    FileIOError(#[from] std::io::Error),
    #[error("Error: Failed to download the file. Error output: {0}")]
    DownloadFail(String),
    #[error("Error: Failed to download the cert. Error output: {0}")]
    DownloadFailCert(String),
    #[error("Error: Failed to download the key. Error output: {0}")]
    DownloadFailKey(String),
    //    #[error("Error: Curl command failed. Error output: {0}")]
    //    CurlError(String),
}

pub fn download_version(file_name: String, sender: Sender<i32>) -> Result<String, DownloadError> {
    let file_path = format!("./{file_name}");
    let path = Path::new(file_path.as_str());

    if path.exists() {
        fs::remove_file(path)?;
    }

    // 0 for download, 1 for list binaries
    match get_node_app_config(0, sender) {
        Ok((username, password, url)) => {
            let output = Command::new("curl")
                .arg("-L")
                .arg("-u")
                .arg(format!("{username}:{password}"))
                .arg(url)
                .arg("--output")
                .arg(file_name.clone())
                .output()?;

            if output.status.success() {
                Ok(format!("Downloaded bytes to '{file_name}'."))
            } else {
                let error_message = String::from_utf8_lossy(&output.stderr);
                Err(DownloadError::DownloadFail(error_message.into()))
            }
        }
        Err(e) => {
            Err(DownloadError::DownloadFail(e.to_string()))
        }
    }
}

pub fn download_cert_n_key() -> Result<(), DownloadError> {
    let certs_directory = "./certificates";
    // Specify the local file path where you want to save the response
    let path = Path::new(certs_directory);
    let key_local_path = path.join("key.pem");
    let cert_local_path = path.join("cert.pem");

    // Define the URL of the file you want to download
    let cert_url = "http://localhost:8080/certificate";
    let key_url = "http://localhost:8080/key";

    // Define the local file path where you want to save the downloaded file
    // Execute the curl command to download the file
    let output = Command::new("curl")
        .arg("-o")
        .arg(cert_local_path.clone())
        .arg(cert_url)
        .output()?;

    // Check if the curl command was successful
    if output.status.success() {
        println!(
            "File downloaded successfully and saved as {}",
            cert_local_path.to_string_lossy()
        );
    } else {
        eprintln!(
            "Failed to download cert file. Curl exited with status code {}",
            output.status
        );
        return Err(DownloadError::DownloadFailCert(output.status.to_string()));
    }

    let output = Command::new("curl")
        .arg("-o")
        .arg(key_local_path.clone())
        .arg(key_url)
        .output()?;

    // Check if the curl command was successful
    if output.status.success() {
        println!(
            "File downloaded successfully and saved as {}",
            key_local_path.to_string_lossy()
        );
    } else {
        eprintln!(
            "Failed to download key file. Curl exited with status code {}",
            output.status
        );
        return Err(DownloadError::DownloadFailKey(output.status.to_string()));
    }
    Ok(())
}
