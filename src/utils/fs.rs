use super::MyError;
use std::{fs, path::Path};

pub fn remove_prev_certificate_and_key() -> Result<(), MyError> {
    let certs_directory = "./certificates";
    // Specify the local file path where you want to save the response
    let path = Path::new(certs_directory);

    if !path.exists() {
        if let Err(err) = fs::create_dir_all(path) {
            eprintln!(
                "Error while creating a path {} object {err}",
                path.to_string_lossy(),
            );
            return Err(MyError::new(format!(
                "Error while creating a path {} object {err}",
                path.to_string_lossy(),
            )));
        }
    } else {
        // Attempt to delete the file
        match fs::remove_file(path.join("key.pem")) {
            Ok(()) => {
                println!(
                    "File '{}' has been deleted successfully.",
                    format!("{}/key.pem", certs_directory)
                );
            }
            Err(err) => {
                eprintln!(
                    "Failed to delete file '{}': {}",
                    format!("{}/key.pem", certs_directory),
                    err
                );
                return Err(MyError::new(err.to_string()));
            }
        }

        // Attempt to delete the file
        match fs::remove_file(path.join("cert.pem")) {
            Ok(()) => {
                println!(
                    "File '{}' has been deleted successfully.",
                    format!("{}/cert.pem", certs_directory)
                );
            }
            Err(err) => {
                eprintln!(
                    "Failed to delete file '{}': {}",
                    format!("{}/cert.pem", certs_directory),
                    err
                );

                return Err(MyError::new(err.to_string()));
            }
        }
    }
    Ok(())
}
