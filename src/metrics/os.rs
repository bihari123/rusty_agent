use crate::utils::MyError;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs;

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_os_name() -> Result<String, MyError> {
    if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
        let mut os_name = None;
        for line in os_release.lines() {
            if line.starts_with("PRETTY_NAME=") {
                // Remove quotes and get the value after '='
                os_name = Some(
                    line.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string(),
                );
                break;
            }
        }

        if let Some(name) = os_name {
            Ok(name)
        } else {
            Err(MyError {
                message: "Operating System Name not found in /etc/os-release.".to_string(),
            })
        }
    } else {
        Err(MyError {
            message: "Failed to read /etc/os-release.".to_string(),
        })
    }
}

#[cfg(target_os = "windows")]
pub fn get_os_name() -> Result<String, MyError> {
    let output = match Command::new("powershell")
        .arg("systeminfo")
        .arg("|")
        .arg("find")
        .arg("\"OS Name\"")
        .output()
    {
        Ok(output) => output.stdout,
        Err(err) => {
            return Err(MyError::new(format!(
                "Cannot get kernel version due to: {err}"
            )))
        }
    };

    let os_name = String::from_utf8_lossy(&output);

    Ok(os_name.trim().to_string())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_kernel_version() -> Result<String, MyError> {
    if let Ok(kernel_version) = fs::read_to_string("/proc/version") {
        let mut version = None;
        if let Some(index) = kernel_version.find("version ") {
            let version_str = &kernel_version[index + "version ".len()..].trim();
            version = Some((*version_str).to_string());
        }

        if let Some(kernel) = version {
            Ok(kernel)
        } else {
            Err(MyError {
                message: "Kernel version not found in /proc/version.".to_string(),
            })
        }
    } else {
        Err(MyError {
            message: "Failed to read /proc/version.".to_string(),
        })
    }
}

#[cfg(target_os = "windows")]
pub fn get_kernel_version() -> Result<String, MyError> {
    let output = match Command::new("powershell")
        .arg("systeminfo")
        .arg("|")
        .arg("find")
        .arg("\"Kernel\"")
        .output()
    {
        Ok(output) => output.stdout,
        Err(err) => {
            return Err(MyError::new(format!(
                "Cannot get kernel version due to: {err}"
            )))
        }
    };

    let kernel_version = String::from_utf8_lossy(&output);

    Ok(kernel_version.trim().to_string())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_os_version() -> Result<String, MyError> {
    if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
        let mut version = None;
        for line in os_release.lines() {
            if line.starts_with("VERSION=") {
                // Remove quotes and get the value after '='
                version = Some(
                    line.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string(),
                );
                break;
            }
        }

        if let Some(os_version) = version {
            Ok(os_version)
        } else {
            Err(MyError {
                message: "Operating System Version not found in /etc/os-release.".to_string(),
            })
        }
    } else {
        Err(MyError {
            message: "Failed to read /etc/os-release.".to_string(),
        })
    }
}

#[cfg(target_os = "windows")]
pub fn get_os_version() -> Result<String, MyError> {
    let output = match Command::new("powershell")
        .arg("(Get-ComputerInfo).WindowsVersion")
        .output()
    {
        Ok(output) => output.stdout,
        Err(err) => return Err(MyError::new(format!("Cannot fetch OS version {err}"))),
    };

    let os_version = String::from_utf8_lossy(&output);

    Ok(os_version.trim().to_string())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_host_info() -> Result<(String, String), MyError> {
    let hostname = match hostname::get_hostname() {
        Some(host) => host,
        None => return Err(MyError::new("Cannot fetch hostname".to_string())),
    };

    let ip_op = match std::process::Command::new("hostname").arg("-i").output() {
        Ok(ip) => ip.stdout,
        Err(err) => return Err(MyError::new(format!("Cannot fetch host ip: {err}"))),
    };

    let ip = String::from_utf8_lossy(&ip_op);

    Ok((hostname.trim().to_string(), ip.trim().to_string()))
}

#[cfg(target_os = "windows")]
pub fn get_host_info() -> Result<(String, String), MyError> {
    let hostname = match hostname::get_hostname() {
        Some(host) => host,
        None => return Err(MyError::new(format!("Cannot fetch hostname"))),
    };

    let ip_op = match std::process::Command::new("powershell")
        .arg("[System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName())")
        .arg("|")
        .arg("Select-Object")
        .arg("Index")
        .arg("{ 1).IPAddressToString}")
        .output()
    {
        Ok(ip) => ip.stdout,
        Err(err) => return Err(MyError::new(format!("Cannot fetch host ip: {err}"))),
    };

    let ip = String::from_utf8_lossy(&ip_op);

    Ok((hostname.trim().to_string(), ip.trim().to_string()))
}

pub fn get_install_dir() -> String {
    std::env::current_dir()
        .unwrap_or_default()
        .parent()
        .and_then(|stem| stem.to_str()).map(std::string::ToString::to_string)
        .unwrap_or_default()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_rust_install_path() -> Result<String, MyError> {
    let uname = match std::process::Command::new("whoami").output() {
        Ok(host) => host.stdout,
        Err(err) => return Err(MyError::new(format!("Cannot fetch username: {err}"))),
    };

    let uname = String::from_utf8_lossy(&uname);
    Ok(format!("/home/{}/.cargo/bin/", uname.trim()))
}

#[cfg(target_os = "windows")]
pub fn get_rust_install_path() -> Result<String, MyError> {
    let uname = match Command::new("cmd")
        .args(&["/C", "echo %USERPROFILE%"])
        .output()
    {
        Ok(host) => host.stdout,
        Err(err) => return Err(MyError::new(format!("Cannot fetch username: {err}"))),
    };

    let uname = String::from_utf8_lossy(&uname);

    Ok(format!("{}/.cargo/bin/", uname.trim()))
}
