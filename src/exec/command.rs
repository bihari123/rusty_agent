use crate::utils::encrypt::base64_decrypt;
use crate::utils::encrypt::EncryptionError;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("The input cannot be empty")]
    EmptyInput,
    #[error("Error while encrypting command: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("Command IO error: {0}")]
    CommandIOError(#[from] std::io::Error),
    #[error("Command failed with error: {0}")]
    CommandFailed(String),
    #[error("Command blacklisted: {0}")]
    CommandBlackListed(String),
}

pub fn run_command_as_root(cmd: &str) -> Result<String, CommandError> {
    if cmd.is_empty() {
        return Err(CommandError::EmptyInput);
    }

    let cmd = base64_decrypt(cmd)?;

    if is_dangerous_command(cmd.as_str()) {
        return Err(CommandError::CommandBlackListed(cmd));
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CommandError::CommandFailed(format!("{stderr}")))
    }
}

pub fn run_bash_script(script_content: &str, async_exec: bool) -> Result<String, CommandError> {
    if script_content.is_empty() {
        return Err(CommandError::EmptyInput);
    }
    let script_content_raw = remove_undesirable_chars(script_content);
    if async_exec {
        let _proc = Command::new("bash")
            .arg("-c")
            .arg(script_content_raw.as_str())
            .spawn()?;

        Ok("Job running in the background".to_string())
    } else {
        let output = Command::new("bash")
            .arg("-c")
            .arg(script_content_raw.as_str())
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Command output:\n{stdout}");
            Ok(stdout.to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Command failed with error:\n{stderr}");
            Err(CommandError::CommandFailed(format!("{stderr}")))
        }
    }
}

pub fn run_python_script(script_content: &str, async_exec: bool) -> Result<String, CommandError> {
    if script_content.is_empty() {
        return Err(CommandError::EmptyInput);
    }

    let script_content_raw = remove_undesirable_chars(script_content);

    if async_exec {
        let _proc = Command::new("python3")
            .arg("-c")
            .arg(script_content_raw.as_str())
            .spawn()?;

        Ok(String::from("Job executing asynchronously"))
    } else {
        let output = Command::new("python3")
            .arg("-c")
            .arg(script_content_raw.as_str())
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Command output:\n{stdout}");
            Ok(stdout.to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Command failed with error:\n{stderr}");
            Err(CommandError::CommandFailed(format!("{stderr}")))
        }
    }
}

pub fn remove_undesirable_chars(src: &str) -> String {
    let mut escaped = String::with_capacity(src.len());
    for c in src.chars() {
        match c {
            '\r' => escaped += "",
            _ => escaped.push(c),
        }
    }
    escaped
}
fn is_dangerous_command(command: &str) -> bool {
    // Define a list of dangerous commands that should not be executed.
    let dangerous_commands = ["rm", "format", "delete", "shutdown", "reboot"];

    // dangerous_commands.contains(&command);

    for c in command.split_whitespace() {
        if dangerous_commands.contains(&c) {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_run_scripts() {
        let input_bash: &str = r"#!/bin/bash\n echo Hello world!";
        let mut result_bash = run_bash_script(input_bash, false);
        assert!(result_bash.is_ok());
        result_bash = run_bash_script("", false);
        assert!(result_bash.is_err());

        let input_python: &str = r"print('Hello, world!')";
        let mut result_python = run_python_script(input_python, false);
        assert!(result_python.is_ok());
        result_python = run_python_script("", false);
        assert!(result_python.is_err());

        let input_comm: &str = "ls";
        let mut result_comm = run_command_as_root(input_comm);
        assert!(result_comm.is_ok());
        result_comm = run_command_as_root("");
        assert!(result_comm.is_err());
    }
}
