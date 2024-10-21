use super::command;
use super::global::GLOBAL_JOBS_HEAP;
use crate::exec::command::CommandError;
use crate::exec::sqlite::{Database, DatabaseError};
use crate::utils::encrypt::{get_database_decrypted, EncryptionError};
use crate::Job;
use serde::{Deserialize, Serialize};
use sqlite::State;
use std::collections::BinaryHeap;
use std::fmt;
use std::sync::mpsc::Sender;
use std::sync::{MutexGuard, PoisonError};
use thiserror::Error;

#[derive(Debug)]
pub enum ScriptAction {
    Delete,
    Update,
    Save,
}
impl fmt::Display for ScriptAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Delete => write!(f, "deleting"),
            Self::Update => write!(f, "updating"),
            Self::Save => write!(f, "saving"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Error while running the command: {0}")]
    CommandRunError(#[from] CommandError),
    #[error("The script type is invalid: {0}")]
    UnknownScriptType(u64),
    #[error("Error while getting lock on database: {0}")]
    DatabaseLockError(#[from] PoisonError<MutexGuard<'static, Database>>),
    #[error("Error while getting lock on database: {0}")]
    JobsHeapLockError(#[from] PoisonError<MutexGuard<'static, BinaryHeap<Job>>>),
    #[error("Error while getting the database encryption: {0}")]
    ScriptError(#[from] EncryptionError),
    #[error("Error running the sqlite query: {0}")]
    SqliteError(#[from] sqlite::Error),
    #[error("Error {action} the script {script}. Record not present.")]
    RecordNotPresent {
        action: ScriptAction,
        script: String,
    },
    #[error("Error {action} the script {script}. Record already present.")]
    RecordAlreadyPresent {
        action: ScriptAction,
        script: String,
    },
    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptRequest {
    pub script_name: String,
    pub content: String,
    pub arguments: String,
    pub cron_expression: String,
    pub script_type: u64,
    pub async_exec: bool,
    pub opensearch_index: String,
    pub opensearch_enabled: bool,
}

impl fmt::Display for ScriptRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ \n \t\"script_name\": {}\n \t\"content\":{}\n \t\"arguments\": {}\n \t\"crone_expression\":{} }}",
            self.script_name,self.content, self.arguments, self.cron_expression
        )
    }
}

pub fn run_script(request_body: ScriptRequest) -> Result<String, ScriptError> {
    let result = match request_body.script_type {
        0 => command::run_python_script(&request_body.content, request_body.async_exec)?,
        1 => command::run_bash_script(&request_body.content, request_body.async_exec)?,
        x => return Err(ScriptError::UnknownScriptType(x)),
    };
    Ok(result)
}

pub fn update_script(
    request_body: ScriptRequest,
    sender: Sender<i32>,
) -> Result<String, ScriptError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let count = db.is_present(
        "scheduled_jobs",
        "script_name",
        request_body.script_name.as_str(),
    )?;

    if count <= 0 {
        return Err(ScriptError::RecordNotPresent {
            action: ScriptAction::Update,
            script: request_body.script_name,
        });
    }

    let query = format!(
        "UPDATE scheduled_jobs SET content = \'{}\' , arguments = \'{}\' ,\
        cron_expression = \'{}\', opensearch_enabled = \'{}\', opensearch_index = \'{}\',\
        script_name = \'{}\', script_type = \'{}\' WHERE script_name =\'{}\' ",
        request_body.content.as_str(),
        request_body.arguments.as_str(),
        request_body.cron_expression,
        u64::from(request_body.opensearch_enabled),
        request_body.opensearch_index,
        request_body.script_name,
        request_body.script_type,
        request_body.script_name.as_str(),
    );

    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {}

    let query = "SELECT * FROM scheduled_jobs";
    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {}

    Ok("Script saved successfully".to_string())
}

pub fn save_script(
    request_body: ScriptRequest,
    sender: Sender<i32>,
) -> Result<String, ScriptError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let count = db.is_present(
        "scheduled_jobs",
        "script_name",
        request_body.script_name.as_str(),
    )?;
    if count > 0 {
        return Err(ScriptError::RecordAlreadyPresent {
            action: ScriptAction::Save,
            script: request_body.script_name,
        });
    }
    let opensearch_enabled = u64::from(request_body.opensearch_enabled);

    let query = format!(
        "INSERT INTO scheduled_jobs VALUES (\'{}\',?,\'{}\',\'{}\',{},\'{}\',{})",
        request_body.script_name.as_str(),
        request_body.cron_expression,
        request_body.arguments.as_str(),
        request_body.script_type,
        request_body.opensearch_index,
        opensearch_enabled,
    );

    let mut statement = db.conn.prepare(query)?;

    statement.bind((1, request_body.content.as_bytes()))?;

    while matches!(statement.next(), Ok(State::Row)) {}

    let query = "SELECT * FROM scheduled_jobs";
    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {}

    Ok("Script saved successfully".to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptDetailsRequest {
    pub script_name: String,
}

impl fmt::Display for ScriptDetailsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ \n \t\"script_name\": {}\n }}", self.script_name,)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScriptDetailsResponse {
    pub script_name: String,
    pub content: String,
    pub arguments: String,
    pub cron_expression: String,
    pub opensearch_index: String,
    pub script_type: u64,
    pub opensearch_enabled: bool,
}

impl fmt::Display for ScriptDetailsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"script_name", &self.script_name)
            .entry(&"content", &self.content)
            .entry(&"arguments", &self.arguments)
            .entry(&"cron_expression", &self.cron_expression)
            .entry(&"opensearch_index", &self.opensearch_index)
            .entry(&"script_type", &self.script_type)
            .entry(&"opensearch_enabled", &self.opensearch_enabled)
            .finish()
    }
}

pub fn delete_script(
    request_body: ScriptDetailsRequest,
    sender: Sender<i32>,
) -> Result<String, ScriptError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let count = db.is_present(
        "scheduled_jobs",
        "script_name",
        request_body.script_name.as_str(),
    )?;
    if count <= 0 {
        return Err(ScriptError::RecordNotPresent {
            action: ScriptAction::Delete,
            script: request_body.script_name,
        });
    }

    let query = format!(
        "DELETE from scheduled_jobs  WHERE script_name =\'{}\' ",
        request_body.script_name.as_str()
    );

    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {}

    let mut jobs_heap = GLOBAL_JOBS_HEAP.lock()?;

    let mut new_heap = BinaryHeap::new();

    while let Some(job) = jobs_heap.pop() {
        if job.name != request_body.script_name {
            // If the name is not "script_name", keep it in the new heap
            new_heap.push(job);
        }
        // Otherwise,skip it (effectively deleting it)
    }

    *jobs_heap = new_heap;

    Ok("Script deleted successfully".to_string())
}

pub fn get_script_details(
    request_body: ScriptDetailsRequest,
    sender: Sender<i32>,
) -> Result<ScriptDetailsResponse, ScriptError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let count = db.is_present(
        "scheduled_jobs",
        "script_name",
        request_body.script_name.as_str(),
    )?;
    if count <= 0 {
        return Err(ScriptError::RecordNotPresent {
            action: ScriptAction::Update,
            script: request_body.script_name,
        });
    }
    let query = format!(
        "SELECT * from scheduled_jobs  WHERE script_name =\'{}\' ",
        request_body.script_name.as_str()
    );

    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {
        let opensearch_enabled = statement.read::<i64, _>("opensearch_enabled")? > 0;

        return Ok(ScriptDetailsResponse {
            script_name: statement.read::<String, _>("script_name")?,
            cron_expression: statement.read::<String, _>("cron_expression")?,
            content: statement.read::<String, _>("content")?,
            arguments: statement.read::<String, _>("arguments")?,
            opensearch_index: statement.read::<String, _>("opensearch_index")?,
            script_type: statement.read::<i64, _>("script_type")? as u64,
            opensearch_enabled,
        });
    }

    Ok(ScriptDetailsResponse::default())
}

pub static HELLO_BASH: &str = r"#!/bin/bash\n echo Hello world!";

pub static HEALTH_CHECK: &str = r#"#!/bin/bash
##########################################################################
## Script      : sample-healthcheck.sh                                  ##
## Date Created: 21-Oct-2024                                            ##
## Version     : 1.1                                                    ##
## Author      : John Doe                                               ##
## Revision History:                                                    ##
## Version    DD-Mmm-YYYY    Author      Description of change          ##
## 1.0        21-Oct-2024    John Doe    Initial version                ##
## 1.1        21-Oct-2024    John Doe    Generalized storage check      ##
##########################################################################
## Usage : ./sample-healthcheck.sh <DISK/CPU/MEM>                       ##
##########################################################################

# Global Variables
usage=$1
return_code=0

# Function to check if usage is below threshold
check_threshold() {
    local usage=$1
    local threshold=$2
    if [ $(echo "$usage < $threshold" | bc -l) -eq 1 ]; then
        return_code=$((return_code + 1))
        echo "Check passed"
    else
        return_code=$((return_code - 1))
        echo "Check failed"
    fi
}

# Main
case ${usage} in
DISK)
    disk_usage=$(df -h --output=pcent / | tail -n 1 | tr -d '% ')
    echo "Disk Usage: ${disk_usage}%"
    check_threshold $disk_usage 80
    ;;
CPU)
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    echo "CPU Usage: ${cpu_usage}%"
    check_threshold $cpu_usage 80
    ;;
MEM)
    mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    echo "Memory Usage: ${mem_usage}%"
    check_threshold $mem_usage 80
    ;;
*)
    echo "Usage: $0 <DISK/CPU/MEM>"
    exit 1
    ;;
esac

# Final Result
[ $return_code -ge 0 ] && echo "Overall check passed" || echo "Overall check failed"
"#;
