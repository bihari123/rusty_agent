use crate::exec::opensearch::{
    formatted_timestamp, remove_new_line, send_agent_app_data_to_opensearch, LogLevel,
    OpenSearchAgentAppLogRequest,
};
use crate::exec::{opensearch::OpenSearchError, sqlite::Database};
use crate::metrics::os;
use crate::utils::encrypt::{get_database_decrypted, EncryptionError};
use crate::Job;
use sqlite::State;
use std::sync::mpsc::Sender;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("Error while accessing database: {0}")]
    SqliteError(#[from] sqlite::Error),
    #[error("Error while sending data to opensearch: {0}")]
    OpenSearchError(#[from] OpenSearchError),
    #[error("Error encrypting database: {0}")]
    EncryptionError(#[from] EncryptionError),
}

fn _app_log(
    db: &mut Database,
    logger_name: String,
    endpoint: Option<String>,
    job_name: Option<String>,
    level: LogLevel,
    job_index: Option<String>,
    message: String,
) -> Result<(), LoggerError> {
    #[allow(unused_assignments)]
    let mut opensearch_endpoint = String::default();
    #[allow(unused_assignments)]
    let mut opensearch_index = String::default();

    let query = format!(
        "SELECT * FROM server_config WHERE param_name = \'{}\' OR param_name = \'{}\'",
        "opensearch_domain_endpoint", "opensearch_application_log_index",
    );
    let mut statement = db.conn.prepare(query)?;
    while matches!(statement.next(), Ok(State::Row)) {
        let param_name = statement.read::<String, _>("param_name")?;
        let global_value = statement.read::<String, _>("local_value")?;
        let local_value = statement.read::<String, _>("global_value")?;

        let final_value: String;
        if !local_value.is_empty() {
            final_value = local_value;
        } else {
            final_value = global_value;
        }

        match param_name.as_str() {
            "opensearch_domain_endpoint" => opensearch_endpoint = final_value,
            "opensearch_application_log_index" => opensearch_index = final_value,
            _ => {}
        }
    }

    let log = OpenSearchAgentAppLogRequest {
        agent_id: String::new(),
        endpoint: endpoint.unwrap_or_default(),
        job_name: job_name.unwrap_or_default(),
        host_name: os::get_host_info().unwrap_or_default().0,
        level,
        logger_name,
        message: remove_new_line(message),
        timestamp: formatted_timestamp(),
    };

    let mut final_index = opensearch_index;
    if let Some(job_index) = job_index {
        if !job_index.is_empty() {
            final_index = job_index;
        }
    };

    send_agent_app_data_to_opensearch(log, opensearch_endpoint, final_index)?;

    Ok(())
}

pub struct EndpointLogs;
impl EndpointLogs {
    pub fn app_log(
        sender: Sender<i32>,
        level: LogLevel,
        endpoint: &str,
        msg: String,
    ) -> Result<(), LoggerError> {
        let (mut db, _decryptor) = get_database_decrypted(Some(sender))?;

        _app_log(
            &mut db,
            "v.kumar".to_string(),
            Some(endpoint.to_string()),
            None,
            level,
            None,
            msg,
        )?;

        Ok(())
    }
}

pub struct JobLogs;
impl JobLogs {
    pub fn app_log(
        sender: Sender<i32>,
        level: LogLevel,
        job: &Job,
        msg: String,
    ) -> Result<(), LoggerError> {
        let (mut db, _decryptor) = get_database_decrypted(Some(sender))?;

        _app_log(
            &mut db,
            "v.kumar".to_string(),
            None,
            Some(job.name.clone()),
            level,
            Some(job.opensearch_index.clone()),
            msg,
        )?;

        Ok(())
    }
}
