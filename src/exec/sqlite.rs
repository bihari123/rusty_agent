use super::{config::ConfigChangeRequest, scheduled_job::Job};
use crate::utils::encrypt::{DecryptDatabase, EncryptionError};
use crate::{
    exec::{global::GLOBAL_JOBS_HEAP, script},
    http::response::{datetime_to_systemtime, time_until_next_run},
    utils::{encrypt::get_database_decrypted, encrypt_string},
};
use chrono::Local;
use sqlite::{Connection, State};
use std::collections::BinaryHeap;
use std::sync::{MutexGuard, PoisonError};
use std::{fs::File, path::Path, sync::mpsc::Sender};
use thiserror::Error;

pub struct Database {
    pub conn: Connection,
    pub filepath: String,
}
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Error while running the sqlite command: {0}")]
    SqliteError(#[from] sqlite::Error),
    #[error("Error while creating the database file: {0}")]
    FileIOError(#[from] std::io::Error),
    #[error("Error in encryption of database: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("Error while getting the jobs lock: {0}")]
    JobLockError(#[from] PoisonError<MutexGuard<'static, BinaryHeap<Job>>>),
    #[error("Error while getting the job run time: {0}")]
    JobRunError(#[from] Box<dyn std::error::Error>),
    #[error("Error while parsing an int: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Unable to update property {0}. Record not present")]
    RecordNotPresent(String),
    #[error("Unable to update property {0}. Multiple instances of record present")]
    MultipleRecords(String),
    #[error("Unable to find property {0}")]
    FieldNotFound(String),
}

impl Database {
    pub fn new(filepath: &str) -> Result<Self, DatabaseError> {
        let path = Path::new(filepath);

        let conn: Connection;
        if !path.exists() {
            File::create(path)?;
        }

        let _decryptor = DecryptDatabase::decrypt(filepath.to_string(), None)?;

        conn = Connection::open(filepath)?;

        Ok(Self {
            conn,
            filepath: filepath.to_string(),
        })
    }

    pub fn init(&self) -> Result<(), DatabaseError> {
        let _decryptor = DecryptDatabase::decrypt(self.filepath.clone(), None)?;

        self.create_table(
            "agent_version",
            &["version", "version_valid", "build_date"],
            &["TEXT", "INTEGER", "TEXT"],
        )?;

        let count = self.is_present("agent_version", "version", " ")?;
        if count == 0 {
            self.insert_record(
                "agent_version",
                &["version", "version_valid", "build_date"],
                &[" ", "0", format!("{}", Local::now()).as_str()],
            )?;
            self.insert_record(
                "agent_version",
                &["version", "version_valid", "build_date"],
                &["0.0.1", "1", format!("{}", Local::now()).as_str()],
            )?;
        }

        self.create_table(
            "server_config",
            &["param_name", "global_value", "local_value", "can_modify"],
            &["TEXT", "TEXT", "TEXT", "INTEGER"],
        )?;

        let count = self.is_present("server_config", "param_name", "ip_addr")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["ip_addr", "0.0.0.0", "0.0.0.0", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "server_port")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["server_port", "20140", "20140", "1"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "min_port")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["min_port", "20000", "20000", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "max_port")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["max_port", "21000", "21000", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "auto_upgrade")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["auto_upgrade", "1", "1", "1"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "opensearch_domain_endpoint")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &[
                    "opensearch_domain_endpoint",
                    "https://sample_aws_endpoint.us-east-1.es.amazonaws.com",
                    "https://sample_aws_endpoint.us-east-1.es.amazonaws.com",
                    "0",
                ],
            )?;
        }

        let count = self.is_present(
            "server_config",
            "param_name",
            "opensearch_application_log_index",
        )?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &[
                    "opensearch_application_log_index",
                    "rust_agent_application_logs_dev",
                    "rust_agent_application_logs_dev",
                    "0",
                ],
            )?;
        }

        let count = self.is_present(
            "server_config",
            "param_name",
            "opensearch_health_discovery_log_index",
        )?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &[
                    "opensearch_health_discovery_log_index",
                    "rust_agent_health_discovery_dev",
                    "rust_agent_health_discovery_dev",
                    "0",
                ],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "opensearch_user_name")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["opensearch_user_name", "admin", "admin", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "opensearch_user_pass")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["opensearch_user_pass", "admin", "admin", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "log_level")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["log_level", "warning", "error", "0"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "cpu_utils_limit")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["cpu_utils_limit", "20", "20", "1"],
            )?;
        }

        let count = self.is_present("server_config", "param_name", "memory_limit")?;
        if count == 0 {
            self.insert_record(
                "server_config",
                &["param_name", "global_value", "local_value", "can_modify"],
                &["memory_limit", "102400", "102400", "1"],
            )?;
        }

        let query = "SELECT * FROM server_config";
        let mut statement = self.conn.prepare(query)?;

        while matches!(statement.next(), Ok(State::Row)) {}

        self.create_table(
            "scheduled_jobs",
            &[
                "script_name",
                "content",
                "cron_expression",
                "arguments",
                "script_type",
                "opensearch_index",
                "opensearch_enabled",
            ],
            &["TEXT", "BLOB", "TEXT", "TEXT", "INTEGER", "TEXT", "INTEGER"],
        )?;

        let count = self.is_present("scheduled_jobs", "script_name", "health_check")?;
        if count == 0 {
            let query = "INSERT INTO scheduled_jobs VALUES ('health_check',?,'0 0/5 * ? * * *','FS',1,'rust_agent_application_logs_dev',1)";

            let mut statement = self.conn.prepare(query)?;
            statement.bind((1, script::HEALTH_CHECK.as_bytes()))?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }

        let count = self.is_present("scheduled_jobs", "script_name", "hello_bash")?;
        if count == 0 {
            let query =
                "INSERT INTO scheduled_jobs VALUES ('hello_bash',?,'0 0 6,14 ? * * *','',1,'rust_agent_application_logs_dev',1)";

            let mut statement = self.conn.prepare(query)?;
            statement.bind((1, script::HELLO_BASH.as_bytes()))?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }

        self.create_table("user_creds", &["user_name", "password"], &["TEXT", "TEXT"])?;

        let count = self.is_present("user_creds", "user_name", "Admin")?;
        if count == 0 {
            let query = "INSERT INTO user_creds VALUES ('Admin',?)";

            let default_password = encrypt_string("Pass")?;

            let mut statement = self.conn.prepare(query)?;
            statement.bind((1, default_password.as_str()))?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }

        self.create_table(
            "node_app_details",
            &["user_name", "password", "endpoint", "purpose"],
            &["TEXT", "TEXT", "TEXT", "TEXT"],
        )?;

        let count = self.is_present("node_app_details", "purpose", "list_binaries")?;
        if count == 0 {
            let query = "INSERT INTO node_app_details VALUES ('admin',?,'https://admin_url','list_binaries')";

            let default_password = "tBgu0U@93Px3";

            let mut statement = self.conn.prepare(query)?;
            statement.bind((1, default_password))?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }

        let count = self.is_present("node_app_details", "purpose", "download_binary")?;
        if count == 0 {
            let query = "INSERT INTO node_app_details VALUES ('admin',?,'https:://admin_url/','download_binary')";

            let default_password = "tBgu0U@93Px3";

            let mut statement = self.conn.prepare(query)?;
            statement.bind((1, default_password))?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }

        println!("\n\nDatabase initialised\n\n");

        Ok(())
    }

    pub fn create_table(
        &self,
        table_name: &str,
        columns: &[&str],
        data_types: &[&str],
    ) -> Result<(), DatabaseError> {
        let mut query = String::from("CREATE TABLE IF NOT EXISTS ");
        query.push_str(table_name);
        query.push_str(" (");

        for i in 0..columns.len() {
            query.push_str(columns[i]);
            query.push(' ');
            query.push_str(data_types[i]);
            query.push(',');
        }

        query.pop(); // Remove the last comma
        query.push(')');

        self.conn.execute(&query)?;

        Ok(())
    }

    fn insert_record(
        &self,
        table_name: &str,
        fields: &[&str],
        values: &[&str],
    ) -> Result<(), DatabaseError> {
        let mut statement = String::from("INSERT OR IGNORE INTO ");
        statement.push_str(table_name);
        statement.push('(');

        for i in 0..fields.len() {
            statement.push_str(fields[i]);
            if i != fields.len() - 1 {
                statement.push(',');
            }
        }

        statement.push_str(") VALUES (");

        for i in 0..values.len() {
            statement.push('\'');
            statement.push_str(values[i]);
            statement.push('\'');
            if i != values.len() - 1 {
                statement.push(',');
            }
        }

        statement.push(')');

        self.conn.execute(&statement)?;

        Ok(())
    }

    pub fn update_record(
        &self,
        table_name: &str,
        set_fields: &[&str],
        set_values: &[&str],
        where_field: &str,
        where_value: &str,
    ) -> Result<(), DatabaseError> {
        let mut statement = String::from("UPDATE ");
        statement.push_str(table_name);
        statement.push_str(" SET ");

        for i in 0..set_fields.len() {
            statement.push_str(set_fields[i]);
            statement.push('=');
            statement.push('\'');
            statement.push_str(set_values[i]);
            statement.push('\'');
            if i != set_fields.len() - 1 {
                statement.push(',');
            }
        }

        statement.push_str(" WHERE ");
        statement.push_str(where_field);
        statement.push('=');
        statement.push('\'');
        statement.push_str(where_value);
        statement.push('\'');

        self.conn.execute(&statement)?;

        Ok(())
    }

    pub fn is_present(
        &self,
        table_name: &str,
        param_name: &str,
        param_val: &str,
    ) -> Result<i64, DatabaseError> {
        let mut stmt = self.conn.prepare(format!(
            "SELECT * FROM {table_name} WHERE {param_name} = \'{param_val}\'  "
        ))?;

        let mut count = 0;

        while matches!(stmt.next(), Ok(State::Row)) {
            count += 1;
        }

        Ok(count)
    }

    pub fn get_server_config(
        &self,
    ) -> Result<
        (
            String,
            u16,
            u16,
            u16,
            bool,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
        DatabaseError,
    > {
        let _decryptor = DecryptDatabase::decrypt(self.filepath.clone(), None)?;

        let mut ip_addr: String = String::new();
        let mut primary_port: u16 = 0;
        let mut min_port: u16 = 0;
        let mut max_port: u16 = 0;
        let mut auto_upgrade: bool = false;
        let mut opensearch_domain_endpoint: String = String::new();
        let mut opensearch_application_log_index: String = String::new();
        let mut opensearch_health_discovery_log_index: String = String::new();
        let mut opesearch_user_name: String = String::new();
        let mut opensearch_user_pass: String = String::new();
        let mut log_level: String = String::new();

        let mut stmt = self.conn.prepare("SELECT  * FROM server_config")?;

        while matches!(stmt.next(), Ok(State::Row)) {
            let paran_name = stmt.read::<String, _>("param_name")?;

            let global_value = stmt.read::<String, _>("global_value")?;
            let local_value = stmt.read::<String, _>("local_value")?;
            let final_value: String;
            if !local_value.is_empty() {
                final_value = local_value;
            } else {
                final_value = global_value;
            }

            match paran_name.as_str() {
                "ip_addr" => ip_addr = final_value.to_string(),
                "min_port" => min_port = final_value.parse()?,
                "max_port" => max_port = final_value.parse()?,
                "server_port" => primary_port = final_value.parse()?,
                "auto_upgrade" => {
                    let auto_upgrade_int: i64 = final_value.parse()?;
                    if auto_upgrade_int == 1 {
                        auto_upgrade = true;
                    }
                }
                "opensearch_domain_endpoint" => {
                    opensearch_domain_endpoint = final_value.to_string();
                }
                "opensearch_application_log_index" => {
                    opensearch_application_log_index = final_value.to_string();
                }
                "opensearch_health_discovery_log_index" => {
                    opensearch_health_discovery_log_index = final_value.to_string();
                }
                "opensearch_user_pass" => opensearch_user_pass = final_value.to_string(),
                "opensearch_user_name" => opesearch_user_name = final_value.to_string(),
                "log_level" => log_level = final_value.to_string(),
                _ => {}
            }
        }

        Ok((
            ip_addr,
            primary_port,
            min_port,
            max_port,
            auto_upgrade,
            opensearch_domain_endpoint,
            opensearch_application_log_index,
            opensearch_health_discovery_log_index,
            opesearch_user_name,
            opensearch_user_pass,
            log_level,
        ))
    }

    pub fn get_scheduled_jobs(&self) -> Result<(), DatabaseError> {
        let _decryptor = DecryptDatabase::decrypt(self.filepath.clone(), None)?;

        let query = "SELECT * FROM scheduled_jobs";
        let mut statement = self.conn.prepare(query)?;

        while matches!(statement.next(), Ok(State::Row)) {
            let script_crone_expression = statement.read::<String, _>("cron_expression")?;
            let schedule_time_sys_time =
                time_until_next_run(script_crone_expression.clone().as_str())?;
            let schedule_time_date_time = datetime_to_systemtime(schedule_time_sys_time);

            let job = Job {
                name: statement.read::<String, _>("script_name")?,
                execute_at: schedule_time_date_time,
                cron_expression: script_crone_expression,
                script_content: statement.read::<String, _>("content")?,
                arguments: statement.read::<String, _>("arguments")?,
                script_type: statement.read::<i64, _>("script_type")? as u64,
                opensearch_index: statement.read::<String, _>("opensearch_index")?,
                opensearch_enabled: statement.read::<i64, _>("opensearch_enabled")? as u64,
            };

            let mut heap_clone = GLOBAL_JOBS_HEAP.lock()?;
            let guard = &mut *heap_clone;
            (guard).push(job);
        }

        Ok(())
    }
}
pub fn get_node_app_config(
    purpose_int: u16,
    sender: Sender<i32>,
) -> Result<(String, String, String), DatabaseError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;
    let mut username: String = Default::default();
    let mut password: String = Default::default();
    let mut endpoint: String = Default::default();

    let purpose_str = match purpose_int {
        0 => "download_binary",
        1 => "list_binaries",
        _ => {
            return Err(DatabaseError::FieldNotFound("unknown".to_string()));
        }
    };

    println!("\n\nrunnign the query\n\n");

    let query = format!("SELECT * FROM node_app_details WHERE purpose = \'{purpose_str}\'");

    let mut stmt = db.conn.prepare(query)?;

    // println!("\n\n query prepared\n\n");
    // stmt.bind((1, purpose_str))?;

    println!("\n\n value binded\n\n");

    // "user_name", "password", "endpoint", "purpose"],
    while matches!(stmt.next(), Ok(State::Row)) {
        username = stmt.read::<String, _>("user_name")?;
        password = stmt.read::<String, _>("password")?;
        endpoint = stmt.read::<String, _>("endpoint")?;
    }

    Ok((username, password, endpoint))
}

pub fn update_config(
    request_body: ConfigChangeRequest,
    sender: Sender<i32>,
) -> Result<(), DatabaseError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender))?;

    let mut count = 0_usize;
    let mut stmt = db.conn.prepare(format!(
        "SELECT * FROM server_config WHERE param_name=\'{}\'",
        request_body.propertyName
    ))?;

    while matches!(stmt.next(), Ok(State::Row)) {
        count += 1;
    }

    match count {
        0 => return Err(DatabaseError::RecordNotPresent(request_body.propertyName)),
        1 => {
            let property = match request_body.propertyValue.as_str() {
                "true" => "1".to_string(),
                "false" => "0".to_string(),
                var => var.to_string(),
            };
            let query = format!(
                "UPDATE server_config SET local_value = \'{}\' WHERE param_name =\'{}\' ",
                property, request_body.propertyName
            );

            let mut statement = db.conn.prepare(query)?;
            while matches!(statement.next(), Ok(State::Row)) {}
        }
        _ => return Err(DatabaseError::MultipleRecords(request_body.propertyName)),
    }

    Ok(())
}
