use super::config::AgentConfig;
use crate::exec::command::remove_undesirable_chars;
use crate::exec::global::PORT_NUMBER;
use crate::exec::opensearch::LogLevel;
#[allow(unused)]
use crate::exec::script::{
    delete_script, get_script_details, ScriptDetailsRequest, ScriptDetailsResponse,
};
use crate::exec::sqlite::get_node_app_config;
use crate::utils::encrypt::base64_decrypt;
use crate::utils::logger::EndpointLogs;
use crate::{
    exec::{
        self,
        config::ConfigChangeRequest,
        global::{DATABASE_OBJ, GLOBAL_JOBS_HEAP},
        scheduled_job::Job,
        script::{save_script, update_script},
        sqlite::{update_config, DatabaseError},
        ScriptRequest,
    },
    metrics::{
        metrics::{self, MetricInfoError},
        os,
    },
    utils::{
        self, download::download_version, encrypt::get_database_decrypted, encrypt_string, MyError,
    },
};
use axum::extract::Query;
use axum::{
    http::{StatusCode, Uri},
    Json,
};
use chrono::{DateTime, Local};
use cron::Schedule;
use fmt::{Debug, Formatter};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use sqlite::State;
use std::str::FromStr;
use std::{convert::Infallible, fmt, process::Command, sync::mpsc::Sender, time::SystemTime};

pub type AxumResponse<B> = (StatusCode, Json<AxumResult<B>>);
pub enum AxumResult<B: Serialize> {
    Err(String),
    Ok(B),
}
impl<B: std::fmt::Debug + Serialize> serde::ser::Serialize for AxumResult<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Err(msg) => serializer.serialize_str(msg),
            Self::Ok(body) => serializer.serialize_some(body),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricResponse {
    pub memory: f32,
    pub cpu_usage: f32,
    pub rust_version: String,
    pub os_name: String,
    pub kernel_version: String,
    pub os_version: String,
    pub disk_usage: f32,
    pub up_time: u64,
    pub port: u16,
    pub jobs: Vec<String>,
}

impl fmt::Display for MetricResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"memory", &self.memory)
            .entry(&"cpu_usage", &self.cpu_usage)
            .entry(&"rust_version", &self.rust_version)
            .entry(&"os_name", &self.os_name)
            .entry(&"kernel_version", &self.kernel_version)
            .entry(&"os_version", &self.os_version)
            .entry(&"disk_usage", &self.disk_usage)
            .entry(&"up_time", &self.up_time)
            .entry(&"port", &self.port)
            .entry(&"jobs", &self.jobs)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExecResponse {
    pub success: bool,
    pub message: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartBeatRequest {
    pub id: String,
}

impl fmt::Display for HeartBeatRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{\"id\": {} }}", self.id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandRequest {
    command: String,
}

impl fmt::Display for CommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ \n \t\"command\": {}\n }}", self.command)
    }
}

pub async fn response_health(_endpoint: Uri, _sender: Sender<i32>) -> (StatusCode, Json<String>) {
    match get_health() {
        Ok(health) => (StatusCode::OK, Json(health)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(format!("INTERNAL SERVER ERROR\r\n\r\n{e}")),
        ),
    }
}

#[derive(Deserialize)]
pub struct JobName {
    name: Option<String>,
}
pub enum JobReturn {
    Single(ScriptDetailsResponse),
    List(Vec<String>),
}
impl Debug for JobReturn {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::List(vec) => write!(f, "{vec:?}"),
            Self::Single(script) => f
                .debug_map()
                .entry(&"script_name", &script.script_name)
                .entry(&"content", &script.content)
                .entry(&"arguments", &script.arguments)
                .entry(&"cron_expression", &script.cron_expression)
                .entry(&"script_type", &script.script_type)
                .entry(&"opensearch_index", &script.opensearch_index)
                .entry(&"opensearch_enabled", &script.opensearch_enabled)
                .finish(),
        }
    }
}
impl serde::ser::Serialize for JobReturn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::List(vec) => {
                let mut s = serializer.serialize_seq(Some(vec.len()))?;
                for item in vec {
                    s.serialize_element(item)?;
                }
                s.end()
            }
            Self::Single(script) => {
                let mut s = serializer.serialize_map(Some(5))?;
                s.serialize_entry(&"script_name", &script.script_name)?;
                s.serialize_entry(&"content", &script.content)?;
                s.serialize_entry(&"arguments", &script.arguments)?;
                s.serialize_entry(&"cron_expression", &script.cron_expression)?;
                s.serialize_entry(&"script_type", &script.script_type)?;
                s.serialize_entry(&"opensearch_index", &script.opensearch_index)?;
                s.serialize_entry(&"opensearch_enabled", &script.opensearch_enabled)?;
                s.end()
            }
        }
    }
}
pub async fn response_get_jobs_list(
    _endpoint: Uri,
    query: Query<JobName>,
    sender: Sender<i32>,
) -> AxumResponse<JobReturn> {
    let mut jobs: Vec<String> = vec![];

    let (db, _decryptor) = get_database_decrypted(Some(sender)).unwrap();

    if let Query(JobName {
        name: Some(job_name),
    }) = query
    {
        if !job_name.is_empty() {
            #[allow(unused)]
            let mut script_name = String::new();
            #[allow(unused)]
            let mut content = String::new();
            #[allow(unused)]
            let mut arguments = String::new();
            #[allow(unused)]
            let mut cron_expression = String::new();
            #[allow(unused)]
            let mut script_type = 0_u64;
            #[allow(unused)]
            let mut opensearch_index = String::new();
            #[allow(unused)]
            let mut opensearch_enabled = 0_64;
            #[allow(unused)]
            let mut script_body = Option::<ScriptDetailsResponse>::None;

            let query = format!(
                "SELECT * from scheduled_jobs WHERE script_name =\'{job_name}\' "
            );

            let mut statement = match db.conn.prepare(query) {
                Ok(st) => st,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AxumResult::Err(
                            DatabaseError::SqliteError(e).to_string(),
                        )),
                    )
                }
            };

            while matches!(statement.next(), Ok(State::Row)) {
                let opensearch_enabled = statement
                    .read::<i64, _>("opensearch_enabled")
                    .unwrap_or(0)
                    > 0;

                script_body = Some(ScriptDetailsResponse {
                    script_name: statement
                        .read::<String, _>("script_name")
                        .unwrap_or_else(|_| String::new()),
                    cron_expression: statement
                        .read::<String, _>("cron_expression")
                        .unwrap_or_else(|_| String::new()),
                    content: statement
                        .read::<String, _>("content")
                        .unwrap_or_else(|_| String::new()),
                    arguments: statement
                        .read::<String, _>("arguments")
                        .unwrap_or_else(|_| String::new()),
                    opensearch_index: statement
                        .read::<String, _>("opensearch_index")
                        .unwrap_or_else(|_| String::new()),
                    script_type: statement
                        .read::<i64, _>("script_type")
                        .unwrap_or(0) as u64,
                    opensearch_enabled,
                });
            }

            let result = match script_body {
                Some(body) => body,
                None => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AxumResult::Err("Script does not exist".to_string())),
                    )
                }
            };

            return (
                StatusCode::OK,
                Json(AxumResult::Ok(JobReturn::Single(result))),
            );
        }
    };

    let query = "SELECT * FROM scheduled_jobs";
    let mut statement = match db.conn.prepare(query) {
        Ok(st) => st,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(format!(
                    "Error Querying the database file: {e}"
                ))),
            );
        }
    };
    while matches!(statement.next(), Ok(State::Row)) {
        jobs.push(
            statement
                .read::<String, _>("script_name")
                .unwrap_or_else(|_| String::new()),
        );
    }

    (StatusCode::OK, Json(AxumResult::Ok(JobReturn::List(jobs))))
}

pub async fn response_get_metric(
    _endpoint: Uri,
    sender: Sender<i32>,
) -> AxumResponse<MetricResponse> {
    match get_metric(sender) {
        Ok(response) => (StatusCode::OK, Json(AxumResult::Ok(response))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AxumResult::Err(format!("{e}"))),
        ),
    }
}

pub async fn response_get_agent_config(
    _endpoint: Uri,
    sender: Sender<i32>,
) -> AxumResponse<AgentConfig> {
    let (db, _decryptor) = get_database_decrypted(Some(sender)).unwrap();

    let mut opensearch_domain_endpoint = Default::default();
    let mut opensearch_user_name = Default::default();
    let mut opensearch_user_pass = Default::default();
    let mut auto_upgrade = false;
    let mut port = Default::default();
    let mut version = Default::default();
    let install_dir = os::get_install_dir();
    let rust_install_path = match os::get_rust_install_path() {
        Ok(dir) => dir,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(format!("{err}"))),
            )
        }
    };

    let mut stmt = match db.conn.prepare("SELECT * FROM agent_version") {
        Ok(st) => st,
        Err(e) => {
            let err_msg = format!("{}", DatabaseError::SqliteError(e),);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(err_msg)),
            );
        }
    };
    while matches!(stmt.next(), Ok(State::Row)) {
        version = stmt.read::<String, _>("version").unwrap_or_default();
        if version == " " {
            continue;
        }
    }
    let mut stmt = match db.conn.prepare(format!(
        "SELECT * FROM server_config WHERE param_name = \'{}\' OR param_name = \'{}\' OR \
        param_name = \'{}\' OR param_name = \'{}\' OR param_name = \'{}\'",
        "opensearch_domain_endpoint",
        "auto_upgrade",
        "server_port",
        "opensearch_user_name",
        "opensearch_user_pass",
    )) {
        Ok(st) => st,
        Err(e) => {
            let err_msg = format!("{}", DatabaseError::SqliteError(e));

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(err_msg)),
            );
        }
    };
    while matches!(stmt.next(), Ok(State::Row)) {
        let paran_name = stmt
            .read::<String, _>("param_name")
            .unwrap_or_else(|_| String::new());
        let global_value = stmt.read::<String, _>("global_value").unwrap_or_default();
        let local_value = stmt.read::<String, _>("local_value").unwrap_or_default();

        let final_value: String;
        if !local_value.is_empty() {
            final_value = local_value;
        } else {
            final_value = global_value;
        }

        match paran_name.as_str() {
            "auto_upgrade" => {
                let auto_upgrade_int: i64 = final_value.parse().unwrap_or_default();
                if auto_upgrade_int == 1 {
                    auto_upgrade = true;
                }
            }
            "server_port" => port = final_value.parse().unwrap_or_default(),
            "opensearch_domain_endpoint" => opensearch_domain_endpoint = final_value.to_string(),
            "opensearch_user_name" => opensearch_user_name = final_value.to_string(),
            "opensearch_user_pass" => opensearch_user_pass = final_value.to_string(),
            _ => {}
        }
    }

    let agent_config = AgentConfig {
        opensearch_non_prod_domain_endpoint: opensearch_domain_endpoint,
        opensearch_non_prod_user_name: opensearch_user_name,
        opensearch_non_prod_pass_word: opensearch_user_pass,
        install_dir,
        version,
        auto_upgrade,
        port,
        rust_install_path,
        ..Default::default()
    };

    (StatusCode::OK, Json(AxumResult::Ok(agent_config)))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentInfo {
    agent_details: AgentDetails,
    agent_config: AgentConfig,
    agent_local_config: AgentLocalConfigurations,
    jobs: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentDetails {
    version: String,
    vm_hostname: String,
    vm_ip: String,
    install_dir: String,
    rust_version: String,
    os_version: String,
    port: u16,
    pid: usize,
    up_time: u64,
    memory: f32,
    cpu_usage: f32,
    disk_usage: f32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentLocalConfigurations {
    #[serde(skip_serializing_if = "Option::is_none")]
    opensearch_non_prod_domain_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opensearch_non_prod_user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opensearch_non_prod_pass_word: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_upgrade: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

pub async fn response_get_agent_info(
    _endpoint: Uri,
    sender: Sender<i32>,
) -> AxumResponse<AgentInfo> {
    let MetricResponse {
        memory,
        cpu_usage,
        rust_version,
        os_version,
        disk_usage,
        up_time,
        jobs,
        ..
    } = match metrics::get_agent_metric(sender.clone()) {
        Ok(metrics) => metrics,
        Err(e) => {
            let msg = format!("error getting the metric response: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(msg)),
            );
        }
    };

    let (db, _decryptor) = get_database_decrypted(Some(sender)).unwrap();

    // Agent configurations
    // <========== Local
    let (mut can_modify_opensearch, mut opensearch_domain_endpoint) = Default::default();
    let (mut can_modify_opensearch_uname, mut opensearch_user_name) = Default::default();
    let (mut can_modify_opensearch_pwd, mut opensearch_user_pass) = Default::default();
    let (mut can_modify_auto_upgrade, mut auto_upgrade) = (false, false);
    let (mut can_modify_port, mut port) = Default::default();
    // ==========> End
    let mut version = Default::default();
    let install_dir = os::get_install_dir();
    let rust_install_path = match os::get_rust_install_path() {
        Ok(dir) => dir,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(format!("{err}"))),
            )
        }
    };
    //----------
    let pid = std::process::id() as usize;
    let (hostname, ip) = match os::get_host_info() {
        Ok(host_info) => host_info,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(format!("{err}"))),
            )
        }
    };

    let mut stmt = match db.conn.prepare("SELECT * FROM agent_version") {
        Ok(st) => st,
        Err(e) => {
            let err_msg = format!("{}", DatabaseError::SqliteError(e),);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(err_msg)),
            );
        }
    };
    while matches!(stmt.next(), Ok(State::Row)) {
        version = stmt.read::<String, _>("version").unwrap_or_default();
        if version == " " {
            continue;
        }
    }
    let mut stmt = match db.conn.prepare(format!(
        "SELECT * FROM server_config WHERE param_name = \'{}\' OR param_name = \'{}\' OR \
        param_name = \'{}\' OR param_name = \'{}\' OR param_name = \'{}\'",
        "opensearch_domain_endpoint",
        "auto_upgrade",
        "server_port",
        "opensearch_user_name",
        "opensearch_user_pass",
    )) {
        Ok(st) => st,
        Err(e) => {
            let err_msg = format!("{}", DatabaseError::SqliteError(e),);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(err_msg)),
            );
        }
    };
    while matches!(stmt.next(), Ok(State::Row)) {
        let paran_name = stmt.read::<String, _>("param_name").unwrap_or_default();
        let global_value = stmt.read::<String, _>("global_value").unwrap_or_default();
        let local_value = stmt.read::<String, _>("local_value").unwrap_or_default();
        let can_modify = stmt.read::<i64, _>("can_modify").unwrap_or_default();

        let final_value: String;
        if !local_value.is_empty() {
            final_value = local_value;
        } else {
            final_value = global_value;
        }

        match paran_name.as_str() {
            "auto_upgrade" => {
                let auto_upgrade_int: i64 = final_value.parse().unwrap_or_default();
                if auto_upgrade_int == 1 {
                    auto_upgrade = true;
                }
                if can_modify == 1 {
                    can_modify_auto_upgrade = true;
                }
            }
            "server_port" => {
                port = final_value.parse().unwrap_or_default();
                if can_modify == 1 {
                    can_modify_port = true;
                }
            }
            "opensearch_domain_endpoint" => {
                opensearch_domain_endpoint = final_value.to_string();
                if can_modify == 1 {
                    can_modify_opensearch = true;
                }
            }
            "opensearch_user_name" => {
                opensearch_user_name = final_value.to_string();
                if can_modify == 1 {
                    can_modify_opensearch_uname = true;
                }
            }
            "opensearch_user_pass" => {
                opensearch_user_pass = final_value.to_string();
                if can_modify == 1 {
                    can_modify_opensearch_pwd = true;
                }
            }
            _ => {}
        }
    }

    let agent_info = AgentInfo {
        agent_details: AgentDetails {
            version: version.clone(),
            vm_hostname: hostname,
            vm_ip: ip,
            install_dir: install_dir.clone(),
            rust_version,
            os_version,
            port,
            pid,
            up_time,
            memory,
            cpu_usage,
            disk_usage,
        },
        agent_config: AgentConfig {
            opensearch_non_prod_domain_endpoint: opensearch_domain_endpoint.clone(),
            opensearch_non_prod_user_name: opensearch_user_name.clone(),
            opensearch_non_prod_pass_word: opensearch_user_pass.clone(),
            install_dir,
            version,
            auto_upgrade,
            port,
            rust_install_path,
            ..Default::default()
        },
        agent_local_config: AgentLocalConfigurations {
            port: can_modify_port.then_some(port),
            auto_upgrade: can_modify_auto_upgrade.then_some(auto_upgrade),
            opensearch_non_prod_domain_endpoint: can_modify_opensearch
                .then_some(opensearch_domain_endpoint),
            opensearch_non_prod_user_name: can_modify_opensearch_uname
                .then_some(opensearch_user_name),
            opensearch_non_prod_pass_word: can_modify_opensearch_pwd.then_some(opensearch_user_pass),
        },
        jobs,
    };

    (StatusCode::OK, Json(AxumResult::Ok(agent_info)))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentVersionResponse {
    version: String,
    version_valid: bool,
    build_date: String,
}

pub async fn response_get_agent_version(
    endpoint: Uri,
    sender: Sender<i32>,
) -> AxumResponse<AgentVersionResponse> {
    let (db, _decryptor) = get_database_decrypted(Some(sender.clone())).unwrap();

    let mut stmt = match db.conn.prepare("SELECT * FROM agent_version") {
        Ok(st) => st,
        Err(e) => {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("{e}"),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AxumResult::Err(format!("{err}"))),
                );
            }

            let err_msg = format!("{}", DatabaseError::SqliteError(e),);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AxumResult::Err(err_msg)),
            );
        }
    };
    let mut version_valid: bool = false;
    let mut version: String = String::new();
    let mut build_date: String = String::new();

    while matches!(stmt.next(), Ok(State::Row)) {
        version = stmt.read::<String, _>("version").unwrap_or_default();

        if version == " " {
            continue;
        }

        let version_valid_text = stmt.read::<String, _>("version_valid").unwrap_or_default();
        let version_valid_int: i64 = version_valid_text.parse().unwrap_or_default();

        if version_valid_int > 0 {
            version_valid = true;
        }

        build_date = stmt.read::<String, _>("build_date").unwrap_or_default();
    }

    let agent_version = AgentVersionResponse { version, version_valid, build_date };

    (StatusCode::OK, Json(AxumResult::Ok(agent_version)))
}

pub async fn response_get_process_id(
    _endpoint: Uri,
    _sender: Sender<i32>,
) -> (StatusCode, Json<i32>) {
    let resonse_body = std::process::id() as i32;
    (StatusCode::OK, Json(resonse_body))
}

pub async fn response_hearbeat(
    _endpoint: Uri,
    Json(payload): Json<HeartBeatRequest>,
    _sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    let result = ExecResponse {
        success: true,
        message: payload.id,
    };

    (StatusCode::OK, Json(result))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutoUpgradeRequest {
    command: bool,
}

impl fmt::Display for AutoUpgradeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ \n \t\"command\": {}\n }}", self.command)
    }
}

pub async fn response_auto_upgrade(
    endpoint: Uri,
    Json(command): Json<AutoUpgradeRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        format!("Auto upgrading: {}", command.command),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    let config_text: String = match command.command {
        true => "1".to_string(),
        _ => "0".to_string(),
    };

    let (db, _decryptor) = get_database_decrypted(Some(sender.clone())).unwrap();

    let (code, responsebody) = match db.update_record(
        "server_config",
        &["local_value"],
        &[config_text.as_str()],
        "param_name",
        "auto_upgrade",
    ) {
        Ok(()) => (
            StatusCode::OK,
            Json(ExecResponse {
                success: true,
                message: "Record updated successfully".to_string(),
            }),
        ),
        Err(e) => {
            if let Err(err) =
                EndpointLogs::app_log(sender, LogLevel::Error, endpoint.path(), format!("{e}"))
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecResponse {
                    success: false,
                    message: format!("{e}"),
                }),
            )
        }
    };

    (code, responsebody)
}

pub async fn response_os_command(
    endpoint: Uri,
    Json(payload): Json<CommandRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        format!("Running OS command {}", payload.command),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    if payload.command.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ExecResponse {
                success: false,
                message: "empty command".to_string(),
            }),
        );
    }

    let (code, result) = match exec::run_command_as_root(&payload.command) {
        Ok(response_body) => {
            let result = ExecResponse {
                success: true,
                message: response_body,
            };

            (StatusCode::OK, Json(result))
        }
        Err(e) => {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("{e}"),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            let result = ExecResponse {
                success: false,
                message: format!("{e}"),
            };

            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
    };

    (code, result)
}
pub async fn response_update_script(
    endpoint: Uri,
    Json(script): Json<ScriptRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Updating script".to_string(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }
    let content = match base64_decrypt(&script.content) {
        Ok(content) => {
            remove_undesirable_chars(&content)
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecResponse {
                    success: false,
                    message: format!("{e}"),
                }),
            );
        }
    };

    let script_name = script.script_name.clone();
    let script_crone_expression = script.cron_expression.clone();
    let script_type = script.script_type;
    let arguments = script.arguments.clone();
    let script_content = content;
    let opensearch_index = script.opensearch_index.clone();
    let opensearch_enabled: u64 = u64::from(script.opensearch_enabled);

    let (code, response) = match update_script(script, sender.clone()) {
        Ok(message) => {
            let schedule_time_sys_time =
                time_until_next_run(script_crone_expression.as_str()).unwrap_or_default();
            let schedule_time_date_time = datetime_to_systemtime(schedule_time_sys_time);
            let job = Job {
                name: script_name.clone(),
                execute_at: schedule_time_date_time,
                cron_expression: script_crone_expression,
                arguments,
                script_content,
                script_type,
                opensearch_index,
                opensearch_enabled,
            };
            let heap_clone = GLOBAL_JOBS_HEAP.clone();
            println!("\ngetting the lock of the clone\n");
            let mut guard = match heap_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ExecResponse {
                            success: false,
                            message: format!("{e}"),
                        }),
                    );
                }
            };
            println!("\npushing the jobs\n");

            (*guard).retain(|x| x.name != script_name.clone());
            (*guard).push(job);
            println!("\nsaved in jobs heaps\n");

            (
                StatusCode::OK,
                Json(ExecResponse {
                    success: true,
                    message,
                }),
            )
        }
        Err(e) => {
            if let Err(err) =
                EndpointLogs::app_log(sender, LogLevel::Error, endpoint.path(), format!("{e}"))
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecResponse {
                    success: false,
                    message: format!("{e}"),
                }),
            )
        }
    };
    (code, response)
}

pub fn time_until_next_run(cron_expr: &str) -> Result<DateTime<Local>, Box<dyn std::error::Error>> {
    let cron_schedule = Schedule::from_str(cron_expr)?;

    let next_run = cron_schedule
        .after(&Local::now())
        .next()
        .unwrap_or(Local::now());

    Ok(next_run)
}

pub fn datetime_to_systemtime(dt: DateTime<Local>) -> SystemTime {
    let duration = dt - Local::now();
    let unix_timestamp = duration.num_seconds();
    SystemTime::now() + std::time::Duration::from_secs(unix_timestamp as u64)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCredsReq {
    pub name: String,
    pub pass: String,
}

impl fmt::Display for UserCredsReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ \n \t\"name\": {}\n \t\"pass\": {}\n }}",
            self.name, self.pass
        )
    }
}

pub fn update_pass(
    request_body: UserCredsReq,
    sender: Sender<i32>,
) -> Result<String, utils::MyError> {
    let (db, _decryptor) = get_database_decrypted(Some(sender)).unwrap();

    match db.is_present("user_creds", "user_name", request_body.name.as_str()) {
        Ok(count) => {
            if count > 0 {
                let new_password = match encrypt_string(request_body.pass.as_str()) {
                    Ok(output) => output,
                    Err(e) => return Err(MyError::new(e.to_string())),
                };

                let query = format!(
                    "UPDATE user_creds SET password = \'{}\' WHERE user_name =\'{}\' ",
                    new_password, request_body.name
                );

                let mut statement = match db.conn.prepare(query) {
                    Ok(st) => st,
                    Err(e) => {
                        return Err(MyError {
                            message: DatabaseError::SqliteError(e).to_string(),
                        })
                    }
                };

                while matches!(statement.next(), Ok(State::Row)) {}
            } else {
                return Err(MyError::new(format!(
                    "Error updating the user {} . Record  not present.",
                    request_body.name
                )));
            }
        }
        Err(e) => {
            return Err(MyError::new(format!("{e}")));
        }
    }

    Ok("User updated successfully".to_string())
}

pub async fn response_update_password(
    endpoint: Uri,
    Json(creds): Json<UserCredsReq>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Updating password".to_string(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    let (code, response) = match update_pass(creds, sender.clone()) {
        Ok(message) => (
            StatusCode::OK,
            ExecResponse {
                success: true,
                message,
            },
        ),
        Err(e) => {
            if let Err(err) =
                EndpointLogs::app_log(sender, LogLevel::Error, endpoint.path(), format!("{e}"))
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            (
                StatusCode::OK,
                ExecResponse {
                    success: false,
                    message: format!("{e}"),
                },
            )
        }
    };
    (code, Json(response))
}

pub async fn response_save_script(
    endpoint: Uri,
    Json(script): Json<ScriptRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Saving script".to_string(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    let content = match base64_decrypt(&script.content) {
        Ok(content) => {
            remove_undesirable_chars(&content)
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecResponse {
                    success: false,
                    message: format!("{e}"),
                }),
            );
        }
    };

    let name = script.script_name.clone();
    let script_cron_expression = script.cron_expression.clone();
    let script_type = script.script_type;
    let arguments = script.arguments.clone();
    let script_content = content;
    let opensearch_index = script.opensearch_index.clone();
    let opensearch_enabled: u64;
    if script.opensearch_enabled {
        opensearch_enabled = 1;
    } else {
        opensearch_enabled = 0;
    }

    let (code, response) = match save_script(script, sender.clone()) {
        Ok(message) => {
            let schedule_time_sys_time =
                match time_until_next_run(script_cron_expression.as_str()) {
                    Ok(time) => time,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ExecResponse {
                                success: false,
                                message: format!("Error parsing the cron expression: {e}"),
                            }),
                        );
                    }
                };
            let schedule_time_date_time = datetime_to_systemtime(schedule_time_sys_time);

            let job = Job {
                name,
                execute_at: schedule_time_date_time,
                cron_expression: script_cron_expression,
                arguments,
                script_content,
                script_type,
                opensearch_index,
                opensearch_enabled,
            };
            let heap_clone = GLOBAL_JOBS_HEAP.clone();
            let mut guard = match heap_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ExecResponse {
                            success: false,
                            message: format!("Error Getting the lock of the jobs heap: {e}"),
                        }),
                    );
                }
            };
            (*guard).push(job);

            println!("\n\n\nsaved in jobs heaps\n\n\n");

            let result = ExecResponse {
                success: true,
                message,
            };

            (StatusCode::OK, Json(result))
        }
        Err(e) => {
            if let Err(err) =
                EndpointLogs::app_log(sender, LogLevel::Error, endpoint.path(), format!("{e}"))
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            let result = ExecResponse {
                success: false,
                message: format!("{e}"),
            };

            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
    };
    (code, response)
}

pub async fn response_script_exec(
    endpoint: Uri,
    Json(payload): Json<ScriptRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Execute script".to_string(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    let (code, response) = match exec::run_script(payload) {
        Ok(message) => {
            let response = ExecResponse {
                success: true,
                message,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            if let Err(err) =
                EndpointLogs::app_log(sender, LogLevel::Error, endpoint.path(), format!("{e}"))
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }

            eprintln!("error while run script: {e}");
            let response = ExecResponse {
                success: false,
                message: format!("{e}"),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    };
    (code, response)
}

#[derive(Debug, Serialize, Deserialize)]
struct JobExecutionRequest {
    command: bool,
}

impl fmt::Display for JobExecutionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ \n \t\"command\": {}\n }}", self.command)
    }
}

pub async fn stop_job_execution(endpoint: Uri, sender: Sender<i32>) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Stopped job execution".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    // 2 for stopping the jobs
    let (code, response) = match sender.send(2) {
        Ok(()) => {
            let response_body = "Job execution stopped".to_string();
            (StatusCode::OK, Json(response_body))
        }
        Err(e) => {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("Error while stopping job execution: {e}"),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
            }

            let response_body =
                format!("\n\nError in control_job_execution: {e}\n\n");

            (StatusCode::INTERNAL_SERVER_ERROR, Json(response_body))
        }
    };

    (code, response)
}

pub async fn start_job_execution(endpoint: Uri, sender: Sender<i32>) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Started job execution".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    // 2 for stopping the jobs
    let (code, response) = match sender.send(1) {
        Ok(()) => {
            

            let response_body: String = "Job execution started".to_string();
            (StatusCode::OK, Json(response_body))
        }
        Err(e) => {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("Error while starting job execution: {e}"),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
            }

            let response_body =
                format!("\n\nError in control_job_execution: {e}\n\n");

            (StatusCode::INTERNAL_SERVER_ERROR, Json(response_body))
        }
    };

    (code, response)
}

pub async fn agent_shutdown(endpoint: Uri, sender: Sender<i32>) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Shutting the agent down".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    // 2 for stopping the jobs
    let (code, response) = match sender.send(0) {
        Ok(()) => {
            let response_body = "Agent Shutdown initiated".to_string();
            (StatusCode::OK, Json(response_body))
        }
        Err(e) => {
            let response_body =
                format!("\n\nError in control_job_execution: {e}\n\n");

            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("Error while shutting the agent down: {e}"),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
            }

            (StatusCode::INTERNAL_SERVER_ERROR, Json(response_body))
        }
    };

    (code, response)
}

fn get_health() -> Result<String, Infallible> {
    let response_body = "Running";
    Ok(response_body.to_string())
}

fn get_metric(sender: Sender<i32>) -> Result<MetricResponse, MetricInfoError> {
    metrics::get_agent_metric(sender)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateConfig(Vec<ConfigChangeRequest>);

pub async fn response_update_config(
    endpoint: Uri,
    Json(UpdateConfig(config_request)): Json<UpdateConfig>,
    sender: Sender<i32>,
) -> (StatusCode, Json<ExecResponse>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Updating configurations".to_string(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecResponse {
                success: false,
                message: format!("{err}"),
            }),
        );
    }

    for config_request in config_request {
        if let Err(e) = update_config(config_request, sender.clone()) {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("Error while updating configurations: {e}"),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ExecResponse {
                        success: false,
                        message: format!("{err}"),
                    }),
                );
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecResponse {
                    success: false,
                    message: format!("{e}"),
                }),
            );
        }
    }

    (
        StatusCode::OK,
        Json(ExecResponse {
            success: true,
            message: "Property updated successfully".to_string(),
        }),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionRequest {
    file_name_version: String,
}

pub async fn response_agent_version_change(
    endpoint: Uri,
    Json(binary_name): Json<VersionRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Update agent version".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }
    //
    //
    match download_version(binary_name.file_name_version.clone(), sender.clone()) {
        Ok(_) => {
            match sender.send(0) {
                // 0 for shutdown
                Ok(()) => {
                    println!("{}", binary_name.file_name_version);
                    let port_selected = match PORT_NUMBER.lock() {
                        Ok(port) => port,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(format!("Error getting the lock of port number : {e}")),
                            );
                        }
                    };

                    let output = match Command::new("chmod")
                        .arg("+x")
                        .arg(format!("./{}", binary_name.file_name_version))
                        .output()
                    {
                        Ok(output) => output,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(format!(
                                    "Failed to change the permissions for the binary  : {e}"
                                )),
                            );
                        }
                    };

                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("Command output:\n{stdout}");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("Command failed with error:\n{stderr}");
                    }

                    println!("The port number of the current version is: {port_selected}");
                    match Command::new(format!("./{}", binary_name.file_name_version))
                        .arg(format!("{port_selected}"))
                        .spawn()
                    {
                        Ok(_) => {}
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(format!("Failed to execute the new binary  : {e}")),
                            );
                        }
                    };

                    let response = "version updated".to_string();
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    if let Err(err) = EndpointLogs::app_log(
                        sender,
                        LogLevel::Error,
                        endpoint.path(),
                        format!("{e}"),
                    ) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
                    }

                    let response = format!("\n\nError in stopping the jobs: {e}\n\n");

                    (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");

            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("{e}"),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
            }

            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string()))
        }
    }
}

pub async fn response_get_agent_version_list(
    endpoint: Uri,
    sender: Sender<i32>,
) -> (StatusCode, Json<Vec<String>>) {
    match get_node_app_config(1, sender.clone()) {
        Ok((username, password, node_endpoint)) => {
            let output = match Command::new("curl")
                .arg("-X")
                .arg("-u")
                .arg(format!("{username}:{password}"))
                .arg(node_endpoint)
                .output()
            {
                Ok(output) => output,
                Err(e) => {
                    eprintln!(
                        "Error while fetching the binary list from the node app: {e}"
                    );
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new()));
                }
            };

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let response: Vec<String> = match serde_json::from_str(&stdout) {
                    Ok(response) => response,
                    Err(e) => {
                        if let Err(_err) = EndpointLogs::app_log(
                            sender,
                            LogLevel::Error,
                            endpoint.path(),
                            format!("{e}"),
                        ) {
                            return (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new()));
                        }

                        eprintln!("{e}");
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new()));
                    }
                };

                (StatusCode::OK, Json(response))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new()))
            }
        }
        Err(e) => {
            println!("Error while listing the binaries: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new()))
        }
    }
}

pub async fn response_script_delete(
    endpoint: Uri,
    Query(script): Query<ScriptDetailsRequest>,
    sender: Sender<i32>,
) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        format!("Deleted script {}", script.script_name),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    let (code, response) = match delete_script(script, sender.clone()) {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(e) => {
            if let Err(err) = EndpointLogs::app_log(
                sender,
                LogLevel::Error,
                endpoint.path(),
                format!("Error while deleting the script: {e}"),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
            }

            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string()))
        }
    };

    (code, response)
}

pub async fn agent_restart(endpoint: Uri, sender: Sender<i32>) -> (StatusCode, Json<String>) {
    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Restarting the agent".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    let mut guard = match GLOBAL_JOBS_HEAP.lock() {
        Ok(guard) => guard,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(format!(
                    "Error getting the lock of the global jobs heap: {e}"
                )),
            );
        }
    };
    (*guard).clear();
    std::mem::drop(guard);

    if let Err(err) = EndpointLogs::app_log(
        sender.clone(),
        LogLevel::Info,
        endpoint.path(),
        "Jobs heap cleared".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    println!("\n\n\njobs heap cleared\n\n\n");

    let db = DATABASE_OBJ.lock().unwrap();
    db.get_scheduled_jobs().unwrap();
    std::mem::drop(db);

    if let Err(err) = EndpointLogs::app_log(
        sender,
        LogLevel::Info,
        endpoint.path(),
        "Jobs heap reloaded".to_string(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(format!("{err}")));
    }

    println!("\n\n\njobs heaps reloaded\n\n\n");

    let response_body = "Agent Restarted".to_string();
    (StatusCode::OK, Json(response_body))
}
