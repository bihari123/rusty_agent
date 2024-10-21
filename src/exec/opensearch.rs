use crate::http::MetricResponse;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    process::Command,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenSearchError {
    #[error("Error while running the opensearch curl command: {0}")]
    OpenSearchRunIOError(#[from] std::io::Error),
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}
impl fmt::Debug for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => write!(f, "{:?}", "ERROR"),
            Self::Warn => write!(f, "{:?}", "WARN"),
            Self::Info => write!(f, "{:?}", "INFO"),
            Self::Debug => write!(f, "{:?}", "DEBUG"),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenSearchAgentAppLogRequest {
    pub agent_id: String,
    pub endpoint: String,
    pub host_name: String,
    pub job_name: String,
    pub level: LogLevel,
    pub logger_name: String,
    pub message: String,
    pub timestamp: String,
}
impl fmt::Display for OpenSearchAgentAppLogRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"agentId", &self.agent_id)
            .entry(&"endpoint", &self.endpoint)
            .entry(&"hostname", &self.host_name)
            .entry(&"jobname", &self.job_name)
            .entry(&"level", &self.level)
            .entry(&"loggerName", &self.logger_name)
            .entry(&"message", &self.message)
            .entry(&"timestamp", &self.timestamp)
            .finish()
    }
}

pub fn send_agent_app_data_to_opensearch(
    data: OpenSearchAgentAppLogRequest,
    opensearch_endpoint: String,
    index: String,
) -> Result<(), OpenSearchError> {
    println!("{}\n", serde_json::json!(
        {
            "type": "app",
            "log": data,
            "domain": opensearch_endpoint,
            "index": index,
        }
    ));

    std::thread::spawn(move || {
        let mut child = match Command::new("curl")
            .arg("-u")
            .arg(format!("{}:{}", "opensearchdb-dev", "QAZplm-925"))
            .arg("--no-keepalive")
            .arg("-H")
            .arg("Connection: close")
            .arg("--connect-timeout")
            .arg("10")
            .arg("-X")
            .arg("POST")
            .arg(format!("{opensearch_endpoint}/{index}/_doc"))
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(format!("{data}"))
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                eprintln!("Error while sending logs to opensearch: {err}");
                return;
            }
        };

        match child.wait() {
            Ok(ok) => {
                println!(
                    "Attempted to send log with timestamp {:?} and exit status: {ok:?}.\n",
                    data.timestamp,
                );
            }
            Err(err) => {
                eprintln!(
                    "Error while sending log with timestamp {:?} to opensearch: {err}.\n",
                    data.timestamp,
                );
            }
        }
    });

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenSearchHealthDiscoveryRequest {
    pub agent_id: String,
    pub host_name: String,
    pub metrics: MetricResponse,
    pub port: u16,
    pub pid: i32,
    pub status: String,
    pub timestamp: String,
}

impl fmt::Display for OpenSearchHealthDiscoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"agent_id", &self.agent_id)
            .entry(&"host_name", &self.host_name)
            .entry(&"metrics", &self.metrics)
            .entry(&"port", &self.port)
            .entry(&"pid", &self.pid)
            .entry(&"status", &self.status)
            .entry(&"timestamp", &self.timestamp)
            .finish()
    }
}

pub fn send_health_discovery_opensearch(
    data: OpenSearchHealthDiscoveryRequest,
    opensearch_endpoint: String,
    index: String,
) -> Result<(), OpenSearchError> {
    println!("{}\n", serde_json::json!(
        {
            "type": "health",
            "log": data,
            "domain": opensearch_endpoint,
            "index": index,
        }
    ));

    std::thread::spawn(move || {
        let mut child = match Command::new("curl")
            .arg("--no-keepalive")
            .arg("-u")
            .arg(format!("{}:{}","opensearchdb-dev","QAZplm-925"))
            .arg("-H")
            .arg("Connection: close")
            .arg("--connect-timeout")
            .arg("10")
            .arg(format!( "{opensearch_endpoint}/{index}/_doc"))
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(format!(
                "{{\"agentId\": {:?}, \"hostname\": {:?}, \"metrics\": {{\"cpuUsage\": {}, \"diskUsage\": {}, \"memoryUsage\": {}, \"osVersion\": {:?}, \"port\": {}, \"rustVersion\": {:?}, \"uptime\": {} }}, \"pid\": {}, \"status\": {:?}, \"timestamp\": {:?} }}",
                data.agent_id,
                data.host_name,
                data.metrics.cpu_usage,
                data.metrics.disk_usage,
                data.metrics.memory,
                data.metrics.os_version,
                data.port,
                data.metrics.rust_version,
                data.metrics.up_time,
                data.pid,
                data.status,
                data.timestamp,
            ))
            .spawn() {
                Ok(child) => child,
                Err(err) => {
                    eprintln!("Error while sending health logs to opensearch: {err}");
                    return;
                }
            };

        match child.wait() {
            Ok(ok) => {
                println!(
                    "Attempted to send log with timestamp {:?} and exit status: {ok:?}.\n",
                    data.timestamp,
                );
            }
            Err(err) => {
                eprintln!(
                    "Error while sending log with timestamp {:?} to opensearch: {err}.\n",
                    data.timestamp,
                );
            }
        }
    });

    Ok(())
}

pub fn remove_new_line(input: String) -> String {
    input.replace('\n', "")
}

pub fn formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
