use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AgentConfig {
    pub cron_agent_checksum: String,
    pub opensearch_non_prod_domain_endpoint: String,
    pub opensearch_prod_domain_endpoint: String,
    pub cron_agent_config_monitoring: String,
    pub agent_id: u16,
    pub script_execution_allowed_path: String,
    pub cron_agent_autoupgrade_check: String,
    pub cron_agent_discovery: String,
    pub logging_file_name: String,
    pub cron_agent_health_discovery: String,
    pub version: String,
    pub opensearch_non_prod_user_name: String,
    pub opensearch_non_prod_pass_word: String,
    pub auto_upgrade: bool,
    pub install_dir: String,
    pub port: u16,
    pub checksum_downloadbatch_slot_max_download: u16,
    pub rust_install_path: String,
    pub checksum_downloadbatch_slot_minute: u16,
}

impl fmt::Display for AgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"cron_agent_checksum", &self.cron_agent_checksum)
            .entry(
                &"opensearch_non_prod_domain_endpoint",
                &self.opensearch_non_prod_domain_endpoint,
            )
            .entry(
                &"opensearch_prod_domain_endpoint",
                &self.opensearch_prod_domain_endpoint,
            )
            .entry(
                &"cron_agent_config_monitoring",
                &self.cron_agent_config_monitoring,
            )
            .entry(&"agent_id", &self.agent_id)
            .entry(
                &"script_execution_allowed_path",
                &self.script_execution_allowed_path,
            )
            .entry(
                &"cron_agent_autoupgrade_check",
                &self.cron_agent_autoupgrade_check,
            )
            .entry(&"cron_agent_discovery", &self.cron_agent_discovery)
            .entry(&"logging_file_name", &self.logging_file_name)
            .entry(
                &"cron_agent_health_discovery",
                &self.cron_agent_health_discovery,
            )
            .entry(&"version", &self.version)
            .entry(
                &"opensearch_non_prod_user_name",
                &self.opensearch_non_prod_user_name,
            )
            .entry(
                &"opensearch_non_prod_pass_word",
                &self.opensearch_non_prod_pass_word,
            )
            .entry(&"auto_upgrade", &self.auto_upgrade)
            .entry(&"install_dir", &self.install_dir)
            .entry(&"port", &self.port)
            .entry(
                &"checksum_downloadbatch_slot_max_download",
                &self.checksum_downloadbatch_slot_max_download,
            )
            .entry(&"rust_install_path", &self.rust_install_path)
            .entry(
                &"checksum_downloadbatch_slot_minute",
                &self.checksum_downloadbatch_slot_minute,
            )
            .finish()
    }
}

pub struct ServerConfig {
    pub ip_addr: String,
    pub primary_port: u16,
    pub min_port: u16,
    pub max_port: u16,
    pub opensearch_endpoint: String,
    pub opensearch_application_log_index: String,
    pub opensearch_health_discovery_log_index: String,
    pub opensearch_username: String,
    pub opensearch_password: String,
    pub auto_upgrade: bool,
    pub log_level: String,
}
