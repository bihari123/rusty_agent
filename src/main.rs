#![allow(non_snake_case)]

mod exec;
mod http;
mod metrics;
mod utils;

use crate::exec::global::DATABASE_OBJ;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    process::{self, Child},
    sync::{
        atomic::AtomicBool,
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
};

use crate::{
    exec::{global::GLOBAL_JOBS_HEAP, scheduled_job::Job},
    http::server::{job_scheduler, process},
};
use clap::Parser;
use http::{config::ServerConfig, server::Server};

#[derive(Parser, Debug)]
#[command(about, version)]
struct AgentArgs {
    /// Takes the value describes passed and tries to host the server on that port. In case of
    /// failure, primary port or any empty available port is chosen.
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = AgentArgs::parse();

    let mut port_flag: u16 = 0;

    if let Some(port) = args.port {
        port_flag = {
            // Check if the port number is valid
            #[allow(unused_comparisons)]
            if !(1..=65535).contains(&port) {
                eprintln!("Error: Port number must be between 1 and 65535.");
                return;
            }
            port
        };
        println!("Recieved port number: {port_flag}");
    }

    let path = Path::new("./rusty_assets/job_output");

    if !path.exists() {
        if let Err(err) = fs::create_dir_all(path) {
            eprintln!(
                "Error while creating a path {} object {err}",
                path.to_string_lossy(),
            );
            return;
        }
    }

    let certs_directory = "./certificates";
    // Specify the local file path where you want to save the response
    let path = Path::new(certs_directory);

    if !path.exists() {
        if let Err(err) = fs::create_dir_all(path) {
            eprintln!(
                "Error while creating a path {} object {err}",
                path.to_string_lossy(),
            );
            return;
        }
        if let Err(e) = utils::download_cert_n_key() {
            eprintln!("Failed to download certs and key: {e}");
            process::exit(0);
        }
    }

    let ip_addr: String;
    let min_port: u16;
    let max_port: u16;
    let primary_port: u16;
    let auto_upgrade: bool;
    let opensearch_endpoint: String;
    let opensearch_application_log_index: String;
    let opensearch_health_discovery_log_index: String;
    let opensearch_username: String;
    let opensearch_password: String;
    let log_level: String;

    {
        let db = match DATABASE_OBJ.lock() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("Error getting the lock for Database Object: {e}");
                return;
            }
        };

        if let Err(err) = db.init() {
            eprintln!("Error during database initialization: {err}");
            return;
        }

        match db.get_server_config() {
            Ok((
                var_ip_addr,
                var_primary_port,
                var_min_port,
                var_max_port,
                var_auto_upgrade,
                var_opensearch_domain_endpoint,
                var_opensearch_application_log_index,
                var_opensearch_health_discovery_log_index,
                var_opensearch_user_name,
                var_opensearch_user_pass,
                var_log_level,
            )) => {
                ip_addr = var_ip_addr;
                primary_port = var_primary_port;
                min_port = var_min_port;
                max_port = var_max_port;
                auto_upgrade = var_auto_upgrade;
                opensearch_endpoint = var_opensearch_domain_endpoint;
                opensearch_application_log_index = var_opensearch_application_log_index;
                opensearch_health_discovery_log_index = var_opensearch_health_discovery_log_index;
                opensearch_username = var_opensearch_user_name;
                opensearch_password = var_opensearch_user_pass;
                log_level = var_log_level;
            }
            Err(err) => {
                eprintln!("Error while getting server config: {err}");
                return;
            }
        }

        db.get_scheduled_jobs().unwrap();
    }

    let temp_config = ServerConfig {
        ip_addr: ip_addr.clone(),
        min_port,
        max_port,
        primary_port,
        opensearch_password: opensearch_password.clone(),
        opensearch_application_log_index: opensearch_application_log_index.clone(),
        opensearch_health_discovery_log_index: opensearch_health_discovery_log_index.clone(),
        opensearch_username: opensearch_username.clone(),
        opensearch_endpoint: opensearch_endpoint.clone(),
        log_level: log_level.clone(),
        auto_upgrade,
    };

    let config = Arc::new(Mutex::new(ServerConfig {
        ip_addr,
        primary_port,
        min_port,
        max_port,
        opensearch_endpoint,
        opensearch_application_log_index,
        opensearch_health_discovery_log_index,
        opensearch_username,
        opensearch_password,
        auto_upgrade,
        log_level,
    }));

    let server = Server::new(config);

    let (sender, reciever): (Sender<i32>, Receiver<i32>) = channel();
    let future = server.run(sender.clone(), port_flag);

    let mut keep_job_running = true;
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let job_heap_clone = GLOBAL_JOBS_HEAP.clone();
    //    let mut child_processes_opensearch_health_logs: HashMap<u32, Child> = HashMap::new();

    let mut child_processes_jobs: HashMap<u32, Child> = HashMap::new();
    let mut job_pid_map: HashMap<u32, Job> = HashMap::new();

    let job_scheduler = job_scheduler(
        Arc::clone(&job_heap_clone),
        sender.clone(),
        reciever,
        &mut child_processes_jobs,
        &mut job_pid_map,
        &shutdown_flag,
        &mut keep_job_running,
    );

    let process = process(&temp_config, sender);

    tokio::join!(future, job_scheduler, process);
}
