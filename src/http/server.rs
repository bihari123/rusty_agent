use super::config::ServerConfig;
use crate::exec::command::remove_undesirable_chars;
use crate::exec::global::PORT_NUMBER;
use crate::exec::opensearch::{
    formatted_timestamp, remove_new_line, send_health_discovery_opensearch, LogLevel,
    OpenSearchHealthDiscoveryRequest,
};
use crate::exec::scheduled_job::Job;
use crate::exec::ScriptRequest;
use crate::http::auth::auth;
use crate::http::request::handler_404;
use crate::http::request::new_router;
use crate::http::response::{datetime_to_systemtime, time_until_next_run};
use crate::utils;
use crate::utils::encrypt::get_database_decrypted;
use crate::utils::logger::JobLogs;
use axum::middleware;
use axum_server::tls_rustls::RustlsConfig;
use hostname::get_hostname;
use sqlite::State;
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::process::{self, Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

// In seconds
const PROCESS_INTERVAL: u64 = 300;

pub struct Server {
    config: Arc<Mutex<ServerConfig>>,
}

impl Server {
    pub const fn new(config: Arc<Mutex<ServerConfig>>) -> Self {
        Self { config }
    }

    pub async fn run(&self, sender: Sender<i32>, port_flag: u16) {
        let server_config = match self.config.lock() {
            Ok(val) => val,
            Err(e) => {
                eprintln!("could not acquire the lock of config: {e}");
                process::exit(0);
            }
        };

        let port_number = match port_flag {
            0 => {
                let Some(port_available) = find_available_port(
                    server_config.ip_addr.as_str(),
                    server_config.primary_port,
                    server_config.min_port,
                    server_config.max_port,
                ) else {
                    eprintln!("Failed to establish a connection ");
                    return;
                };
                port_available
            }

            n => {
                let addr: SocketAddr =
                    match format!("{}:{}", server_config.ip_addr.as_str(), n).parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            println!("Unable to parse socket address: {e} ");
                            process::exit(0);
                        }
                    };

                loop {
                    if TcpListener::bind(addr).is_ok() {
                        break;
                    } else {
                        sleep(Duration::from_secs(2)).await;
                    }
                }

                n
            }
        };

        let mut port_selected = match PORT_NUMBER.lock() {
            Ok(port_number) => port_number,
            Err(e) => {
                eprintln!("Error getting the lock of the port_number: {e}");
                process::exit(0);
            }
        };
        *port_selected = port_number;
        std::mem::drop(port_selected);

        let addr: SocketAddr = match format!("{}:{}", &server_config.ip_addr, port_number).parse() {
            Ok(addr) => addr,
            Err(e) => {
                println!("Unable to parse socket address: {e}");
                process::exit(0);
            }
        };

        println!("Listening on https://{addr:>5}");
        println!("{}\n", "=".repeat(34));

        let router = new_router(sender)
            .fallback(handler_404)
            .route_layer(middleware::from_fn(auth));

        let cert_config = match RustlsConfig::from_pem_file(
            "certificates/cert.pem",
            "certificates/key.pem",
        )
        .await
        {
            Ok(certs_config) => certs_config,
            Err(e) => {
                eprintln!("Error getting the certificates: {e}");
                return;
            }
        };

        if let Err(e) = axum_server::bind_rustls(addr, cert_config)
            .serve(router.into_make_service())
            .await
        {
            if e.to_string().to_lowercase().contains("certificate expired") {
                eprintln!("Certificate_expired. Fetching it from master");
                if let Err(e) = utils::remove_prev_certificate_and_key() {
                    eprintln!("Failed to remove previous certs: {e}");
                    process::exit(0);
                }
                if let Err(e) = utils::download_cert_n_key() {
                    eprintln!("Failed to download certs and key: {e}");
                    process::exit(0);
                }
            } else {
                eprintln!("Error: {e:?}");
            }
        }
    }
}

pub fn find_available_port(
    ip: &str,
    primary_port: u16,
    min_port: u16,
    max_port: u16,
) -> Option<u16> {
    if primary_port < min_port || primary_port > max_port || min_port > max_port {
        return None;
    }

    let mut addr: SocketAddr = match format!("{ip}:{primary_port}").parse() {
        Ok(addr) => addr,
        Err(e) => {
            println!("Unable to parse socket address {ip} {primary_port}: {e}");
            process::exit(0);
        }
    };

    if TcpListener::bind(addr).is_ok() {
        return Some(primary_port);
    } else {
        for p in min_port..max_port {
            addr = match format!("{ip}:{p}").parse() {
                Ok(addr) => addr,
                Err(e) => {
                    println!("Unable to parse socket address {ip} {p}: {e}");
                    process::exit(0);
                }
            };

            if TcpListener::bind(addr).is_ok() {
                return Some(p);
            }
        }
    }
    None
}

pub async fn job_scheduler(
    job_heap_clone: Arc<Mutex<BinaryHeap<Job>>>,
    sender: Sender<i32>,
    reciever: Receiver<i32>,
    child_processes_jobs: &mut HashMap<u32, Child>,
    job_pid_map: &mut HashMap<u32, Job>,
    shutdown_flag: &AtomicBool,
    keep_job_running: &mut bool,
) {
    loop {
        sleep(Duration::from_secs(2)).await;

        let mut completed_processes_jobs: Vec<u32> = Vec::new();
        let mut task_queue = job_heap_clone.lock().unwrap();

        match reciever.try_recv() {
            Ok(0) => {
                // 0 for shutdown
                *keep_job_running = false;
                // shutdown = true;
                shutdown_flag.store(true, Ordering::Relaxed);
            }
            Ok(1) => {
                // 1 for starting
                println!("\nGot the signal to start the job execution.\nStarting the jobs\n");
                *keep_job_running = true;
            }
            // 2 for stoping the jobs
            Ok(2) => *keep_job_running = false,
            Ok(n) => eprintln!("Unknown signal {n}"),
            Err(_) => {}
        }

        if *keep_job_running {
            match (*task_queue).peek() {
                Some(task) if task.execute_at <= SystemTime::now() => {
                    let task = (*task_queue).pop().unwrap();
                    let opensearch_enabled = task.opensearch_enabled > 0;

                    let script_req = ScriptRequest {
                        script_name: task.name.clone(),
                        content: task.script_content.clone(),
                        script_type: task.script_type,
                        arguments: task.arguments.clone(),
                        async_exec: true,
                        cron_expression: task.cron_expression.clone(),
                        opensearch_enabled,
                        opensearch_index: task.opensearch_index.clone(),
                    };

                    let script_content_raw =
                        remove_undesirable_chars(script_req.content.as_str()).to_string();

                    let error_file = File::create(format!(
                        "./rusty_assets/job_output/{}.error",
                        script_req.script_name.clone(),
                    ))
                    .expect("Failed to create error file.");

                    let output_file = File::create(format!(
                        "./rusty_assets/job_output/{}.output",
                        script_req.script_name.clone(),
                    ))
                    .expect("Failed to create error file.");

                    let child = match script_req.script_type {
                        0 => {
                            let proc = Command::new("python")
                                .arg("-c")
                                .arg(script_content_raw.as_str())
                                .stderr(error_file)
                                .stdout(output_file)
                                .spawn()
                                .expect("failed to execute process");
                            proc
                        }
                        1 => {
                            let proc = Command::new("bash")
                                .arg("-c")
                                .arg(script_content_raw.as_str())
                                .stderr(error_file)
                                .stdout(output_file)
                                .spawn()
                                .expect("failed to execute process");
                            proc
                        }
                        _ => continue,
                    };

                    let script_pid = child.id();

                    child_processes_jobs.insert(script_pid, child);

                    job_pid_map.insert(
                        script_pid,
                        Job {
                            name: task.name.clone(),
                            execute_at: SystemTime::now(),
                            cron_expression: task.cron_expression.clone(),
                            arguments: task.arguments.clone(),
                            script_type: task.script_type,
                            script_content: task.script_content.clone(),
                            opensearch_index: task.opensearch_index.clone(),
                            opensearch_enabled: task.opensearch_enabled,
                        },
                    );
                }
                _ => {
                    // Sleep for a short duration before checking the queue again.
                    sleep(Duration::from_millis(100)).await;
                }
            }
        } else if shutdown_flag.load(Ordering::Relaxed) && child_processes_jobs.is_empty() {
            println!("\n\nAll the child processes completed. Stopping the agent\n\n");
            process::exit(0);
        }

        for (pid, process) in child_processes_jobs.iter_mut() {
            match process.try_wait() {
                Ok(Some(exit_status)) => {
                    let exit_code = exit_status.code().unwrap_or(
                        1, // Default exit code for signal termination
                    );

                    if exit_code == 1 {
                        eprintln!("couldn't get the exit code of the process: {pid}");
                    }
                    // Remove the completed process and its error file from the list
                    completed_processes_jobs.push(*pid);
                }
                Ok(None) => {
                    // The process is still running
                    // Perform any necessary operations
                }
                Err(err) => {
                    eprintln!("Failed to check status for PID {pid}: {err}");
                }
            }
        }

        // Remove the completed processes and their error files from the HashMap
        for pid in completed_processes_jobs {
            child_processes_jobs.remove(&pid);

            let mut job = job_pid_map.remove(&pid).unwrap();

            send_job_errors_opensearch(sender.clone(), &mut job);
            send_job_output_opensearch(sender.clone(), &mut job);

            if let Err(err) = std::fs::remove_file(format!(
                "./rusty_assets/job_output/{}.error",
                job.name.clone()
            )) {
                eprintln!(
                    "Failed to delete error file. ./rusty_assets/job_output/{}.error:  {}",
                    job.name.clone(),
                    err
                );
            }

            if let Err(err) = std::fs::remove_file(format!(
                "./rusty_assets/job_output/{}.output",
                job.name.clone()
            )) {
                eprintln!(
                    "Failed to delete error file. ./rusty_assets/job_output/{}.output:  {}",
                    job.name.clone(),
                    err
                );
            }

            let schedule_time_sys_time =
                time_until_next_run(job.cron_expression.clone().as_str()).unwrap();
            let schedule_time_date_time = datetime_to_systemtime(schedule_time_sys_time);

            job.execute_at = schedule_time_date_time;

            (*task_queue).push(job);
        }
    }
}

pub async fn process(config: &ServerConfig, sender: Sender<i32>) {
    loop {
        sleep(Duration::from_secs(PROCESS_INTERVAL)).await;

        let metrics = crate::metrics::metrics::get_agent_metric(sender.clone()).unwrap();

        let host_name = get_hostname().unwrap_or_default();
        let pid = std::process::id();
        let mut port = 0;

        {
            let (db, _decryptor) = get_database_decrypted(Some(sender.clone())).unwrap();

            let Ok(mut stmt) = db.conn.prepare(format!(
                "SELECT * FROM server_config WHERE param_name = \'{}\'",
                "server_port"
            )) else {
                eprintln!("Error while connecting to database from `process`");
                continue;
            };
            if matches!(stmt.next(), Ok(State::Row)) {
                let global_value = stmt.read::<String, _>("global_value").unwrap();
                let local_value = stmt.read::<String, _>("local_value").unwrap();

                let final_value = if !local_value.is_empty() {
                    local_value
                } else {
                    global_value
                };

                port = final_value.parse().unwrap();
            }
        }

        let data = OpenSearchHealthDiscoveryRequest {
            host_name,
            agent_id: String::default(),
            timestamp: formatted_timestamp(),
            port,
            pid: pid as i32,
            metrics,
            status: "active".to_string(),
        };

        send_health_discovery_opensearch(
            data,
            config.opensearch_endpoint.clone(),
            config.opensearch_health_discovery_log_index.clone(),
        )
        .unwrap();
    }
}

fn send_job_output_opensearch(sender: Sender<i32>, job: &mut Job) {
    let mut output_content = String::new();

    if File::open(format!(
        "./rusty_assets/job_output/{}.output",
        job.name.clone()
    ))
    .and_then(|mut file| file.read_to_string(&mut output_content))
    .is_err()
    {
        return;
    }

    if job.opensearch_enabled <= 0 {
        return;
    }
    if output_content.is_empty() {
        return;
    }

    let output_content = remove_new_line(output_content);

    println!(
        "{}",
        serde_json::json!(
            {
                "jobName": job.name.clone(),
                "output": output_content,
            }
        )
    );

    JobLogs::app_log(
        sender,
        LogLevel::Info,
        job,
        format!("job {} output {}", job.name.clone(), output_content,),
    )
    .unwrap();
}

fn send_job_errors_opensearch(sender: Sender<i32>, job: &mut Job) {
    let mut error_content = String::new();

    if File::open(format!(
        "./rusty_assets/job_output/{}.error",
        job.name.clone()
    ))
    .and_then(|mut file| file.read_to_string(&mut error_content))
    .is_err()
    {
        return;
    }

    if error_content.is_empty() {
        return;
    }
    if job.opensearch_enabled <= 0 {
        return;
    }

    let error_content = remove_new_line(error_content);

    eprintln!(
        "job: {} failed with error : {}",
        job.name.clone(),
        error_content
    );

    JobLogs::app_log(
        sender,
        LogLevel::Info,
        job,
        format!(
            "job {} failed with error {}",
            job.name.clone(),
            error_content,
        ),
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_available_port() {
        assert_eq!(find_available_port("localhost", 8080, 8060, 8070), None);

        assert_eq!(find_available_port("localhost", 8080, 8070, 8060), None);
        assert_eq!(
            find_available_port("localhost", 8080, 8060, 8090),
            Some(8080)
        );
    }
}
