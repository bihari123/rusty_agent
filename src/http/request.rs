use super::response::{
    self, AutoUpgradeRequest, CommandRequest, HeartBeatRequest, JobName, UserCredsReq,
    VersionRequest,
};
use crate::exec::script::ScriptDetailsRequest;
use crate::exec::ScriptRequest;
use crate::http::response::UpdateConfig;
use axum::extract::Query;
use axum::routing::delete;
use axum::{
    http::{StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use std::sync::mpsc::Sender;

pub fn new_router(sender: Sender<i32>) -> Router {
    let sender_for_metric = sender.clone();
    let sender_for_jobs = sender.clone();
    let sender_for_config = sender.clone();
    let sender_for_version = sender.clone();
    let sender_for_save_script = sender.clone();
    let sender_for_password_update = sender.clone();
    let sender_for_stop_job = sender.clone();
    let sender_for_start_job = sender.clone();
    let sender_for_shutdown = sender.clone();
    let sender_for_update_script = sender.clone();
    let sender_for_config_change = sender.clone();
    let sender_for_version_change = sender.clone();
    let sender_for_agent_info = sender.clone();
    let sender_for_delete_scrip = sender.clone();
    let sender_for_health = sender.clone();
    let sender_for_pid = sender.clone();
    let sender_for_cmd = sender.clone();
    let sender_for_heatbeat = sender.clone();
    let sender_for_script_run = sender.clone();
    let sender_for_auto_upgrade = sender.clone();
    let sender_for_restart = sender.clone();
    let sender_for_version_list = sender;

    Router::new()
        .route(
            "/agent/status",
            get(|endpoint: Uri| response::response_health(endpoint, sender_for_health)),
        )
        .route(
            "/agent/metric",
            get(move |endpoint: Uri| response::response_get_metric(endpoint, sender_for_metric)),
        )
        .route(
            "/agent/config",
            get(move |endpoint: Uri| {
                response::response_get_agent_config(endpoint, sender_for_config)
            }),
        )
        .route(
            "/agent/pid",
            get(|endpoint: Uri| response::response_get_process_id(endpoint, sender_for_pid)),
        )
        .route(
            "/agent/version",
            get(move |endpoint: Uri| {
                response::response_get_agent_version(endpoint, sender_for_version)
            }),
        )
        .route(
            "/agent/heartbeat",
            post(|endpoint: Uri, payload: Json<HeartBeatRequest>| {
                response::response_hearbeat(endpoint, payload, sender_for_heatbeat)
            }),
        )
        .route(
            "/agent/command/execute",
            post(|endpoint: Uri, payload: Json<CommandRequest>| {
                response::response_os_command(endpoint, payload, sender_for_cmd)
            }),
        )
        .route(
            "/agent/userpassword/update",
            put(move |endpoint: Uri, user_creds: Json<UserCredsReq>| {
                response::response_update_password(endpoint, user_creds, sender_for_password_update)
            }),
        )
        .route(
            "/agent/shutdown",
            put(move |endpoint: Uri| response::agent_shutdown(endpoint, sender_for_shutdown)),
        )
        .route(
            "/agent/jobs/start",
            put(move |endpoint: Uri| response::start_job_execution(endpoint, sender_for_start_job)),
        )
        .route(
            "/agent/jobs/stop",
            put(move |endpoint: Uri| response::stop_job_execution(endpoint, sender_for_stop_job)),
        )
        .route(
            "/agent/jobs",
            get(|endpoint: Uri, query: Query<JobName>| {
                response::response_get_jobs_list(endpoint, query, sender_for_jobs)
            }),
        )
        .route(
            "/agent/job/execute",
            post(|endpoint: Uri, payload: Json<ScriptRequest>| {
                response::response_script_exec(endpoint, payload, sender_for_script_run)
            }),
        )
        .route(
            "/agent/job",
            put(move |endpoint: Uri, script: Json<ScriptRequest>| {
                response::response_update_script(endpoint, script, sender_for_update_script)
            }),
        )
        .route(
            "/agent/job",
            delete(move |endpoint: Uri, script: Query<ScriptDetailsRequest>| {
                response::response_script_delete(endpoint, script, sender_for_delete_scrip)
            }),
        )
        .route(
            "/agent/job",
            post(move |endpoint: Uri, script: Json<ScriptRequest>| {
                response::response_save_script(endpoint, script, sender_for_save_script)
            }),
        )
        .route(
            "/agent/config",
            put(move |endpoint: Uri, config: Json<UpdateConfig>| {
                response::response_update_config(endpoint, config, sender_for_config_change)
            }),
        )
        .route(
            "/agent/config/auto_upgrade",
            put(
                move |endpoint: Uri, auto_upgrade: Json<AutoUpgradeRequest>| {
                    response::response_auto_upgrade(endpoint, auto_upgrade, sender_for_auto_upgrade)
                },
            ),
        )
        .route(
            "/agent/version",
            put(move |endpoint: Uri, request: Json<VersionRequest>| {
                response::response_agent_version_change(
                    endpoint,
                    request,
                    sender_for_version_change,
                )
            }),
        )
        .route(
            "/agent/version/list",
            get(move |endpoint: Uri| {
                response::response_get_agent_version_list(endpoint, sender_for_version_list)
            }),
        )
        .route(
            "/agent/info",
            get(move |endpoint: Uri| {
                response::response_get_agent_info(endpoint, sender_for_agent_info)
            }),
        )
        .route(
            "/agent/restart",
            put(move |endpoint: Uri| response::agent_restart(endpoint, sender_for_restart)),
        )
}

pub async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "NOT FOUND")
}
