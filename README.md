# rusty_agent
`rusty_agent` is a high-performance, asynchronous HTTPS server implemented in Rust using the Tokio runtime. It's designed for efficient system monitoring, job scheduling, and remote command execution with a minimal memory footprint (&lt;10MB).


## Technical Overview

- **Language:** Rust
- **Async Runtime:** Tokio
- **Web Framework:** Custom implementation using Tokio's `TcpListener` and `TlsAcceptor`
- **Database:** SQLite with custom encryption wrapper
- **Serialization:** Serde for JSON handling
- **Cryptography:** Custom implementation for database encryption
- **Cross-platform:** Windows and Linux support with conditional compilation

## Core Features

1. **Asynchronous HTTPS Server**
   - Custom implementation using Tokio's async I/O primitives
   - TLS support for secure communication
   - Optimized for low memory usage (<10MB)

2. **RESTful API**
   - JSON-based request/response handling
   - Endpoints for configuration, metrics, job management, and system operations

3. **System Metrics Monitoring**
   - Real-time CPU, memory, and disk usage tracking
   - OS-specific implementations for accurate resource measurement

4. **Cron Job Scheduling and Execution**
   - In-memory job queue using `BinaryHeap` for efficient scheduling
   - Support for various script types (Python, Bash)
   - Asynchronous job execution

5. **Secure Storage**
   - SQLite database with custom encryption-at-rest implementation
   - Parameterized queries to prevent SQL injection

6. **Version Management**
   - Self-update mechanism
   - Version compatibility checks

7. **Logging and Monitoring**
   - Structured logging
   - Integration with OpenSearch for centralized log management

## API Endpoints

The server exposes RESTful API endpoints for various operations:

1. `GET /agent/config`: Retrieve agent configuration
2. `PUT /agent/config`: Update agent configuration
3. `GET /agent/metric`: Fetch system metrics
4. `POST /agent/heartbeat`: Send heartbeat to OpenSearch
5. `POST /agent/command/execute`: Execute remote commands
6. `GET/POST/PUT/DELETE /agent/job`: CRUD operations for scheduled jobs
7. `GET/PUT /agent/version`: Manage agent version
8. `PUT /agent/shutdown`: Gracefully shut down the agent
9. `PUT /agent/restart`: Restart the agent

## Core Data Structures

1. **AgentConfig**
   ```rust
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
   ```

2. **MetricResponse**
   ```rust
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
   ```

3. **Job**
   ```rust
   pub struct Job {
       pub name: String,
       pub execute_at: SystemTime,
       pub cron_expression: String,
       pub script_content: String,
       pub arguments: String,
       pub script_type: u64,
       pub opensearch_index: String,
       pub opensearch_enabled: u64,
   }
   ```

## Security Considerations

- HTTPS server for encrypted communication
- Custom encryption for SQLite database at rest
- Base64 encoding for script payloads
- Parameterized SQL queries to prevent injection attacks
- Secure handling of sensitive configuration data

## Cross-platform Implementation

The agent uses conditional compilation to support both Windows and Linux:

```rust
#[cfg(target_os = "windows")]
// Windows-specific implementations

#[cfg(any(target_os = "unix", target_os = "linux"))]
// Linux/Unix-specific implementations
```

This ensures optimal performance and accuracy on each supported platform.

## Building and Running

1. Ensure Rust and Cargo are installed (minimum supported Rust version: [specify version])
2. Clone the repository: `git clone https://github.com/bihari123/rusty_agent.git`
3. Build the project: `cargo build --release`
4. Execute the binary: `./target/release/rusty_agent [PORT]`

## Testing

- Unit tests: `cargo test`
- Integration tests: [Specify how to run integration tests]
- Load testing: [Specify load testing procedures or tools]

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch: `git checkout -b feature-branch-name`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-branch-name`
5. Submit a pull request

Please ensure your code adheres to the project's coding standards and includes appropriate tests.

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

### GNU General Public License v3.0

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

For the full license text, please see the [LICENSE](LICENSE) file in the project repository or visit [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html).
GPL-3.0 license

