//! External module host: spawns/connects to external gRPC modules
//! and wraps them behind the `AnalysisModule` trait.

use crate::client::AnalysisModuleClient;
use crate::config::{ExternalModuleConfig, TransportMode};
use crate::error::PluginError;
use crate::proto::{
    AnalysisRequest, DescribeRequest, ExplainRequest, FileInfoProto, FindingProto, FixRequest,
};
use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, ModuleInfo, RuleExplanation,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;
use std::process::Child;
use std::sync::Mutex;
use tonic::transport::Channel;

/// An external module accessed over gRPC.
///
/// Wraps a tonic gRPC client and implements the `AnalysisModule` trait so that
/// external modules are indistinguishable from built-in ones at the `ModuleHost` level.
///
/// When running in `Container` mode, the struct captures the Docker container ID
/// and stops the container on drop.
pub struct ExternalModule {
    config: ExternalModuleConfig,
    /// Cached module info from the Describe RPC.
    cached_info: Mutex<Option<ModuleInfo>>,
    /// gRPC channel (connected lazily).
    channel: Mutex<Option<Channel>>,
    /// Spawned child process (command mode only).
    _child: Mutex<Option<Child>>,
    /// Docker container ID (container mode only), used for cleanup on drop.
    container_id: Mutex<Option<String>>,
}

impl ExternalModule {
    /// Create a new external module wrapper from config.
    pub fn new(config: ExternalModuleConfig) -> Self {
        Self {
            config,
            cached_info: Mutex::new(None),
            channel: Mutex::new(None),
            _child: Mutex::new(None),
            container_id: Mutex::new(None),
        }
    }

    /// Check if Docker is available on the system.
    pub fn docker_available() -> bool {
        std::process::Command::new("docker")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get or create the gRPC channel. This handles connecting based on the
    /// transport mode (command spawn, direct gRPC, or Docker container).
    fn get_or_connect_channel(&self) -> std::result::Result<Channel, PluginError> {
        let mut guard = self.channel.lock().unwrap();
        if let Some(ref ch) = *guard {
            return Ok(ch.clone());
        }

        let endpoint_str = match self.config.mode {
            TransportMode::Command => {
                let cmd = self.config.command.as_deref().unwrap_or("");
                // TOCTOU note: We allocate an ephemeral port by binding to :0 and
                // reading the assigned port, then drop the listener before the child
                // process binds. Another process could claim the port in between.
                // We mitigate this with a retry loop (with backoff) when connecting
                // to the child, which handles the rare collision case.
                let port = self.config.port.unwrap_or_else(|| {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
                    listener
                        .and_then(|l| l.local_addr().ok())
                        .map(|a| a.port())
                        .unwrap_or(50051)
                });

                let child = std::process::Command::new(cmd)
                    .arg("--port")
                    .arg(port.to_string())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| PluginError::SpawnFailed {
                        command: cmd.to_owned(),
                        reason: e.to_string(),
                    })?;

                *self._child.lock().unwrap() = Some(child);
                format!("http://127.0.0.1:{port}")
            }
            TransportMode::Grpc => self.config.resolve_endpoint(),
            TransportMode::Container => {
                if !Self::docker_available() {
                    return Err(PluginError::DockerUnavailable(
                        "docker command not found or not running".to_owned(),
                    ));
                }
                let image = self.config.image.as_deref().unwrap_or("");
                let port = self.config.port.unwrap_or(50051);
                let output = std::process::Command::new("docker")
                    .args(["run", "-d", "--rm", "-p"])
                    .arg(format!("{port}:{port}"))
                    .arg(image)
                    .output()
                    .map_err(|e| PluginError::SpawnFailed {
                        command: format!("docker run {image}"),
                        reason: e.to_string(),
                    })?;
                // Capture the container ID so we can stop it on drop.
                let cid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if !cid.is_empty() {
                    *self.container_id.lock().unwrap() = Some(cid);
                }
                format!("http://127.0.0.1:{port}")
            }
        };

        // Retry with exponential backoff to handle TOCTOU port races and slow
        // child/container startup. Tries up to 5 times (total ~3.1 s max wait).
        let max_retries = 5u32;
        let mut last_err = None;
        for attempt in 0..max_retries {
            match block_on(async {
                Channel::from_shared(endpoint_str.clone())
                    .map_err(|e| PluginError::Transport(e.to_string()))?
                    .connect()
                    .await
                    .map_err(|e| PluginError::Transport(e.to_string()))
            }) {
                Ok(ch) => {
                    *guard = Some(ch.clone());
                    return Ok(ch);
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < max_retries {
                        let backoff = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
                        std::thread::sleep(backoff);
                    }
                }
            }
        }
        // All retries exhausted.
        Err(last_err.unwrap())
    }

    fn make_client(&self) -> std::result::Result<AnalysisModuleClient, PluginError> {
        let channel = self.get_or_connect_channel()?;
        Ok(AnalysisModuleClient::new(channel))
    }
}

/// Run a future to completion, spawning a new tokio runtime if needed.
fn block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We are inside a tokio runtime; run on a blocking thread.
            std::thread::scope(|s| s.spawn(|| handle.block_on(fut)).join().unwrap())
        }
        Err(_) => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(fut)
        }
    }
}

impl AnalysisModule for ExternalModule {
    fn describe(&self) -> ModuleInfo {
        // Return cached info if available.
        if let Some(ref info) = *self.cached_info.lock().unwrap() {
            return info.clone();
        }

        // Try to call the remote Describe RPC.
        let result: std::result::Result<ModuleInfo, PluginError> = (|| {
            let mut client = self.make_client()?;
            let info_proto = block_on(async {
                client
                    .describe(DescribeRequest {})
                    .await
                    .map_err(|e| PluginError::Transport(e.to_string()))
            })?;
            let info: ModuleInfo = info_proto.into();
            Ok(info)
        })();

        match result {
            Ok(info) => {
                *self.cached_info.lock().unwrap() = Some(info.clone());
                info
            }
            Err(_) => {
                // Fallback: return minimal info from config.
                ModuleInfo {
                    id: self.config.id.clone(),
                    name: format!("{} (external)", self.config.id),
                    version: "0.0.0".to_owned(),
                    languages: vec![],
                    capabilities: vec!["analyze".to_owned()],
                    rules: vec![],
                }
            }
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let mut client = self
            .make_client()
            .map_err(|e| ChaffraError::Analysis(e.to_string()))?;

        let request = AnalysisRequest {
            files: files.iter().map(FileInfoProto::from).collect(),
            config: config.clone(),
            enabled_rules: vec![],
            language: String::new(),
        };

        let response = block_on(async {
            client
                .analyze(request)
                .await
                .map_err(|e| ChaffraError::Analysis(e.to_string()))
        })?;

        Ok(response.into())
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        let mut client = self
            .make_client()
            .map_err(|e| ChaffraError::Analysis(e.to_string()))?;

        let request = ExplainRequest {
            rule_id: rule_id.to_owned(),
        };

        let response = block_on(async {
            client
                .explain(request)
                .await
                .map_err(|e| ChaffraError::Analysis(e.to_string()))
        })?;

        Ok(response.into())
    }

    fn fix(&self, findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>> {
        let mut client = self
            .make_client()
            .map_err(|e| ChaffraError::Analysis(e.to_string()))?;

        let request = FixRequest {
            findings: findings.iter().map(FindingProto::from).collect(),
            dry_run,
        };

        let response = block_on(async {
            client
                .fix(request)
                .await
                .map_err(|e| ChaffraError::Analysis(e.to_string()))
        })?;

        Ok(response.results.into_iter().map(FixResult::from).collect())
    }
}

impl Drop for ExternalModule {
    fn drop(&mut self) {
        // Stop the Docker container if one was started in container mode.
        if let Some(cid) = self.container_id.lock().unwrap().take() {
            let _ = std::process::Command::new("docker")
                .args(["stop", &cid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

impl std::fmt::Debug for ExternalModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalModule")
            .field("id", &self.config.id)
            .field("mode", &self.config.mode)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportMode;

    fn test_config() -> ExternalModuleConfig {
        ExternalModuleConfig {
            id: "test-module".to_owned(),
            mode: TransportMode::Grpc,
            command: None,
            endpoint: Some("http://127.0.0.1:50099".to_owned()),
            image: None,
            port: None,
        }
    }

    #[test]
    fn test_external_module_describe_fallback() {
        // Without a running server, describe should return fallback info.
        let module = ExternalModule::new(test_config());
        let info = module.describe();
        assert_eq!(info.id, "test-module");
        assert!(info.name.contains("external"));
    }

    #[test]
    fn test_external_module_debug() {
        let module = ExternalModule::new(test_config());
        let debug = format!("{module:?}");
        assert!(debug.contains("test-module"));
        assert!(debug.contains("Grpc"));
    }

    #[test]
    fn test_docker_available_check() {
        // Just verify it returns a bool without panicking.
        let _available = ExternalModule::docker_available();
    }

    #[test]
    fn test_external_module_analyze_connection_failure() {
        let module = ExternalModule::new(test_config());
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new());
        // Should fail because no server is running.
        assert!(result.is_err());
    }

    #[test]
    fn test_external_module_explain_connection_failure() {
        let module = ExternalModule::new(test_config());
        let result = module.explain("some-rule");
        assert!(result.is_err());
    }

    #[test]
    fn test_external_module_fix_connection_failure() {
        let module = ExternalModule::new(test_config());
        let result = module.fix(&[], false);
        assert!(result.is_err());
    }
}
