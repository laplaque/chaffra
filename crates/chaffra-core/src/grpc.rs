//! gRPC adapter: wraps an `AnalysisModule` trait impl as a tonic gRPC service
//! and provides a client handle for in-process dispatch.
//!
//! Built-in modules implement the Rust `AnalysisModule` trait. This module wraps
//! each trait impl as a tonic gRPC service and connects a tonic client directly
//! to the server's `tower::Service` implementation -- no TCP socket, no network.
//! All calls go through full proto serialization (prost encode/decode) with
//! low transport overhead (validated < 10ms/call in benchmarks).

pub mod convert;

use crate::config::ChaffraConfig;
use crate::diagnostic::{AnalysisResult, FileInfo, ModuleInfo, RuleExplanation};
use crate::error::{ChaffraError, Result};
use crate::module::AnalysisModule;
use crate::telemetry::ModuleTelemetry;

use chaffra_proto::proto::analysis_module_client::AnalysisModuleClient;
use chaffra_proto::proto::analysis_module_server::AnalysisModuleServer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A tonic gRPC service that delegates to an `AnalysisModule` trait impl.
pub struct GrpcModuleService {
    inner: Arc<dyn AnalysisModule>,
}

impl GrpcModuleService {
    pub fn new(module: Arc<dyn AnalysisModule>) -> Self {
        Self { inner: module }
    }
}

#[tonic::async_trait]
impl chaffra_proto::proto::analysis_module_server::AnalysisModule for GrpcModuleService {
    async fn describe(
        &self,
        _request: tonic::Request<chaffra_proto::proto::DescribeRequest>,
    ) -> std::result::Result<tonic::Response<chaffra_proto::proto::ModuleInfo>, tonic::Status> {
        let info = self.inner.describe();
        Ok(tonic::Response::new(convert::module_info_to_proto(&info)))
    }

    async fn analyze(
        &self,
        request: tonic::Request<chaffra_proto::proto::AnalysisRequest>,
    ) -> std::result::Result<tonic::Response<chaffra_proto::proto::AnalysisResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let files: Vec<FileInfo> = req
            .files
            .iter()
            .map(convert::file_info_from_proto)
            .collect();
        let config = req.config;

        let result = self
            .inner
            .analyze(&files, &config)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(convert::analysis_result_to_proto(
            &result,
        )))
    }

    async fn explain(
        &self,
        request: tonic::Request<chaffra_proto::proto::ExplainRequest>,
    ) -> std::result::Result<tonic::Response<chaffra_proto::proto::ExplainResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let explanation = self
            .inner
            .explain(&req.rule_id)
            .map_err(|e| tonic::Status::not_found(e.to_string()))?;

        Ok(tonic::Response::new(convert::rule_explanation_to_proto(
            &explanation,
        )))
    }

    async fn fix(
        &self,
        request: tonic::Request<chaffra_proto::proto::FixRequest>,
    ) -> std::result::Result<tonic::Response<chaffra_proto::proto::FixResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let findings: Vec<crate::diagnostic::Finding> = req
            .findings
            .iter()
            .map(convert::finding_from_proto)
            .collect::<crate::error::Result<Vec<_>>>()
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;

        let results = self
            .inner
            .fix(&findings, req.dry_run)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(chaffra_proto::proto::FixResponse {
            results: results.iter().map(convert::fix_result_to_proto).collect(),
        }))
    }
}

/// Type alias for the in-process gRPC server used as the client's transport.
///
/// `AnalysisModuleServer<GrpcModuleService>` implements
/// `Service<http::Request<Body>, Response = http::Response<Body>>`, which
/// satisfies `tonic::client::GrpcService<Body>` via tonic's blanket impl.
type InProcessTransport = AnalysisModuleServer<GrpcModuleService>;

/// Client handle that dispatches calls over in-process gRPC transport.
///
/// This wraps an `AnalysisModuleClient` connected to the tonic server's
/// `tower::Service` implementation directly -- no TCP, no network, just
/// in-memory proto serialization.
pub struct GrpcModuleHandle {
    client: Mutex<AnalysisModuleClient<InProcessTransport>>,
    /// Cached module info from `Describe`, to avoid re-calling for ID lookups.
    info: ModuleInfo,
}

impl std::fmt::Debug for GrpcModuleHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcModuleHandle")
            .field("module_id", &self.info.id)
            .finish()
    }
}

impl GrpcModuleHandle {
    /// Create an in-process gRPC handle from an `AnalysisModule` trait impl.
    ///
    /// This starts the module as a tonic gRPC server using tower's in-process
    /// service (no TCP socket, no network). The returned handle dispatches
    /// calls via proto serialization with low transport overhead.
    pub fn from_module(module: Box<dyn AnalysisModule>) -> Self {
        let info = module.describe();
        let service = GrpcModuleService::new(Arc::from(module));
        let server = AnalysisModuleServer::new(service);

        // Connect the client directly to the server's Service impl.
        // No TCP socket, no listener -- the client calls the server in-process.
        let client = AnalysisModuleClient::new(server);

        Self {
            client: Mutex::new(client),
            info,
        }
    }

    /// Return cached module info.
    pub fn info(&self) -> &ModuleInfo {
        &self.info
    }

    /// Call `Describe` via gRPC.
    pub async fn describe(&self) -> Result<ModuleInfo> {
        let mut client = self.client.lock().await;
        let response = client
            .describe(chaffra_proto::proto::DescribeRequest {})
            .await
            .map_err(|e| ChaffraError::Analysis(format!("gRPC describe failed: {e}")))?;

        Ok(convert::module_info_from_proto(&response.into_inner()))
    }

    /// Call `Analyze` via gRPC.
    pub async fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let mut client = self.client.lock().await;
        let request = chaffra_proto::proto::AnalysisRequest {
            files: files.iter().map(convert::file_info_to_proto).collect(),
            config: config.clone(),
            enabled_rules: vec![],
            language: String::new(),
        };

        let response = client
            .analyze(request)
            .await
            .map_err(|e| ChaffraError::Analysis(format!("gRPC analyze failed: {e}")))?;

        convert::analysis_result_from_proto(&response.into_inner())
    }

    /// Call `Explain` via gRPC.
    pub async fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        let mut client = self.client.lock().await;
        let request = chaffra_proto::proto::ExplainRequest {
            rule_id: rule_id.to_owned(),
        };

        let response = client
            .explain(request)
            .await
            .map_err(|e| ChaffraError::Analysis(format!("gRPC explain failed: {e}")))?;

        Ok(convert::rule_explanation_from_proto(&response.into_inner()))
    }

    /// Call `Fix` via gRPC.
    pub async fn fix(
        &self,
        findings: &[crate::diagnostic::Finding],
        dry_run: bool,
    ) -> Result<Vec<crate::diagnostic::FixResult>> {
        let mut client = self.client.lock().await;
        let request = chaffra_proto::proto::FixRequest {
            findings: findings.iter().map(convert::finding_to_proto).collect(),
            dry_run,
        };

        let response = client
            .fix(request)
            .await
            .map_err(|e| ChaffraError::Analysis(format!("gRPC fix failed: {e}")))?;

        Ok(response
            .into_inner()
            .results
            .iter()
            .map(convert::fix_result_from_proto)
            .collect())
    }
}

/// gRPC-backed module host that dispatches all calls via proto serialization.
///
/// This replaces the old trait-dispatch `ModuleHost`. Every module is wrapped
/// in a `GrpcModuleHandle` so that all dispatch goes through the full gRPC
/// serialization path (prost encode -> proto bytes -> prost decode), validating
/// the proto contract for every call.
pub struct GrpcModuleHost {
    modules: HashMap<String, GrpcModuleHandle>,
    runtime: RuntimeHandle,
}

/// Wrapper that either borrows the current tokio runtime or dispatches work
/// onto a dedicated OS thread to avoid nested-runtime panics.
enum RuntimeHandle {
    /// Reuse the caller's multi-thread tokio runtime via `block_in_place`.
    Current(tokio::runtime::Handle),
    /// No usable runtime on the current thread — dispatch onto a fresh OS
    /// thread with its own single-threaded runtime. This covers both the
    /// "no runtime" case and the "current-thread runtime" case (where
    /// nested `block_on` would panic).
    ThreadDispatch,
}

impl RuntimeHandle {
    fn detect() -> Self {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                RuntimeHandle::Current(handle)
            }
            _ => RuntimeHandle::ThreadDispatch,
        }
    }

    fn block_on<F: std::future::Future + Send>(&self, future: F) -> F::Output
    where
        F::Output: Send,
    {
        match self {
            RuntimeHandle::Current(handle) => {
                tokio::task::block_in_place(|| handle.block_on(future))
            }
            RuntimeHandle::ThreadDispatch => {
                // Run on a separate OS thread to avoid nested-runtime panics.
                std::thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("failed to create tokio runtime");
                        rt.block_on(future)
                    })
                    .join()
                    .expect("runtime thread panicked")
                })
            }
        }
    }
}

impl GrpcModuleHost {
    /// Create a new empty gRPC module host.
    ///
    /// If a tokio runtime is active in the current thread, its handle is reused.
    /// Otherwise a lightweight single-threaded runtime is created internally.
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            runtime: RuntimeHandle::detect(),
        }
    }

    /// Register a module. The module is wrapped in a `GrpcModuleHandle`
    /// that starts an in-process gRPC service.
    pub fn register(&mut self, module: Box<dyn AnalysisModule>) -> Result<()> {
        let handle = GrpcModuleHandle::from_module(module);
        let id = handle.info().id.clone();
        if self.modules.contains_key(&id) {
            return Err(ChaffraError::ModuleAlreadyRegistered(id));
        }
        self.modules.insert(id, handle);
        Ok(())
    }

    /// Get a module handle by ID.
    pub fn get(&self, id: &str) -> Option<&GrpcModuleHandle> {
        self.modules.get(id)
    }

    /// List all registered module IDs and their info.
    pub fn list(&self) -> Vec<ModuleInfo> {
        self.modules.values().map(|h| h.info().clone()).collect()
    }

    /// Run analysis on a specific module via gRPC dispatch.
    pub fn analyze(
        &self,
        module_id: &str,
        files: &[FileInfo],
        config: &ChaffraConfig,
    ) -> Result<AnalysisResult> {
        let handle = self
            .modules
            .get(module_id)
            .ok_or_else(|| ChaffraError::ModuleNotFound(module_id.to_owned()))?;

        let module_config = config.module_config(module_id);

        let mut telemetry = ModuleTelemetry::new(module_id);
        telemetry.start();

        let mut result = self
            .runtime
            .block_on(handle.analyze(files, &module_config))?;

        telemetry.stop();
        telemetry.increment("files_analyzed", result.metrics.files_analyzed);
        telemetry.increment("findings", result.findings.len() as u64);

        result.metrics.duration_ms = telemetry.duration_ms();
        for (k, v) in telemetry.counters() {
            result.metrics.counters.insert(k.clone(), *v);
        }

        Ok(result)
    }

    /// Explain a rule, routing to the correct module based on rule ID prefix.
    ///
    /// Rule IDs are formatted as "module-id:rule-name".
    pub fn explain(&self, qualified_rule_id: &str) -> Result<RuleExplanation> {
        if let Some((module_id, rule_id)) = qualified_rule_id.split_once(':') {
            let handle = self
                .modules
                .get(module_id)
                .ok_or_else(|| ChaffraError::ModuleNotFound(module_id.to_owned()))?;
            self.runtime.block_on(handle.explain(rule_id))
        } else {
            for handle in self.modules.values() {
                if let Ok(explanation) = self.runtime.block_on(handle.explain(qualified_rule_id)) {
                    return Ok(explanation);
                }
            }
            Err(ChaffraError::RuleNotFound(qualified_rule_id.to_owned()))
        }
    }
}

impl Default for GrpcModuleHost {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GrpcModuleHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcModuleHost")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::*;
    use crate::module::empty_metrics;

    struct TestModule;

    impl AnalysisModule for TestModule {
        fn describe(&self) -> ModuleInfo {
            ModuleInfo {
                id: "test".to_owned(),
                name: "Test Module".to_owned(),
                version: "0.1.0".to_owned(),
                languages: vec!["go".to_owned()],
                capabilities: vec!["analyze".to_owned()],
                rules: vec![Rule {
                    id: "test-rule".to_owned(),
                    name: "Test Rule".to_owned(),
                    description: "A test rule".to_owned(),
                    default_severity: Severity::Warning,
                    category: "test".to_owned(),
                }],
            }
        }

        fn analyze(
            &self,
            files: &[FileInfo],
            _config: &HashMap<String, String>,
        ) -> Result<AnalysisResult> {
            Ok(AnalysisResult {
                findings: vec![Finding {
                    rule_id: "test-rule".to_owned(),
                    message: "test finding".to_owned(),
                    severity: Severity::Warning,
                    location: Location {
                        file: "test.go".to_owned(),
                        start_line: 1,
                        end_line: 2,
                        start_column: 0,
                        end_column: 10,
                    },
                    confidence: 0.95,
                    actions: vec![Action {
                        description: "Fix it".to_owned(),
                        auto_fixable: true,
                        edits: vec![TextEdit {
                            file: "test.go".to_owned(),
                            start_line: 1,
                            end_line: 2,
                            new_text: "fixed".to_owned(),
                        }],
                    }],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("key".to_owned(), "value".to_owned());
                        m
                    },
                }],
                metrics: empty_metrics(files.len() as u64),
            })
        }

        fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
            if rule_id == "test-rule" {
                Ok(RuleExplanation {
                    rule_id: "test-rule".to_owned(),
                    name: "Test Rule".to_owned(),
                    description: "A test rule".to_owned(),
                    rationale: "For testing".to_owned(),
                    default_severity: Severity::Warning,
                    suppression_syntax: "// chaffra:ignore test-rule".to_owned(),
                    examples: vec!["example1".to_owned(), "example2".to_owned()],
                })
            } else {
                Err(ChaffraError::RuleNotFound(rule_id.to_owned()))
            }
        }

        fn fix(
            &self,
            findings: &[crate::diagnostic::Finding],
            dry_run: bool,
        ) -> Result<Vec<FixResult>> {
            Ok(findings
                .iter()
                .map(|f| FixResult {
                    rule_id: f.rule_id.clone(),
                    applied: !dry_run,
                    edits: f
                        .actions
                        .first()
                        .map(|a| a.edits.clone())
                        .unwrap_or_default(),
                    reason: if dry_run {
                        "dry run".to_owned()
                    } else {
                        "applied".to_owned()
                    },
                })
                .collect())
        }
    }

    #[tokio::test]
    async fn test_grpc_handle_describe() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let info = handle.describe().await.unwrap();
        assert_eq!(info.id, "test");
        assert_eq!(info.name, "Test Module");
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.languages, vec!["go"]);
        assert_eq!(info.rules.len(), 1);
        assert_eq!(info.rules[0].id, "test-rule");
    }

    #[tokio::test]
    async fn test_grpc_handle_analyze_roundtrip() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let config = HashMap::new();

        let result = handle.analyze(&files, &config).await.unwrap();
        assert_eq!(result.findings.len(), 1);

        let finding = &result.findings[0];
        assert_eq!(finding.rule_id, "test-rule");
        assert_eq!(finding.message, "test finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.location.file, "test.go");
        assert_eq!(finding.location.start_line, 1);
        assert_eq!(finding.location.end_line, 2);
        assert_eq!(finding.location.start_column, 0);
        assert_eq!(finding.location.end_column, 10);
        assert!((finding.confidence - 0.95).abs() < 0.01);
        assert_eq!(finding.actions.len(), 1);
        assert_eq!(finding.actions[0].description, "Fix it");
        assert!(finding.actions[0].auto_fixable);
        assert_eq!(finding.actions[0].edits.len(), 1);
        assert_eq!(finding.actions[0].edits[0].new_text, "fixed");
        assert_eq!(finding.metadata.get("key"), Some(&"value".to_owned()));
    }

    #[tokio::test]
    async fn test_grpc_handle_explain_roundtrip() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let explanation = handle.explain("test-rule").await.unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
        assert_eq!(explanation.name, "Test Rule");
        assert_eq!(explanation.description, "A test rule");
        assert_eq!(explanation.rationale, "For testing");
        assert_eq!(explanation.default_severity, Severity::Warning);
        assert_eq!(
            explanation.suppression_syntax,
            "// chaffra:ignore test-rule"
        );
        assert_eq!(explanation.examples, vec!["example1", "example2"]);
    }

    #[tokio::test]
    async fn test_grpc_handle_explain_not_found() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let result = handle.explain("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_grpc_handle_fix_dry_run() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let findings = vec![crate::diagnostic::Finding {
            rule_id: "test-rule".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 2,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![Action {
                description: "Fix".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 1,
                    end_line: 2,
                    new_text: "fixed".to_owned(),
                }],
            }],
            metadata: HashMap::new(),
        }];

        let results = handle.fix(&findings, true).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert_eq!(results[0].reason, "dry run");
    }

    #[tokio::test]
    async fn test_grpc_handle_fix_apply() {
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let findings = vec![crate::diagnostic::Finding {
            rule_id: "test-rule".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 2,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![Action {
                description: "Fix".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 1,
                    end_line: 2,
                    new_text: "fixed".to_owned(),
                }],
            }],
            metadata: HashMap::new(),
        }];

        let results = handle.fix(&findings, false).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert_eq!(results[0].reason, "applied");
        assert_eq!(results[0].edits[0].new_text, "fixed");
    }

    #[test]
    fn test_grpc_module_host_register_and_list() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let modules = host.list();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].id, "test");
    }

    #[test]
    fn test_grpc_module_host_duplicate_registration() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let err = host.register(Box::new(TestModule)).unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleAlreadyRegistered(_)));
    }

    #[test]
    fn test_grpc_module_host_analyze() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let config = ChaffraConfig::default();
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = host.analyze("test", &files, &config).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "test-rule");
    }

    #[test]
    fn test_grpc_module_host_analyze_unknown() {
        let host = GrpcModuleHost::new();
        let config = ChaffraConfig::default();
        let err = host.analyze("nope", &[], &config).unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleNotFound(_)));
    }

    #[test]
    fn test_grpc_module_host_explain_qualified() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let explanation = host.explain("test:test-rule").unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
    }

    #[test]
    fn test_grpc_module_host_explain_unqualified() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let explanation = host.explain("test-rule").unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
    }

    #[test]
    fn test_grpc_module_host_explain_not_found() {
        let host = GrpcModuleHost::new();
        let err = host.explain("nope:nope").unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleNotFound(_)));
    }

    /// Verify that a Finding survives the full proto serialization round-trip.
    #[test]
    fn test_finding_proto_roundtrip() {
        let original = crate::diagnostic::Finding {
            rule_id: "unused-function".to_owned(),
            message: "Function `helper` is never used".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "src/lib.go".to_owned(),
                start_line: 42,
                end_line: 55,
                start_column: 4,
                end_column: 20,
            },
            confidence: 0.95,
            actions: vec![Action {
                description: "Remove function `helper`".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "src/lib.go".to_owned(),
                    start_line: 42,
                    end_line: 55,
                    new_text: String::new(),
                }],
            }],
            metadata: {
                let mut m = HashMap::new();
                m.insert("symbol".to_owned(), "helper".to_owned());
                m.insert("kind".to_owned(), "function".to_owned());
                m
            },
        };

        let proto = convert::finding_to_proto(&original);
        let restored = convert::finding_from_proto(&proto).unwrap();

        assert_eq!(original.rule_id, restored.rule_id);
        assert_eq!(original.message, restored.message);
        assert_eq!(original.severity, restored.severity);
        assert_eq!(original.location.file, restored.location.file);
        assert_eq!(original.location.start_line, restored.location.start_line);
        assert_eq!(original.location.end_line, restored.location.end_line);
        assert_eq!(
            original.location.start_column,
            restored.location.start_column
        );
        assert_eq!(original.location.end_column, restored.location.end_column);
        assert!((original.confidence - restored.confidence).abs() < 0.001);
        assert_eq!(original.actions.len(), restored.actions.len());
        assert_eq!(
            original.actions[0].description,
            restored.actions[0].description
        );
        assert_eq!(
            original.actions[0].auto_fixable,
            restored.actions[0].auto_fixable
        );
        assert_eq!(
            original.actions[0].edits.len(),
            restored.actions[0].edits.len()
        );
        assert_eq!(original.metadata, restored.metadata);
    }

    /// Verify ModuleInfo survives round-trip.
    #[test]
    fn test_module_info_proto_roundtrip() {
        let original = ModuleInfo {
            id: "dead-code".to_owned(),
            name: "Dead Code Detection".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: vec![Rule {
                id: "unused-function".to_owned(),
                name: "Unused function".to_owned(),
                description: "Function is never called".to_owned(),
                default_severity: Severity::Warning,
                category: "dead-code".to_owned(),
            }],
        };

        let proto = convert::module_info_to_proto(&original);
        let restored = convert::module_info_from_proto(&proto);

        assert_eq!(original.id, restored.id);
        assert_eq!(original.name, restored.name);
        assert_eq!(original.version, restored.version);
        assert_eq!(original.languages, restored.languages);
        assert_eq!(original.capabilities, restored.capabilities);
        assert_eq!(original.rules.len(), restored.rules.len());
        assert_eq!(original.rules[0].id, restored.rules[0].id);
        assert_eq!(
            original.rules[0].default_severity,
            restored.rules[0].default_severity
        );
    }

    /// Verify RuleExplanation survives round-trip.
    #[test]
    fn test_rule_explanation_proto_roundtrip() {
        let original = RuleExplanation {
            rule_id: "unused-function".to_owned(),
            name: "Unused function".to_owned(),
            description: "Detects functions that are defined but never called".to_owned(),
            rationale: "Dead code increases maintenance burden".to_owned(),
            default_severity: Severity::Warning,
            suppression_syntax: "// chaffra:ignore unused-function".to_owned(),
            examples: vec!["func helper() {} // never called".to_owned()],
        };

        let proto = convert::rule_explanation_to_proto(&original);
        let restored = convert::rule_explanation_from_proto(&proto);

        assert_eq!(original.rule_id, restored.rule_id);
        assert_eq!(original.name, restored.name);
        assert_eq!(original.description, restored.description);
        assert_eq!(original.rationale, restored.rationale);
        assert_eq!(original.default_severity, restored.default_severity);
        assert_eq!(original.suppression_syntax, restored.suppression_syntax);
        assert_eq!(original.examples, restored.examples);
    }

    /// Performance comparison: trait dispatch vs gRPC in-process dispatch.
    #[tokio::test]
    async fn test_grpc_overhead_vs_trait_dispatch() {
        let module = TestModule;
        let files = vec![FileInfo {
            path: "bench.go".to_owned(),
            content: b"package main\nfunc main() {}\n".to_vec(),
        }];
        let config = HashMap::new();

        // Trait dispatch timing
        let trait_start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = module.analyze(&files, &config).unwrap();
        }
        let trait_elapsed = trait_start.elapsed();

        // gRPC in-process dispatch timing
        let handle = GrpcModuleHandle::from_module(Box::new(TestModule));
        let grpc_start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = handle.analyze(&files, &config).await.unwrap();
        }
        let grpc_elapsed = grpc_start.elapsed();

        let trait_per_call = trait_elapsed / 100;
        let grpc_per_call = grpc_elapsed / 100;

        // The gRPC overhead should be small. We just verify it doesn't
        // exceed 10ms per call (generous threshold for CI).
        assert!(
            grpc_per_call.as_millis() < 10,
            "gRPC per-call overhead too high: trait={trait_per_call:?}, grpc={grpc_per_call:?}"
        );

        eprintln!(
            "Performance comparison (100 iterations):\n  \
             Trait dispatch: {trait_per_call:?}/call\n  \
             gRPC in-process: {grpc_per_call:?}/call\n  \
             Overhead: {:?}/call",
            grpc_per_call.saturating_sub(trait_per_call)
        );
    }

    /// Regression: sync host must not panic when called from a current-thread
    /// tokio runtime (e.g. `#[tokio::test(flavor = "current_thread")]`).
    #[tokio::test(flavor = "current_thread")]
    async fn test_grpc_host_from_current_thread_runtime() {
        let mut host = GrpcModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let config = ChaffraConfig::default();
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = host.analyze("test", &files, &config).unwrap();
        assert_eq!(result.findings.len(), 1);

        let explanation = host.explain("test:test-rule").unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
    }

    /// Regression: finding_from_proto rejects a finding with missing location.
    #[test]
    fn test_finding_from_proto_missing_location() {
        let proto_finding = chaffra_proto::proto::Finding {
            rule_id: "test-rule".to_owned(),
            message: "bad finding".to_owned(),
            severity: "warning".to_owned(),
            location: None,
            confidence: 0.9,
            actions: vec![],
            metadata: Default::default(),
        };
        let err = convert::finding_from_proto(&proto_finding).unwrap_err();
        assert!(
            matches!(err, ChaffraError::ProtoConversion(_)),
            "expected ProtoConversion error, got: {err:?}"
        );
    }

    /// Regression: analysis_result_from_proto rejects a response with missing metrics.
    #[test]
    fn test_analysis_result_from_proto_missing_metrics() {
        let proto_response = chaffra_proto::proto::AnalysisResponse {
            findings: vec![],
            metrics: None,
        };
        let err = convert::analysis_result_from_proto(&proto_response).unwrap_err();
        assert!(
            matches!(err, ChaffraError::ProtoConversion(_)),
            "expected ProtoConversion error, got: {err:?}"
        );
    }

    /// Regression: analysis_result_from_proto rejects when a finding has missing location.
    #[test]
    fn test_analysis_result_from_proto_finding_missing_location() {
        let proto_response = chaffra_proto::proto::AnalysisResponse {
            findings: vec![chaffra_proto::proto::Finding {
                rule_id: "bad".to_owned(),
                message: "incomplete".to_owned(),
                severity: "warning".to_owned(),
                location: None,
                confidence: 0.5,
                actions: vec![],
                metadata: Default::default(),
            }],
            metrics: Some(chaffra_proto::proto::ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 0,
                counters: Default::default(),
            }),
        };
        let err = convert::analysis_result_from_proto(&proto_response).unwrap_err();
        assert!(matches!(err, ChaffraError::ProtoConversion(_)));
    }
}
