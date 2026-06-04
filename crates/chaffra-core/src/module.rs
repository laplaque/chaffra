//! AnalysisModule trait and ModuleHost for registration and dispatch.

use crate::config::ChaffraConfig;
use crate::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, ModuleInfo, ModuleMetrics, RuleExplanation,
};
use crate::error::{ChaffraError, Result};
use crate::telemetry::ModuleTelemetry;
use std::collections::HashMap;

/// The core trait that every analysis module implements.
///
/// Built-in modules implement this trait directly and run in-process.
/// External modules would have a wrapper that translates to/from gRPC.
pub trait AnalysisModule: Send + Sync {
    /// Return metadata about this module.
    fn describe(&self) -> ModuleInfo;

    /// Run analysis on the provided files.
    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult>;

    /// Explain a rule by ID.
    fn explain(&self, rule_id: &str) -> Result<RuleExplanation>;

    /// Apply fixes for the given findings.
    fn fix(&self, findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>>;
}

/// Registry and dispatcher for analysis modules.
pub struct ModuleHost {
    modules: HashMap<String, Box<dyn AnalysisModule>>,
}

impl ModuleHost {
    /// Create a new empty module host.
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Register a module. Returns an error if a module with the same ID
    /// is already registered.
    pub fn register(&mut self, module: Box<dyn AnalysisModule>) -> Result<()> {
        let info = module.describe();
        let id = info.id.clone();
        if self.modules.contains_key(&id) {
            return Err(ChaffraError::ModuleAlreadyRegistered(id));
        }
        self.modules.insert(id, module);
        Ok(())
    }

    /// Get a module by ID.
    pub fn get(&self, id: &str) -> Option<&dyn AnalysisModule> {
        self.modules.get(id).map(|m| m.as_ref())
    }

    /// List all registered module IDs and their info.
    pub fn list(&self) -> Vec<ModuleInfo> {
        self.modules.values().map(|m| m.describe()).collect()
    }

    /// Run analysis on a specific module.
    pub fn analyze(
        &self,
        module_id: &str,
        files: &[FileInfo],
        config: &ChaffraConfig,
    ) -> Result<AnalysisResult> {
        let module = self
            .modules
            .get(module_id)
            .ok_or_else(|| ChaffraError::ModuleNotFound(module_id.to_owned()))?;

        let module_config = config.module_config(module_id);

        let mut telemetry = ModuleTelemetry::new(module_id);
        telemetry.start();

        let mut result = module.analyze(files, &module_config)?;

        telemetry.stop();
        telemetry.increment("files_analyzed", result.metrics.files_analyzed);
        telemetry.increment("findings", result.findings.len() as u64);

        // Merge telemetry into result metrics.
        result.metrics.duration_ms = telemetry.duration_ms();
        for (k, v) in telemetry.counters() {
            result.metrics.counters.insert(k.clone(), *v);
        }

        Ok(result)
    }

    /// Explain a rule, routing to the correct module based on rule ID prefix.
    ///
    /// Rule IDs are formatted as "module-id:rule-name" (e.g. "dead-code:unused-function").
    pub fn explain(&self, qualified_rule_id: &str) -> Result<RuleExplanation> {
        if let Some((module_id, rule_id)) = qualified_rule_id.split_once(':') {
            let module = self
                .modules
                .get(module_id)
                .ok_or_else(|| ChaffraError::ModuleNotFound(module_id.to_owned()))?;
            module.explain(rule_id)
        } else {
            // Try all modules.
            for module in self.modules.values() {
                if let Ok(explanation) = module.explain(qualified_rule_id) {
                    return Ok(explanation);
                }
            }
            Err(ChaffraError::RuleNotFound(qualified_rule_id.to_owned()))
        }
    }

    /// Create a module host with all built-in modules registered.
    pub fn with_builtins() -> Self {
        // Modules are registered by the CLI or integration code,
        // not here -- this is a convenience entry point that starts empty.
        // Actual registration happens in the CLI wiring.
        Self::new()
    }
}

impl Default for ModuleHost {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ModuleHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleHost")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Helper to create default metrics.
pub fn empty_metrics(files_analyzed: u64) -> ModuleMetrics {
    ModuleMetrics {
        files_analyzed,
        duration_ms: 0,
        counters: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::*;

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
                findings: vec![],
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
                    examples: vec![],
                })
            } else {
                Err(ChaffraError::RuleNotFound(rule_id.to_owned()))
            }
        }

        fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        assert!(host.get("test").is_some());
        assert!(host.get("nonexistent").is_none());
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let err = host.register(Box::new(TestModule)).unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleAlreadyRegistered(_)));
    }

    #[test]
    fn test_list_modules() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let list = host.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "test");
    }

    #[test]
    fn test_analyze_dispatch() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let config = ChaffraConfig::default();
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = host.analyze("test", &files, &config).unwrap();
        assert_eq!(result.metrics.files_analyzed, 1);
    }

    #[test]
    fn test_analyze_unknown_module() {
        let host = ModuleHost::new();
        let config = ChaffraConfig::default();
        let err = host.analyze("nope", &[], &config).unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleNotFound(_)));
    }

    #[test]
    fn test_explain_qualified() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let explanation = host.explain("test:test-rule").unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
    }

    #[test]
    fn test_explain_unqualified() {
        let mut host = ModuleHost::new();
        host.register(Box::new(TestModule)).unwrap();
        let explanation = host.explain("test-rule").unwrap();
        assert_eq!(explanation.rule_id, "test-rule");
    }

    #[test]
    fn test_explain_not_found() {
        let host = ModuleHost::new();
        let err = host.explain("nope:nope").unwrap_err();
        assert!(matches!(err, ChaffraError::ModuleNotFound(_)));
    }
}
