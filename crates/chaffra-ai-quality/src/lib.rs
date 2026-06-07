//! AI-generated code quality analysis.
//!
//! Detects common defects introduced by AI code generators: hallucinated API calls,
//! phantom security functions, missing decorators, unfinished stubs, disabled controls,
//! impossible dependency versions, and inconsistent error handling patterns.

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::detect_language;
use chaffra_parse::parser;
use chaffra_parse::suppression::is_line_suppressed;
use chaffra_parse::symbols::{self, ImportInfo, Reference, Symbol, SymbolKind};
use std::collections::{HashMap, HashSet};

pub struct AiQualityModule;

impl AiQualityModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiQualityModule {
    fn default() -> Self {
        Self::new()
    }
}

const RULES: &[(&str, &str, &str, Severity, &str)] = &[
    (
        "phantom-api-call",
        "Phantom API call",
        "Call to a function that does not exist in the codebase or known standard library",
        Severity::Error,
        "ai-quality",
    ),
    (
        "phantom-security-call",
        "Phantom security call",
        "Call to a nonexistent security or authentication function",
        Severity::Error,
        "ai-quality",
    ),
    (
        "missing-decorator",
        "Missing decorator",
        "Security decorator mentioned in comment but not applied to the function",
        Severity::Warning,
        "ai-quality",
    ),
    (
        "unfinished-stub",
        "Unfinished stub",
        "Function body contains only pass, todo!(), TODO comments, or placeholder content",
        Severity::Warning,
        "ai-quality",
    ),
    (
        "disabled-control",
        "Disabled security control",
        "Security check is commented out or gated behind if false / if False",
        Severity::Error,
        "ai-quality",
    ),
    (
        "impossible-dependency-version",
        "Impossible dependency version",
        "Dependency specifies a version constraint that cannot be satisfied",
        Severity::Warning,
        "ai-quality",
    ),
    (
        "inconsistent-error-handling",
        "Inconsistent error handling",
        "File mixes different error handling patterns indicating mechanical generation",
        Severity::Info,
        "ai-quality",
    ),
];

/// Known Go standard library packages (subset covering common usage).
const GO_STDLIB_PACKAGES: &[&str] = &[
    "fmt", "os", "io", "net", "http", "json", "log", "sync", "context", "time", "strings",
    "strconv", "bytes", "errors", "path", "filepath", "bufio", "crypto", "encoding", "reflect",
    "testing", "regexp", "sort", "math", "database", "sql", "html", "template", "flag",
];

/// Known Python builtins and common standard library names.
const PYTHON_BUILTINS: &[&str] = &[
    "print",
    "len",
    "range",
    "int",
    "str",
    "float",
    "list",
    "dict",
    "set",
    "tuple",
    "bool",
    "type",
    "isinstance",
    "issubclass",
    "hasattr",
    "getattr",
    "setattr",
    "delattr",
    "open",
    "input",
    "super",
    "map",
    "filter",
    "zip",
    "enumerate",
    "sorted",
    "reversed",
    "min",
    "max",
    "sum",
    "abs",
    "round",
    "any",
    "all",
    "next",
    "iter",
    "hash",
    "id",
    "repr",
    "format",
    "chr",
    "ord",
    "hex",
    "oct",
    "bin",
    "pow",
    "divmod",
    "complex",
    "bytes",
    "bytearray",
    "memoryview",
    "object",
    "staticmethod",
    "classmethod",
    "property",
    "Exception",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AttributeError",
    "RuntimeError",
    "OSError",
    "IOError",
    "FileNotFoundError",
    "NotImplementedError",
    "StopIteration",
    "True",
    "False",
    "None",
];

/// Security-related function name patterns that AI models commonly hallucinate.
const PHANTOM_SECURITY_PATTERNS: &[&str] = &[
    "validate_token",
    "verify_auth",
    "check_permissions",
    "sanitize_input",
    "encrypt_data",
    "decrypt_data",
    "verify_signature",
    "check_csrf",
    "validate_session",
    "authenticate_user",
    "authorize_request",
    "verify_certificate",
    "validate_credentials",
];

/// Python decorator names commonly mentioned in comments but not applied.
const SECURITY_DECORATORS_PYTHON: &[&str] = &[
    "login_required",
    "permission_required",
    "requires_auth",
    "csrf_protect",
    "rate_limit",
    "require_http_methods",
    "requires_permission",
    "authenticated",
];

/// Go security-related comment patterns indicating a decorator/middleware should exist.
const SECURITY_COMMENT_GO: &[&str] = &[
    "// requires authentication",
    "// requires authorization",
    "// must be authenticated",
    "// auth required",
    "// protected endpoint",
    "// requires permission",
];

impl AnalysisModule for AiQualityModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "ai-quality".to_owned(),
            name: "AI Quality Analysis".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, sev, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: *sev,
                    category: (*cat).to_owned(),
                })
                .collect(),
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        _config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let mut findings = Vec::new();

        // Phase 1: Collect all defined symbols across all files.
        let mut all_defined: HashSet<String> = HashSet::new();
        let mut all_imported: HashSet<String> = HashSet::new();
        let mut per_file_data: Vec<FileData> = Vec::new();

        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l @ Language::Go) | Some(l @ Language::Python) => l,
                _ => continue,
            };

            let tree = parser::parse(&file.content, lang)?;
            let syms = symbols::extract_symbols(&tree, &file.content, lang, &file.path);
            let imports = symbols::extract_imports(&tree, &file.content, lang);
            let refs = symbols::extract_references(&tree, &file.content, lang, &file.path);
            let source = String::from_utf8_lossy(&file.content).to_string();

            for sym in &syms {
                all_defined.insert(sym.name.clone());
            }
            for imp in &imports {
                let pkg = import_local_name(imp, lang);
                all_imported.insert(pkg);
                for name in &imp.names {
                    all_imported.insert(name.clone());
                }
            }

            per_file_data.push(FileData {
                path: file.path.clone(),
                language: lang,
                symbols: syms,
                references: refs,
                source,
            });
        }

        // Add builtins to the known set.
        let known = build_known_set(&all_defined, &all_imported);

        // Phase 2: Analyze each file.
        for fd in &per_file_data {
            detect_phantom_api_calls(fd, &known, &mut findings);
            detect_phantom_security_calls(fd, &known, &mut findings);
            detect_missing_decorators(fd, &mut findings);
            detect_unfinished_stubs(fd, &mut findings);
            detect_disabled_controls(fd, &mut findings);
            detect_inconsistent_error_handling(fd, &mut findings);
        }

        // Phase 3: Check dependency files.
        for file in files {
            detect_impossible_dependency_versions(file, &mut findings);
        }

        // Filter out findings suppressed by `chaffra:ignore <rule-id>` comments.
        let findings = findings
            .into_iter()
            .filter(|f| {
                let file = per_file_data.iter().find(|fd| fd.path == f.location.file);
                if let Some(fd) = file {
                    !is_line_suppressed(&fd.source, f.location.start_line, &f.rule_id, fd.language)
                } else {
                    true
                }
            })
            .collect();

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: HashMap::new(),
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "phantom-api-call" => Ok(RuleExplanation {
                rule_id: "phantom-api-call".to_owned(),
                name: "Phantom API call".to_owned(),
                description: "Detects calls to functions that do not exist in the codebase or recognized standard library.".to_owned(),
                rationale: "AI code generators sometimes hallucinate function names that look plausible but do not exist, leading to runtime errors.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore phantom-api-call".to_owned(),
                examples: vec![
                    "result = validate_and_sanitize(input)  # function does not exist".to_owned(),
                    "resp := http.SecureGet(url)  // no such method in net/http".to_owned(),
                ],
            }),
            "phantom-security-call" => Ok(RuleExplanation {
                rule_id: "phantom-security-call".to_owned(),
                name: "Phantom security call".to_owned(),
                description: "Detects calls to nonexistent security or authentication functions.".to_owned(),
                rationale: "AI models often generate calls to security functions that sound correct but are not implemented, creating a false sense of security.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore phantom-security-call".to_owned(),
                examples: vec![
                    "if verify_auth(token): ...  # verify_auth is never defined".to_owned(),
                ],
            }),
            "missing-decorator" => Ok(RuleExplanation {
                rule_id: "missing-decorator".to_owned(),
                name: "Missing decorator".to_owned(),
                description: "A security decorator is mentioned in a comment but not actually applied to the function.".to_owned(),
                rationale: "AI generators sometimes describe security measures in comments without implementing them.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore missing-decorator".to_owned(),
                examples: vec![
                    "# requires @login_required\ndef admin_view(): ...  # decorator missing".to_owned(),
                ],
            }),
            "unfinished-stub" => Ok(RuleExplanation {
                rule_id: "unfinished-stub".to_owned(),
                name: "Unfinished stub".to_owned(),
                description: "Function body contains only placeholder content like pass, todo!(), or TODO comments.".to_owned(),
                rationale: "Stubs left by AI generation can reach production if not caught.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore unfinished-stub".to_owned(),
                examples: vec![
                    "def process_payment():\n    pass  # stub".to_owned(),
                    "func HandleRequest() { // TODO: implement }".to_owned(),
                ],
            }),
            "disabled-control" => Ok(RuleExplanation {
                rule_id: "disabled-control".to_owned(),
                name: "Disabled security control".to_owned(),
                description: "Security check that is commented out or gated behind an always-false condition.".to_owned(),
                rationale: "AI models sometimes generate security code in a disabled state, creating vulnerabilities.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore disabled-control".to_owned(),
                examples: vec![
                    "if false { validateCSRF(r) }".to_owned(),
                    "# if check_auth(user): ...  // commented out".to_owned(),
                ],
            }),
            "impossible-dependency-version" => Ok(RuleExplanation {
                rule_id: "impossible-dependency-version".to_owned(),
                name: "Impossible dependency version".to_owned(),
                description: "Dependency version constraint uses a format that cannot be satisfied.".to_owned(),
                rationale: "AI generators sometimes produce version constraints that look valid but are syntactically broken or reference nonexistent versions.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore impossible-dependency-version".to_owned(),
                examples: vec![
                    "requests>=99.0.0  # version does not exist".to_owned(),
                ],
            }),
            "inconsistent-error-handling" => Ok(RuleExplanation {
                rule_id: "inconsistent-error-handling".to_owned(),
                name: "Inconsistent error handling".to_owned(),
                description: "File mixes different error handling patterns, suggesting mechanical generation.".to_owned(),
                rationale: "AI-generated code often mixes try/except with manual checks, or err != nil with panic, indicating concatenated snippets.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore inconsistent-error-handling".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>> {
        let mut results = Vec::new();
        for finding in findings {
            if finding.actions.is_empty() {
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: false,
                    edits: vec![],
                    reason: "no auto-fix available".to_owned(),
                });
            } else {
                let action = &finding.actions[0];
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: !dry_run,
                    edits: action.edits.clone(),
                    reason: if dry_run {
                        "dry run".to_owned()
                    } else {
                        "applied".to_owned()
                    },
                });
            }
        }
        Ok(results)
    }
}

struct FileData {
    path: String,
    language: Language,
    symbols: Vec<Symbol>,
    references: Vec<Reference>,
    source: String,
}

fn import_local_name(imp: &ImportInfo, lang: Language) -> String {
    match lang {
        Language::Go => imp
            .alias
            .as_deref()
            .unwrap_or_else(|| imp.path.rsplit('/').next().unwrap_or(&imp.path))
            .to_owned(),
        Language::Python => imp
            .alias
            .as_deref()
            .unwrap_or_else(|| imp.path.rsplit('.').next().unwrap_or(&imp.path))
            .to_owned(),
        _ => imp
            .alias
            .as_deref()
            .unwrap_or_else(|| imp.path.rsplit('/').next().unwrap_or(&imp.path))
            .to_owned(),
    }
}

fn build_known_set(defined: &HashSet<String>, imported: &HashSet<String>) -> HashSet<String> {
    let mut known: HashSet<String> = defined.clone();
    known.extend(imported.iter().cloned());

    // Add Go stdlib package names.
    for pkg in GO_STDLIB_PACKAGES {
        known.insert((*pkg).to_owned());
    }

    // Add Python builtins.
    for name in PYTHON_BUILTINS {
        known.insert((*name).to_owned());
    }

    // Common method names that are always valid.
    let common_methods = [
        "append",
        "extend",
        "insert",
        "remove",
        "pop",
        "clear",
        "copy",
        "get",
        "keys",
        "values",
        "items",
        "update",
        "join",
        "split",
        "strip",
        "lower",
        "upper",
        "replace",
        "find",
        "startswith",
        "endswith",
        "encode",
        "decode",
        "read",
        "write",
        "close",
        "flush",
        "Error",
        "String",
        "Len",
        "Close",
        "Read",
        "Write",
        "self",
        "cls",
    ];
    for m in &common_methods {
        known.insert((*m).to_owned());
    }

    known
}

/// Detect calls to functions that are not defined anywhere in the codebase.
fn detect_phantom_api_calls(fd: &FileData, known: &HashSet<String>, findings: &mut Vec<Finding>) {
    let defined_in_file: HashSet<&str> = fd.symbols.iter().map(|s| s.name.as_str()).collect();

    for r in &fd.references {
        // Skip if it's a known symbol.
        if known.contains(&r.name) || defined_in_file.contains(r.name.as_str()) {
            continue;
        }

        // Skip common patterns: single-letter vars, self/cls, capitalized field access.
        if r.name.len() <= 1 {
            continue;
        }

        // Skip if it looks like a security call (handled by phantom-security-call).
        if is_security_related(&r.name) {
            continue;
        }

        // Check if reference matches any known selector pattern (pkg.Method).
        // These are caught as field identifiers and are usually valid.
        if is_likely_method_call(&r.name, &fd.source, fd.language) {
            continue;
        }

        // Only flag if the name looks like a function call in the source.
        if is_function_call(&r.name, &fd.source, fd.language) {
            findings.push(Finding {
                rule_id: "phantom-api-call".to_owned(),
                message: format!(
                    "call to `{}` which is not defined in the codebase or standard library",
                    r.name
                ),
                severity: Severity::Error,
                location: Location {
                    file: fd.path.clone(),
                    start_line: r.line,
                    end_line: r.line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.7,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

/// Detect calls to nonexistent security functions.
fn detect_phantom_security_calls(
    fd: &FileData,
    known: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    for r in &fd.references {
        if known.contains(&r.name) {
            continue;
        }

        if is_security_related(&r.name) && is_function_call(&r.name, &fd.source, fd.language) {
            findings.push(Finding {
                rule_id: "phantom-security-call".to_owned(),
                message: format!("call to undefined security function `{}`", r.name),
                severity: Severity::Error,
                location: Location {
                    file: fd.path.clone(),
                    start_line: r.line,
                    end_line: r.line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.9,
                actions: vec![],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("category".to_owned(), "security".to_owned());
                    m
                },
            });
        }
    }
}

/// Detect decorators mentioned in comments but not applied.
fn detect_missing_decorators(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    match fd.language {
        Language::Python => {
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                // Look for comments mentioning a decorator.
                if !trimmed.starts_with('#') {
                    continue;
                }
                for decorator in SECURITY_DECORATORS_PYTHON {
                    if trimmed.contains(decorator) {
                        // Check if the next non-empty, non-comment line is a def with
                        // that decorator applied.
                        let has_decorator =
                            check_decorator_applied(&lines, i, decorator, fd.language);
                        if !has_decorator {
                            findings.push(Finding {
                                rule_id: "missing-decorator".to_owned(),
                                message: format!(
                                    "comment mentions `@{decorator}` but decorator is not applied"
                                ),
                                severity: Severity::Warning,
                                location: Location {
                                    file: fd.path.clone(),
                                    start_line: (i + 1) as u32,
                                    end_line: (i + 1) as u32,
                                    start_column: 0,
                                    end_column: 0,
                                },
                                confidence: 0.8,
                                actions: vec![],
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        Language::Go => {
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim().to_lowercase();
                for pattern in SECURITY_COMMENT_GO {
                    if trimmed.contains(&pattern.to_lowercase()) {
                        // In Go, look for middleware wrapping in the function below.
                        let has_middleware = check_go_middleware_applied(&lines, i);
                        if !has_middleware {
                            findings.push(Finding {
                                rule_id: "missing-decorator".to_owned(),
                                message: format!(
                                    "comment states \"{pattern}\" but no auth middleware is applied"
                                ),
                                severity: Severity::Warning,
                                location: Location {
                                    file: fd.path.clone(),
                                    start_line: (i + 1) as u32,
                                    end_line: (i + 1) as u32,
                                    start_column: 0,
                                    end_column: 0,
                                },
                                confidence: 0.7,
                                actions: vec![],
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Detect functions with placeholder bodies.
fn detect_unfinished_stubs(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    for sym in &fd.symbols {
        if sym.kind != SymbolKind::Function {
            continue;
        }

        let start = sym.start_line as usize;
        let end = sym.end_line as usize;
        if start == 0 || end == 0 || start > lines.len() || end > lines.len() {
            continue;
        }

        let body_lines: Vec<&str> = lines[start..end.min(lines.len())]
            .iter()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        if is_stub_body(&body_lines, fd.language) {
            findings.push(Finding {
                rule_id: "unfinished-stub".to_owned(),
                message: format!("function `{}` has a placeholder body", sym.name),
                severity: Severity::Warning,
                location: Location {
                    file: fd.path.clone(),
                    start_line: sym.start_line,
                    end_line: sym.end_line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.9,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

/// Detect disabled security controls.
fn detect_disabled_controls(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = (i + 1) as u32;

        // Pattern 1: Commented-out security checks.
        let is_comment = match fd.language {
            Language::Python => trimmed.starts_with('#'),
            Language::Go => trimmed.starts_with("//"),
            _ => false,
        };

        if is_comment {
            let comment_body = match fd.language {
                Language::Python => trimmed.trim_start_matches('#').trim(),
                Language::Go => trimmed.trim_start_matches("//").trim(),
                _ => "",
            };

            if looks_like_disabled_security_check(comment_body) {
                findings.push(Finding {
                    rule_id: "disabled-control".to_owned(),
                    message: "security check appears to be commented out".to_owned(),
                    severity: Severity::Error,
                    location: Location {
                        file: fd.path.clone(),
                        start_line: line_num,
                        end_line: line_num,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.8,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }

        // Pattern 2: if false / if False gating security code.
        match fd.language {
            Language::Go
                if (trimmed.starts_with("if false {") || trimmed.starts_with("if false{"))
                    && (line_contains_security_keyword(trimmed)
                        || next_lines_contain_security(&lines, i)) =>
            {
                findings.push(Finding {
                    rule_id: "disabled-control".to_owned(),
                    message: "`if false` gates a security check".to_owned(),
                    severity: Severity::Error,
                    location: Location {
                        file: fd.path.clone(),
                        start_line: line_num,
                        end_line: line_num,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.9,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
            Language::Python
                if trimmed.starts_with("if False:")
                    && (line_contains_security_keyword(trimmed)
                        || next_lines_contain_security(&lines, i)) =>
            {
                findings.push(Finding {
                    rule_id: "disabled-control".to_owned(),
                    message: "`if False` gates a security check".to_owned(),
                    severity: Severity::Error,
                    location: Location {
                        file: fd.path.clone(),
                        start_line: line_num,
                        end_line: line_num,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.9,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
            _ => {}
        }
    }
}

/// Detect impossible dependency versions in requirements.txt / go.mod.
fn detect_impossible_dependency_versions(file: &FileInfo, findings: &mut Vec<Finding>) {
    let filename = file.path.rsplit('/').next().unwrap_or(&file.path);

    if filename == "requirements.txt" {
        let source = String::from_utf8_lossy(&file.content);
        for (i, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(issue) = check_python_requirement(trimmed) {
                findings.push(Finding {
                    rule_id: "impossible-dependency-version".to_owned(),
                    message: issue,
                    severity: Severity::Warning,
                    location: Location {
                        file: file.path.clone(),
                        start_line: (i + 1) as u32,
                        end_line: (i + 1) as u32,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.8,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }
    }

    if filename == "go.mod" {
        let source = String::from_utf8_lossy(&file.content);
        for (i, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if let Some(issue) = check_go_module_version(trimmed) {
                findings.push(Finding {
                    rule_id: "impossible-dependency-version".to_owned(),
                    message: issue,
                    severity: Severity::Warning,
                    location: Location {
                        file: file.path.clone(),
                        start_line: (i + 1) as u32,
                        end_line: (i + 1) as u32,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.8,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }
    }
}

/// Detect inconsistent error handling patterns within a file.
fn detect_inconsistent_error_handling(fd: &FileData, findings: &mut Vec<Finding>) {
    match fd.language {
        Language::Go => {
            let has_err_check = fd.source.contains("if err != nil");
            let has_panic = fd.source.contains("panic(");
            let has_log_fatal = fd.source.contains("log.Fatal");

            // Mixing err != nil with panic/log.Fatal suggests inconsistent patterns.
            let patterns_used = [has_err_check, has_panic, has_log_fatal]
                .iter()
                .filter(|&&v| v)
                .count();

            if patterns_used >= 2 && has_err_check && (has_panic || has_log_fatal) {
                findings.push(Finding {
                    rule_id: "inconsistent-error-handling".to_owned(),
                    message: "file mixes `if err != nil` returns with panic/log.Fatal".to_owned(),
                    severity: Severity::Info,
                    location: Location {
                        file: fd.path.clone(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.6,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }
        Language::Python => {
            let has_try_except = fd.source.contains("try:");
            let has_bare_except = fd
                .source
                .lines()
                .any(|l| l.trim() == "except:" || l.trim().starts_with("except: "));
            let has_typed_except = fd.source.lines().any(|l| {
                let t = l.trim();
                t.starts_with("except ") && t.ends_with(':') && t != "except:"
            });

            // Mixing bare except with typed except suggests inconsistent patterns.
            if has_try_except && has_bare_except && has_typed_except {
                findings.push(Finding {
                    rule_id: "inconsistent-error-handling".to_owned(),
                    message: "file mixes bare `except:` with typed `except SomeError:`".to_owned(),
                    severity: Severity::Info,
                    location: Location {
                        file: fd.path.clone(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.6,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }
        _ => {}
    }
}

// --- Helpers ---

fn is_security_related(name: &str) -> bool {
    let lower = name.to_lowercase();
    PHANTOM_SECURITY_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
        || lower.contains("auth")
        || lower.contains("csrf")
        || lower.contains("sanitiz")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
        || lower.contains("verify_sig")
}

fn is_function_call(name: &str, source: &str, lang: Language) -> bool {
    // Check if `name(` appears in the source outside of comments and strings.
    let pattern = format!("{name}(");
    for line in source.lines() {
        if !line.contains(&pattern) {
            continue;
        }
        let trimmed = line.trim();
        // Skip comment lines.
        let is_comment = match lang {
            Language::Python => trimmed.starts_with('#'),
            Language::Go => trimmed.starts_with("//"),
            _ => false,
        };
        if is_comment {
            continue;
        }
        // Skip if the match occurs only within a string literal (simple heuristic:
        // count quotes before the match position; odd count means inside a string).
        if let Some(pos) = line.find(&pattern) {
            let prefix = &line[..pos];
            let double_quotes = prefix.chars().filter(|&c| c == '"').count();
            let single_quotes = prefix.chars().filter(|&c| c == '\'').count();
            if double_quotes % 2 == 0 && single_quotes % 2 == 0 {
                return true;
            }
        }
    }
    false
}

fn is_likely_method_call(name: &str, source: &str, lang: Language) -> bool {
    match lang {
        // In Go, exported method calls appear as `receiver.MethodName(` in source.
        // Check if the name appears with a dot-receiver pattern.
        Language::Go => {
            if !name.starts_with(char::is_uppercase) {
                return false;
            }
            let dot_pattern = format!(".{name}(");
            source.contains(&dot_pattern)
        }
        Language::Python => name == "self" || name == "cls",
        _ => false,
    }
}

fn check_decorator_applied(
    lines: &[&str],
    comment_line: usize,
    decorator: &str,
    _lang: Language,
) -> bool {
    // Look at lines between the comment and the next function def.
    let search_range = (comment_line + 1)..((comment_line + 10).min(lines.len()));
    for i in search_range {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with(&format!("@{decorator}")) {
            return true;
        }
        if trimmed.starts_with("def ") || trimmed.starts_with("class ") {
            return false;
        }
    }
    false
}

fn check_go_middleware_applied(lines: &[&str], comment_line: usize) -> bool {
    let search_range = (comment_line + 1)..((comment_line + 15).min(lines.len()));
    for i in search_range {
        let trimmed = lines[i].trim().to_lowercase();
        if trimmed.contains("middleware") || trimmed.contains("auth") || trimmed.contains("wrap") {
            return true;
        }
        // Stop searching at the next function declaration.
        if trimmed.starts_with("func ") && i > comment_line + 1 {
            return false;
        }
    }
    false
}

fn is_stub_body(body_lines: &[&str], lang: Language) -> bool {
    if body_lines.is_empty() {
        return true;
    }

    // Filter out the function signature line.
    let content_lines: Vec<&&str> = body_lines
        .iter()
        .filter(|l| {
            !l.starts_with("def ")
                && !l.starts_with("func ")
                && !l.starts_with("func(")
                && **l != "{"
                && **l != "}"
                && **l != ")"
                && **l != "})"
        })
        .collect();

    if content_lines.is_empty() {
        return true;
    }

    match lang {
        Language::Python => content_lines.iter().all(|l| {
            let t = l.trim();
            t == "pass"
                || t.starts_with("# TODO")
                || t.starts_with("# todo")
                || t == "..."
                || t == "raise NotImplementedError"
                || t == "raise NotImplementedError()"
        }),
        Language::Go => content_lines.iter().all(|l| {
            let t = l.trim();
            t == "// TODO"
                || t.starts_with("// TODO:")
                || t.starts_with("// todo:")
                || t == "todo!()"
                || t == "panic(\"not implemented\")"
                || t == "panic(\"TODO\")"
                || t == "return"
                || t == "return nil"
        }),
        _ => false,
    }
}

fn looks_like_disabled_security_check(comment_body: &str) -> bool {
    let lower = comment_body.to_lowercase();
    // Must look like actual code, not a descriptive comment.
    let has_parens = comment_body.contains('(');
    let has_security_keyword = lower.contains("auth")
        || lower.contains("csrf")
        || lower.contains("token")
        || lower.contains("permission")
        || lower.contains("sanitiz")
        || lower.contains("validate")
        || lower.contains("verify");

    has_parens && has_security_keyword
}

fn line_contains_security_keyword(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("auth")
        || lower.contains("csrf")
        || lower.contains("token")
        || lower.contains("permission")
        || lower.contains("sanitize")
        || lower.contains("validate")
}

fn next_lines_contain_security(lines: &[&str], current: usize) -> bool {
    let end = (current + 5).min(lines.len());
    for line in &lines[current + 1..end] {
        if line_contains_security_keyword(line) {
            return true;
        }
    }
    false
}

fn check_python_requirement(line: &str) -> Option<String> {
    // Look for version specifiers with absurdly high major versions.
    let operators = [">=", "<=", "==", "~=", "!=", ">", "<"];

    for op in &operators {
        if let Some(pos) = line.find(op) {
            let version_str = line[pos + op.len()..].trim();
            if let Some(major) = version_str.split('.').next() {
                if let Ok(v) = major.parse::<u32>() {
                    if v >= 90 {
                        let pkg = line[..pos].trim();
                        return Some(format!(
                            "dependency `{pkg}` specifies version {op}{version_str} which is likely unsatisfiable"
                        ));
                    }
                }
            }
        }
    }

    // Check for conflicting constraints on the same line (e.g., >=3.0,<2.0).
    if line.contains(',') {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let lower = extract_version_bound(parts[0], ">=")
                .or_else(|| extract_version_bound(parts[0], ">"));
            let upper = extract_version_bound(parts[1], "<=")
                .or_else(|| extract_version_bound(parts[1], "<"));
            if let (Some(lo), Some(hi)) = (lower, upper) {
                if lo > hi {
                    return Some(format!(
                        "dependency has conflicting version constraints: lower bound {lo} > upper bound {hi}"
                    ));
                }
            }
        }
    }

    None
}

fn extract_version_bound(spec: &str, op: &str) -> Option<u32> {
    if let Some(pos) = spec.find(op) {
        let version_str = spec[pos + op.len()..].trim();
        if let Some(major) = version_str.split('.').next() {
            return major.parse().ok();
        }
    }
    None
}

fn check_go_module_version(line: &str) -> Option<String> {
    let trimmed = line.trim();
    // Look for require lines with nonsensical versions.
    if !trimmed.starts_with("require") && !trimmed.contains(" v") {
        return None;
    }

    // Match `module/path v99.0.0` style.
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if part.starts_with('v') && part.contains('.') {
            let version = &part[1..]; // strip 'v'
            if let Some(major) = version.split('.').next() {
                if let Ok(v) = major.parse::<u32>() {
                    if v >= 90 {
                        let module = if i > 0 { parts[i - 1] } else { "unknown" };
                        return Some(format!(
                            "module `{module}` requires version {part} which is likely unsatisfiable"
                        ));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(path: &str, content: &str) -> FileInfo {
        FileInfo {
            path: path.to_owned(),
            content: content.as_bytes().to_vec(),
        }
    }

    // --- describe ---

    #[test]
    fn test_describe() {
        let module = AiQualityModule::new();
        let info = module.describe();
        assert_eq!(info.id, "ai-quality");
        assert_eq!(info.rules.len(), 7);
        assert!(info.languages.contains(&"go".to_owned()));
        assert!(info.languages.contains(&"python".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = AiQualityModule::default();
        let info = module.describe();
        assert_eq!(info.id, "ai-quality");
    }

    // --- phantom-api-call ---

    #[test]
    fn test_phantom_api_call_python() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "app.py",
            "def main():\n    result = nonexistent_api_function(data)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call")
            .collect();
        assert!(!phantom.is_empty(), "should detect phantom API call");
    }

    #[test]
    fn test_phantom_api_call_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {\n\tresult := fabricated_helper(x)\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call")
            .collect();
        assert!(!phantom.is_empty(), "should detect phantom API call in Go");
    }

    #[test]
    fn test_no_phantom_for_defined_function() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "app.py",
            "def helper():\n    return 42\n\ndef main():\n    x = helper()\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call" && f.message.contains("helper"))
            .collect();
        assert!(
            phantom.is_empty(),
            "should not flag defined function as phantom"
        );
    }

    #[test]
    fn test_no_phantom_for_builtins() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "app.py",
            "def main():\n    x = len([1, 2, 3])\n    print(x)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| {
                f.rule_id == "phantom-api-call"
                    && (f.message.contains("len") || f.message.contains("print"))
            })
            .collect();
        assert!(phantom.is_empty(), "should not flag builtins as phantom");
    }

    // --- phantom-security-call ---

    #[test]
    fn test_phantom_security_call() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "auth.py",
            "def login():\n    if verify_auth(token):\n        return True\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom_sec: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-security-call")
            .collect();
        assert!(
            !phantom_sec.is_empty(),
            "should detect phantom security call"
        );
    }

    #[test]
    fn test_no_phantom_security_when_defined() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "auth.py",
            "def verify_auth(token):\n    return token == 'valid'\n\ndef login():\n    if verify_auth('abc'):\n        return True\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom_sec: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-security-call")
            .collect();
        assert!(
            phantom_sec.is_empty(),
            "should not flag defined security function"
        );
    }

    // --- missing-decorator ---

    #[test]
    fn test_missing_decorator_python() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "views.py",
            "# requires @login_required\ndef admin_view():\n    pass\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let missing: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-decorator")
            .collect();
        assert!(!missing.is_empty(), "should detect missing decorator");
    }

    #[test]
    fn test_decorator_present_not_flagged() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "views.py",
            "# requires @login_required\n@login_required\ndef admin_view():\n    pass\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let missing: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-decorator")
            .collect();
        assert!(
            missing.is_empty(),
            "should not flag when decorator is present"
        );
    }

    #[test]
    fn test_missing_decorator_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "handler.go",
            "package main\n\n// requires authentication\nfunc AdminHandler() {\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let missing: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-decorator")
            .collect();
        assert!(
            !missing.is_empty(),
            "should detect missing auth middleware in Go"
        );
    }

    // --- unfinished-stub ---

    #[test]
    fn test_unfinished_stub_python_pass() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "service.py",
            "def process_payment():\n    pass\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let stubs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unfinished-stub")
            .collect();
        assert!(!stubs.is_empty(), "should detect Python pass stub");
    }

    #[test]
    fn test_unfinished_stub_python_todo() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "service.py",
            "def process_payment():\n    # TODO: implement\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let stubs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unfinished-stub")
            .collect();
        assert!(!stubs.is_empty(), "should detect Python TODO stub");
    }

    #[test]
    fn test_unfinished_stub_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "handler.go",
            "package main\n\nfunc Handle() {\n\t// TODO: implement\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let stubs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unfinished-stub")
            .collect();
        assert!(!stubs.is_empty(), "should detect Go TODO stub");
    }

    #[test]
    fn test_real_function_not_stub() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "service.py",
            "def process_payment():\n    charge = calculate_charge()\n    return charge\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let stubs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unfinished-stub" && f.message.contains("process_payment"))
            .collect();
        assert!(
            stubs.is_empty(),
            "should not flag function with real body as stub"
        );
    }

    // --- disabled-control ---

    #[test]
    fn test_disabled_control_commented_out() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "auth.py",
            "def login():\n    # validate_token(user_token)\n    return True\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let disabled: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "disabled-control")
            .collect();
        assert!(
            !disabled.is_empty(),
            "should detect commented-out security check"
        );
    }

    #[test]
    fn test_disabled_control_if_false_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "handler.go",
            "package main\n\nfunc Handle() {\n\tif false {\n\t\tvalidateCSRF(r)\n\t}\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let disabled: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "disabled-control")
            .collect();
        assert!(
            !disabled.is_empty(),
            "should detect if false gating security"
        );
    }

    #[test]
    fn test_disabled_control_if_false_python() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "auth.py",
            "def check():\n    if False:\n        verify_token(t)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let disabled: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "disabled-control")
            .collect();
        assert!(
            !disabled.is_empty(),
            "should detect if False gating security in Python"
        );
    }

    // --- impossible-dependency-version ---

    #[test]
    fn test_impossible_python_version() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "requirements.txt",
            "requests>=99.0.0\nflask==2.0.0\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let versions: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "impossible-dependency-version")
            .collect();
        assert_eq!(versions.len(), 1, "should detect impossible version");
        assert!(versions[0].message.contains("requests"));
    }

    #[test]
    fn test_valid_python_version_not_flagged() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "requirements.txt",
            "requests>=2.28.0\nflask==2.0.0\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let versions: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "impossible-dependency-version")
            .collect();
        assert!(versions.is_empty(), "should not flag valid versions");
    }

    #[test]
    fn test_impossible_go_mod_version() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors v99.0.0\n)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let versions: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "impossible-dependency-version")
            .collect();
        assert!(
            !versions.is_empty(),
            "should detect impossible Go module version"
        );
    }

    #[test]
    fn test_conflicting_python_version() {
        let module = AiQualityModule::new();
        let files = vec![make_file("requirements.txt", "requests>=3.0,<2.0\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let versions: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "impossible-dependency-version")
            .collect();
        assert!(
            !versions.is_empty(),
            "should detect conflicting constraints"
        );
    }

    // --- inconsistent-error-handling ---

    #[test]
    fn test_inconsistent_error_handling_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "mixed.go",
            "package main\n\nimport \"log\"\n\nfunc Do() error {\n\tif err != nil {\n\t\treturn err\n\t}\n\tpanic(\"unexpected\")\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let inconsistent: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "inconsistent-error-handling")
            .collect();
        assert!(
            !inconsistent.is_empty(),
            "should detect mixed error handling in Go"
        );
    }

    #[test]
    fn test_inconsistent_error_handling_python() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "mixed.py",
            "def process():\n    try:\n        do_thing()\n    except:\n        pass\n    try:\n        other()\n    except ValueError:\n        handle()\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let inconsistent: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "inconsistent-error-handling")
            .collect();
        assert!(
            !inconsistent.is_empty(),
            "should detect mixed error handling in Python"
        );
    }

    // --- explain ---

    #[test]
    fn test_explain_all_rules() {
        let module = AiQualityModule::new();
        let rule_ids = [
            "phantom-api-call",
            "phantom-security-call",
            "missing-decorator",
            "unfinished-stub",
            "disabled-control",
            "impossible-dependency-version",
            "inconsistent-error-handling",
        ];
        for rule_id in &rule_ids {
            let explanation = module.explain(rule_id).unwrap();
            assert_eq!(explanation.rule_id, *rule_id);
            assert!(!explanation.description.is_empty());
            assert!(!explanation.rationale.is_empty());
        }
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = AiQualityModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    // --- fix ---

    #[test]
    fn test_fix_dry_run() {
        let module = AiQualityModule::new();
        let findings = vec![Finding {
            rule_id: "unfinished-stub".to_owned(),
            message: "stub".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.py".to_owned(),
                start_line: 1,
                end_line: 2,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.9,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
    }

    #[test]
    fn test_fix_non_dry_run() {
        let module = AiQualityModule::new();
        let findings = vec![Finding {
            rule_id: "unfinished-stub".to_owned(),
            message: "stub".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.py".to_owned(),
                start_line: 1,
                end_line: 2,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.9,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert_eq!(results[0].reason, "no auto-fix available");
    }

    // --- edge cases ---

    #[test]
    fn test_non_source_files_skipped() {
        let module = AiQualityModule::new();
        let files = vec![make_file("readme.md", "# Hello\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_empty_file() {
        let module = AiQualityModule::new();
        let files = vec![make_file("empty.py", "")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_metrics() {
        let module = AiQualityModule::new();
        let files = vec![make_file("app.py", "def hello():\n    print('hi')\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert_eq!(result.metrics.files_analyzed, 1);
    }

    // --- helper function tests ---

    #[test]
    fn test_is_security_related() {
        assert!(is_security_related("verify_auth"));
        assert!(is_security_related("check_csrf_token"));
        assert!(is_security_related("sanitize_input"));
        assert!(!is_security_related("process_data"));
        assert!(!is_security_related("calculate_total"));
    }

    #[test]
    fn test_is_stub_body_python() {
        assert!(is_stub_body(&["pass"], Language::Python));
        assert!(is_stub_body(&["# TODO: implement"], Language::Python));
        assert!(is_stub_body(&["..."], Language::Python));
        assert!(is_stub_body(
            &["raise NotImplementedError"],
            Language::Python
        ));
        assert!(!is_stub_body(&["return 42"], Language::Python));
    }

    #[test]
    fn test_is_stub_body_go() {
        assert!(is_stub_body(&["// TODO: implement"], Language::Go));
        assert!(is_stub_body(&["panic(\"not implemented\")"], Language::Go));
        assert!(is_stub_body(&["return nil"], Language::Go));
        assert!(!is_stub_body(&["fmt.Println(\"hello\")"], Language::Go));
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("baz.txt"), None);
    }

    #[test]
    fn test_import_local_name() {
        let go_imp = ImportInfo {
            path: "github.com/pkg/errors".to_owned(),
            alias: None,
            names: vec![],
            line: 1,
        };
        assert_eq!(import_local_name(&go_imp, Language::Go), "errors");

        let py_imp = ImportInfo {
            path: "os.path".to_owned(),
            alias: Some("osp".to_owned()),
            names: vec![],
            line: 1,
        };
        assert_eq!(import_local_name(&py_imp, Language::Python), "osp");
    }

    #[test]
    fn test_check_python_requirement_valid() {
        assert!(check_python_requirement("requests>=2.28.0").is_none());
        assert!(check_python_requirement("flask==2.0.0").is_none());
    }

    #[test]
    fn test_check_python_requirement_impossible() {
        assert!(check_python_requirement("requests>=99.0.0").is_some());
    }

    #[test]
    fn test_check_go_module_version_valid() {
        assert!(check_go_module_version("\tgithub.com/pkg/errors v0.9.1").is_none());
    }

    #[test]
    fn test_check_go_module_version_impossible() {
        assert!(check_go_module_version("\tgithub.com/pkg/errors v99.0.0").is_some());
    }

    #[test]
    fn test_looks_like_disabled_security_check() {
        assert!(looks_like_disabled_security_check("validate_token(user)"));
        assert!(looks_like_disabled_security_check("check_auth(request)"));
        assert!(!looks_like_disabled_security_check("this is a comment"));
        assert!(!looks_like_disabled_security_check("TODO: add auth"));
    }

    #[test]
    fn test_unfinished_stub_not_implemented_error() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "service.py",
            "def process_payment():\n    raise NotImplementedError()\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let stubs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unfinished-stub")
            .collect();
        assert!(
            !stubs.is_empty(),
            "should detect NotImplementedError as stub"
        );
    }

    // --- M2 regression: Go method calls with >2 char names ---

    #[test]
    fn test_go_method_call_not_flagged_as_phantom() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "server.go",
            "package main\n\nfunc main() {\n\tserver.Handle(\"/api\")\n\tserver.Serve()\n\tconn.Close()\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| {
                f.rule_id == "phantom-api-call"
                    && (f.message.contains("Handle") || f.message.contains("Serve"))
            })
            .collect();
        assert!(
            phantom.is_empty(),
            "should not flag Go receiver method calls (Handle, Serve) as phantom"
        );
    }

    // --- M1 regression: suppression via chaffra:ignore ---

    #[test]
    fn test_suppression_same_line_python() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "app.py",
            "def main():\n    result = nonexistent_api_function(data)  # chaffra:ignore phantom-api-call\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call")
            .collect();
        assert!(
            phantom.is_empty(),
            "should suppress phantom-api-call with inline chaffra:ignore comment"
        );
    }

    #[test]
    fn test_suppression_preceding_line_go() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {\n\t// chaffra:ignore phantom-api-call\n\tresult := fabricated_helper(x)\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call")
            .collect();
        assert!(
            phantom.is_empty(),
            "should suppress phantom-api-call with preceding-line chaffra:ignore comment"
        );
    }

    #[test]
    fn test_suppression_wrong_rule_not_suppressed() {
        let module = AiQualityModule::new();
        let files = vec![make_file(
            "app.py",
            "def main():\n    result = nonexistent_api_function(data)  # chaffra:ignore unfinished-stub\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let phantom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "phantom-api-call")
            .collect();
        assert!(
            !phantom.is_empty(),
            "should NOT suppress phantom-api-call when chaffra:ignore targets a different rule"
        );
    }

    // --- M5 regression: fix not in capabilities ---

    #[test]
    fn test_fix_not_in_capabilities() {
        let module = AiQualityModule::new();
        let info = module.describe();
        assert!(
            !info.capabilities.contains(&"fix".to_owned()),
            "capabilities should not include 'fix'"
        );
    }

    // --- L2 regression: is_function_call skips comments ---

    #[test]
    fn test_is_function_call_skips_comments_python() {
        // The function name only appears inside a comment
        assert!(!is_function_call(
            "phantom_fn",
            "def main():\n    # phantom_fn(data)\n    pass\n",
            Language::Python,
        ));
    }

    #[test]
    fn test_is_function_call_skips_comments_go() {
        assert!(!is_function_call(
            "phantom_fn",
            "package main\n\n// phantom_fn(data)\nfunc main() {}\n",
            Language::Go,
        ));
    }

    #[test]
    fn test_is_function_call_matches_real_code() {
        assert!(is_function_call(
            "real_fn",
            "def main():\n    result = real_fn(data)\n",
            Language::Python,
        ));
    }

    // --- is_likely_method_call with source ---

    #[test]
    fn test_is_likely_method_call_go_receiver() {
        let source = "server.Handle(\"/api\")\nserver.Serve()\n";
        assert!(is_likely_method_call("Handle", source, Language::Go));
        assert!(is_likely_method_call("Serve", source, Language::Go));
        // Standalone call (no dot receiver) should not be treated as method call
        let source2 = "Handle(\"/api\")\n";
        assert!(!is_likely_method_call("Handle", source2, Language::Go));
    }
}
