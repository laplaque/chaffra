//! LLM defense analysis module.
//!
//! Detects security risks in code that integrates with large language models:
//! unsafe tool use, prompt injection exposure, missing output validation,
//! missing rate limiting, excessive tool permissions, and unguarded agent loops.

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::detect_language;
use chaffra_parse::parser;
use chaffra_parse::suppression::is_line_suppressed;
use chaffra_parse::symbols::{self, ImportInfo};
use std::collections::{HashMap, HashSet};

pub struct LlmDefenseModule;

impl LlmDefenseModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LlmDefenseModule {
    fn default() -> Self {
        Self::new()
    }
}

const RULES: &[(&str, &str, &str, Severity, &str)] = &[
    (
        "unsafe-tool-use",
        "Unsafe tool use",
        "LLM tool definition allows execution of arbitrary code or commands",
        Severity::Error,
        "llm-defense",
    ),
    (
        "prompt-injection-exposure",
        "Prompt injection exposure",
        "User input is concatenated directly into an LLM prompt without sanitization",
        Severity::Error,
        "llm-defense",
    ),
    (
        "missing-output-validation",
        "Missing output validation",
        "LLM response is used in SQL, HTML, or shell context without validation",
        Severity::Error,
        "llm-defense",
    ),
    (
        "missing-rate-limit",
        "Missing rate limit",
        "LLM API calls are made without rate limiting or throttling",
        Severity::Warning,
        "llm-defense",
    ),
    (
        "excessive-tool-permissions",
        "Excessive tool permissions",
        "Tool definition grants write permissions where read would suffice",
        Severity::Warning,
        "llm-defense",
    ),
    (
        "unguarded-agent-loop",
        "Unguarded agent loop",
        "Agent loop has no iteration limit or timeout guard",
        Severity::Error,
        "llm-defense",
    ),
];

/// LLM SDK import patterns (Python).
const LLM_PYTHON_IMPORTS: &[&str] = &[
    "openai",
    "anthropic",
    "langchain",
    "llama_index",
    "transformers",
    "cohere",
    "google.generativeai",
    "vertexai",
    "litellm",
    "autogen",
    "crewai",
];

/// LLM SDK import patterns (Go).
const LLM_GO_IMPORTS: &[&str] = &[
    "github.com/sashabaranov/go-openai",
    "github.com/anthropics/anthropic-sdk-go",
    "github.com/tmc/langchaingo",
];

/// Patterns indicating unsafe tool execution capabilities.
const UNSAFE_TOOL_PATTERNS: &[&str] = &[
    "subprocess",
    "os.system",
    "exec.Command",
    "os.exec",
    "eval(",
    "exec(",
    "shell=True",
    "os.popen",
    "commands.getoutput",
];

/// Patterns indicating prompt construction with user input.
const PROMPT_INJECTION_PATTERNS: &[&str] = &[
    "f\"",       // f-string with potential user data
    "f'",        // f-string with potential user data
    ".format(",  // str.format
    "% ",        // printf-style
    "+ user",    // string concatenation with user variable
    "+ input",   // string concatenation with input variable
    "+ query",   // string concatenation with query variable
    "+ request", // string concatenation with request variable
];

/// Keywords indicating a prompt context.
const PROMPT_CONTEXT_KEYWORDS: &[&str] = &[
    "prompt",
    "system_prompt",
    "user_prompt",
    "message",
    "messages",
    "instruction",
    "system_message",
    "human_message",
    "template",
];

/// Patterns indicating output used in dangerous contexts.
const DANGEROUS_OUTPUT_CONTEXTS: &[&str] = &[
    "execute(", // SQL execute
    "cursor.execute",
    "db.execute",
    "innerHTML",
    "dangerouslySetInnerHTML",
    "os.system(",
    "subprocess.run(",
    "subprocess.call(",
    "exec.Command(",
    "Exec(",
];

/// Rate limiting indicator patterns.
const RATE_LIMIT_PATTERNS: &[&str] = &[
    "rate_limit",
    "ratelimit",
    "throttle",
    "limiter",
    "semaphore",
    "time.sleep",
    "time.Sleep",
    "backoff",
    "retry",
    "RateLimiter",
    "TokenBucket",
    "LeakyBucket",
];

/// Agent loop patterns.
const AGENT_LOOP_PATTERNS: &[&str] = &[
    "while True",
    "while true",
    "for {",  // Go infinite loop
    "loop {", // Rust-style but in comments/docs
];

/// Loop guard patterns.
const LOOP_GUARD_PATTERNS: &[&str] = &[
    "max_iterations",
    "max_steps",
    "max_turns",
    "iteration_limit",
    "step_limit",
    "timeout",
    "max_loops",
    "break",
    "counter",
    "attempts",
    "max_retries",
];

impl AnalysisModule for LlmDefenseModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "llm-defense".to_owned(),
            name: "LLM Defense Analysis".to_owned(),
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

        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l @ Language::Go) | Some(l @ Language::Python) => l,
                _ => continue,
            };

            let tree = parser::parse(&file.content, lang)?;
            let imports = symbols::extract_imports(&tree, &file.content, lang);
            let source = String::from_utf8_lossy(&file.content).to_string();

            // Only analyze files that import LLM SDKs or contain LLM-related code.
            if !has_llm_imports(&imports, lang) && !has_llm_indicators(&source) {
                continue;
            }

            let fd = FileData {
                path: file.path.clone(),
                language: lang,
                source,
            };

            detect_unsafe_tool_use(&fd, &mut findings);
            detect_prompt_injection(&fd, &mut findings);
            detect_missing_output_validation(&fd, &mut findings);
            detect_missing_rate_limit(&fd, &mut findings);
            detect_excessive_tool_permissions(&fd, &mut findings);
            detect_unguarded_agent_loop(&fd, &mut findings);
        }

        // Filter out findings suppressed by `chaffra:ignore <rule-id>` comments.
        let findings = findings
            .into_iter()
            .filter(|f| {
                let file = files.iter().find(|fi| fi.path == f.location.file);
                if let Some(fi) = file {
                    let source = String::from_utf8_lossy(&fi.content);
                    let lang = detect_language(&fi.path).unwrap_or(Language::Python);
                    !is_line_suppressed(&source, f.location.start_line, &f.rule_id, lang)
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
            "unsafe-tool-use" => Ok(RuleExplanation {
                rule_id: "unsafe-tool-use".to_owned(),
                name: "Unsafe tool use".to_owned(),
                description: "Detects LLM tool definitions that allow executing arbitrary code.".to_owned(),
                rationale: "If an LLM can invoke shell commands or eval code, a prompt injection can escalate to remote code execution.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore unsafe-tool-use".to_owned(),
                examples: vec![
                    "tools = [{'name': 'run_code', 'fn': lambda code: exec(code)}]".to_owned(),
                ],
            }),
            "prompt-injection-exposure" => Ok(RuleExplanation {
                rule_id: "prompt-injection-exposure".to_owned(),
                name: "Prompt injection exposure".to_owned(),
                description: "User input is concatenated into an LLM prompt without sanitization.".to_owned(),
                rationale: "Unsanitized user input in prompts allows attackers to override system instructions.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore prompt-injection-exposure".to_owned(),
                examples: vec![
                    "prompt = f\"Summarize: {user_input}\"".to_owned(),
                ],
            }),
            "missing-output-validation" => Ok(RuleExplanation {
                rule_id: "missing-output-validation".to_owned(),
                name: "Missing output validation".to_owned(),
                description: "LLM output is used in SQL, HTML, or shell without validation.".to_owned(),
                rationale: "LLM outputs are untrusted and must be validated before use in injection-sensitive contexts.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore missing-output-validation".to_owned(),
                examples: vec![
                    "cursor.execute(f\"SELECT * FROM {llm_response}\")".to_owned(),
                ],
            }),
            "missing-rate-limit" => Ok(RuleExplanation {
                rule_id: "missing-rate-limit".to_owned(),
                name: "Missing rate limit".to_owned(),
                description: "LLM API calls without rate limiting or throttling.".to_owned(),
                rationale: "Unbounded LLM calls can lead to cost overruns, quota exhaustion, or denial of service.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore missing-rate-limit".to_owned(),
                examples: vec![],
            }),
            "excessive-tool-permissions" => Ok(RuleExplanation {
                rule_id: "excessive-tool-permissions".to_owned(),
                name: "Excessive tool permissions".to_owned(),
                description: "Tool definitions grant write/execute permissions where read would suffice.".to_owned(),
                rationale: "Least-privilege principle: tools should only have the minimum permissions needed.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore excessive-tool-permissions".to_owned(),
                examples: vec![
                    "tool = {'name': 'file_manager', 'permissions': ['read', 'write', 'delete']}".to_owned(),
                ],
            }),
            "unguarded-agent-loop" => Ok(RuleExplanation {
                rule_id: "unguarded-agent-loop".to_owned(),
                name: "Unguarded agent loop".to_owned(),
                description: "Agent loop runs without iteration limit or timeout.".to_owned(),
                rationale: "Unbounded agent loops can run indefinitely, consuming resources and accumulating costs.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore unguarded-agent-loop".to_owned(),
                examples: vec![
                    "while True:\n    response = agent.step()".to_owned(),
                ],
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
    source: String,
}

fn has_llm_imports(imports: &[ImportInfo], lang: Language) -> bool {
    let patterns = match lang {
        Language::Python => LLM_PYTHON_IMPORTS,
        Language::Go => LLM_GO_IMPORTS,
        _ => return false,
    };

    imports.iter().any(|imp| {
        patterns
            .iter()
            .any(|p| imp.path.contains(p) || imp.names.iter().any(|n| n.contains(p)))
    })
}

fn has_llm_indicators(source: &str) -> bool {
    let lower = source.to_lowercase();
    lower.contains("openai")
        || lower.contains("anthropic")
        || lower.contains("langchain")
        || lower.contains("llm")
        || lower.contains("chat_completion")
        || lower.contains("chatcompletion")
        || lower.contains("completion.create")
        || lower.contains("generate_content")
}

/// Detect tool definitions that allow arbitrary code execution.
fn detect_unsafe_tool_use(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    // Look for tool definitions that reference unsafe execution.
    let mut in_tool_def = false;
    let mut tool_start_line = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim().to_lowercase();

        // Detect start of a tool definition.
        if trimmed.contains("tool")
            && (trimmed.contains("def")
                || trimmed.contains("function")
                || trimmed.contains("{")
                || trimmed.contains("dict")
                || trimmed.contains("="))
        {
            in_tool_def = true;
            tool_start_line = i;
        }

        // Check for unsafe patterns only within actual tool definition blocks.
        if in_tool_def {
            for pattern in UNSAFE_TOOL_PATTERNS {
                if fd
                    .source
                    .lines()
                    .nth(i)
                    .is_some_and(|l| l.contains(pattern))
                {
                    findings.push(Finding {
                        rule_id: "unsafe-tool-use".to_owned(),
                        message: format!(
                            "tool definition uses unsafe execution pattern: `{pattern}`"
                        ),
                        severity: Severity::Error,
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

        // Reset tool context after a few lines or at closing brace.
        if in_tool_def && (i - tool_start_line > 20 || trimmed == "}" || trimmed == "]") {
            in_tool_def = false;
        }
    }
}

/// Detect prompt injection via direct user input concatenation.
fn detect_prompt_injection(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Check if this line involves prompt construction.
        let is_prompt_line = PROMPT_CONTEXT_KEYWORDS
            .iter()
            .any(|k| trimmed.to_lowercase().contains(k));

        if !is_prompt_line {
            continue;
        }

        // Check for string interpolation with user input.
        for pattern in PROMPT_INJECTION_PATTERNS {
            if trimmed.contains(pattern) {
                // Verify this involves user-controlled data.
                if has_user_input_indicator(trimmed) {
                    findings.push(Finding {
                        rule_id: "prompt-injection-exposure".to_owned(),
                        message: "user input is concatenated into LLM prompt without sanitization"
                            .to_owned(),
                        severity: Severity::Error,
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
                    break; // One finding per line.
                }
            }
        }
    }
}

/// Detect LLM output used in dangerous contexts.
fn detect_missing_output_validation(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    // First pass: find variables that hold LLM responses.
    let response_vars = find_llm_response_vars(&lines, fd.language);

    // Second pass: check if those variables are used in dangerous contexts.
    for (i, line) in lines.iter().enumerate() {
        for context in DANGEROUS_OUTPUT_CONTEXTS {
            if line.contains(context) {
                // Check if any LLM response variable is referenced on this line.
                for var in &response_vars {
                    if line.contains(var.as_str()) {
                        findings.push(Finding {
                            rule_id: "missing-output-validation".to_owned(),
                            message: format!(
                                "LLM response variable `{var}` used in `{context}` without validation"
                            ),
                            severity: Severity::Error,
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
}

/// Detect LLM calls without rate limiting.
fn detect_missing_rate_limit(fd: &FileData, findings: &mut Vec<Finding>) {
    // Check if file has LLM API calls.
    let has_llm_calls = has_llm_api_call_patterns(&fd.source);
    if !has_llm_calls {
        return;
    }

    // Check if there are any rate limiting patterns in the file.
    let has_rate_limiting = RATE_LIMIT_PATTERNS.iter().any(|p| fd.source.contains(p));

    if !has_rate_limiting {
        // Find the first LLM call line for location.
        let line_num = find_first_llm_call_line(&fd.source);
        findings.push(Finding {
            rule_id: "missing-rate-limit".to_owned(),
            message: "LLM API calls without rate limiting in this file".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: fd.path.clone(),
                start_line: line_num,
                end_line: line_num,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.7,
            actions: vec![],
            metadata: HashMap::new(),
        });
    }
}

/// Detect tool definitions with excessive permissions.
fn detect_excessive_tool_permissions(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim().to_lowercase();

        // Look for tool permission definitions.
        if !trimmed.contains("permission")
            && !trimmed.contains("access")
            && !trimmed.contains("scope")
        {
            continue;
        }

        // Check for write/delete/execute permissions.
        let has_write =
            trimmed.contains("write") || trimmed.contains("delete") || trimmed.contains("execute");
        let has_read = trimmed.contains("read");

        // If both read and write are in the same permission line, flag it.
        if has_write && has_read && (trimmed.contains("tool") || is_in_tool_context(&lines, i)) {
            findings.push(Finding {
                rule_id: "excessive-tool-permissions".to_owned(),
                message:
                    "tool grants write/delete permissions alongside read; consider least-privilege"
                        .to_owned(),
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

/// Detect agent loops without iteration limits.
fn detect_unguarded_agent_loop(fd: &FileData, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = fd.source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Check for infinite loop patterns.
        let is_infinite_loop = AGENT_LOOP_PATTERNS.iter().any(|p| trimmed.starts_with(p));
        if !is_infinite_loop {
            continue;
        }

        // Check if this loop is in an LLM/agent context.
        if !is_in_agent_context(&lines, i) {
            continue;
        }

        // Check if the loop has guard conditions.
        let has_guard = check_loop_guards(&lines, i);
        if !has_guard {
            findings.push(Finding {
                rule_id: "unguarded-agent-loop".to_owned(),
                message: "agent loop without iteration limit or timeout guard".to_owned(),
                severity: Severity::Error,
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

// --- Helpers ---

fn has_user_input_indicator(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("user")
        || lower.contains("input")
        || lower.contains("query")
        || lower.contains("request")
        || lower.contains("body")
        || lower.contains("param")
        || lower.contains("arg")
}

fn find_llm_response_vars(lines: &[&str], _lang: Language) -> HashSet<String> {
    let mut vars = HashSet::new();
    let response_name_patterns = [
        "completion",
        "response",
        "result",
        "output",
        "generated",
        "chat_response",
        "llm_output",
        "ai_response",
    ];

    let is_llm_rhs = |rhs: &str| -> bool {
        rhs.contains("client.messages.create")
            || rhs.contains("openai.chat.completions.create")
            || rhs.contains("chat.completions.create")
            || rhs.contains("completions.create")
            || rhs.contains("messages.create")
            || rhs.contains("chain.invoke")
            || rhs.contains("llm.generate")
            || rhs.contains("model.predict")
            || rhs.contains("chatcompletion.create")
            || rhs.contains("generate_content")
    };

    for line in lines {
        let trimmed = line.trim();
        if let Some(eq_pos) = trimmed.find('=') {
            if eq_pos + 1 >= trimmed.len() {
                continue;
            }
            let next_char = trimmed.as_bytes().get(eq_pos + 1);
            if next_char == Some(&b'=') {
                continue;
            }

            let lhs = trimmed[..eq_pos].trim();
            let rhs = trimmed[eq_pos + 1..].trim().to_lowercase();

            let has_llm_name = {
                let lhs_lower = lhs.to_lowercase();
                response_name_patterns.iter().any(|p| lhs_lower.contains(p))
            };

            let has_llm_call = is_llm_rhs(&rhs);

            if has_llm_name && has_llm_call {
                let var_name = lhs
                    .split_whitespace()
                    .last()
                    .unwrap_or(lhs)
                    .trim_start_matches("let ")
                    .trim_start_matches("var ")
                    .trim_start_matches(':')
                    .trim();
                if !var_name.is_empty() {
                    vars.insert(var_name.to_owned());
                }
            }
        }
    }
    vars
}

fn has_llm_api_call_patterns(source: &str) -> bool {
    let patterns = [
        "openai.ChatCompletion",
        "client.chat.completions",
        "client.completions",
        "client.messages.create",
        "anthropic.Anthropic",
        "completions.create(",
        "messages.create(",
        "ChatCompletion.create(",
        "generate_content(",
        "ChatOpenAI",
        "chat.completions.create",
    ];
    patterns.iter().any(|p| source.contains(p))
}

fn find_first_llm_call_line(source: &str) -> u32 {
    let patterns = [
        "create(",
        "generate(",
        "complete(",
        "chat(",
        "ChatCompletion",
        "messages.create",
    ];
    for (i, line) in source.lines().enumerate() {
        if patterns.iter().any(|p| line.contains(p)) {
            return (i + 1) as u32;
        }
    }
    1
}

fn is_in_tool_context(lines: &[&str], current: usize) -> bool {
    // Look backwards a few lines for tool-related keywords.
    let start = current.saturating_sub(10);
    for line in lines.iter().take(current).skip(start) {
        let lower = line.trim().to_lowercase();
        if lower.contains("tool") || lower.contains("function_call") || lower.contains("plugin") {
            return true;
        }
    }
    false
}

fn is_in_agent_context(lines: &[&str], current: usize) -> bool {
    // Check surrounding lines for agent/LLM context.
    let start = current.saturating_sub(15);
    let end = (current + 15).min(lines.len());
    for line in lines.iter().take(end).skip(start) {
        let lower = line.trim().to_lowercase();
        if lower.contains("agent")
            || lower.contains("llm")
            || lower.contains("openai")
            || lower.contains("anthropic")
            || lower.contains("chat")
            || lower.contains("completion")
            || lower.contains("step")
        {
            return true;
        }
    }
    false
}

fn check_loop_guards(lines: &[&str], loop_line: usize) -> bool {
    // Check the loop line and the next ~30 lines for guard conditions.
    let end = (loop_line + 30).min(lines.len());
    for line in lines.iter().take(end).skip(loop_line) {
        let lower = line.trim().to_lowercase();
        if LOOP_GUARD_PATTERNS.iter().any(|p| lower.contains(p)) {
            return true;
        }
    }
    false
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
        let module = LlmDefenseModule::new();
        let info = module.describe();
        assert_eq!(info.id, "llm-defense");
        assert_eq!(info.rules.len(), 6);
        assert!(info.languages.contains(&"go".to_owned()));
        assert!(info.languages.contains(&"python".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = LlmDefenseModule;
        let info = module.describe();
        assert_eq!(info.id, "llm-defense");
    }

    // --- unsafe-tool-use ---

    #[test]
    fn test_unsafe_tool_use_exec() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "agent.py",
            "import openai\n\ntool_def = {'name': 'run', 'fn': lambda c: exec(c)}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unsafe_tools: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unsafe-tool-use")
            .collect();
        assert!(!unsafe_tools.is_empty(), "should detect exec in tool def");
    }

    #[test]
    fn test_unsafe_tool_use_subprocess() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "tools.py",
            "import openai\nimport subprocess\n\ndef tool_run_command(cmd):\n    subprocess.run(cmd, shell=True)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unsafe_tools: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unsafe-tool-use")
            .collect();
        assert!(
            !unsafe_tools.is_empty(),
            "should detect subprocess in tool context"
        );
    }

    // --- prompt-injection-exposure ---

    #[test]
    fn test_prompt_injection_fstring() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "chat.py",
            "import openai\n\ndef ask(user_input):\n    prompt = f\"Summarize: {user_input}\"\n    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let injections: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "prompt-injection-exposure")
            .collect();
        assert!(
            !injections.is_empty(),
            "should detect prompt injection via f-string"
        );
    }

    #[test]
    fn test_prompt_injection_format() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "chat.py",
            "import openai\n\ndef ask(user_query):\n    prompt = \"Answer: {}\".format(user_query)\n    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let injections: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "prompt-injection-exposure")
            .collect();
        assert!(
            !injections.is_empty(),
            "should detect prompt injection via .format()"
        );
    }

    // --- missing-output-validation ---

    #[test]
    fn test_missing_output_validation_sql() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "db_agent.py",
            "import openai\n\nresponse = client.chat.completions.create(messages=[])\ncursor.execute(f\"SELECT * FROM {response}\")\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let violations: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-output-validation")
            .collect();
        assert!(
            !violations.is_empty(),
            "should detect LLM output in SQL execute"
        );
    }

    #[test]
    fn test_missing_output_validation_shell() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "agent.py",
            "import openai\n\nresult = client.chat.completions.create(messages=[])\nos.system(result)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let violations: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-output-validation")
            .collect();
        assert!(
            !violations.is_empty(),
            "should detect LLM output in os.system"
        );
    }

    // --- missing-rate-limit ---

    #[test]
    fn test_missing_rate_limit() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "bot.py",
            "import openai\n\ndef respond(msg):\n    return client.chat.completions.create(messages=[{'content': msg}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let rate: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-rate-limit")
            .collect();
        assert!(!rate.is_empty(), "should detect missing rate limit");
    }

    #[test]
    fn test_rate_limit_present_not_flagged() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "bot.py",
            "import openai\nimport time\n\ndef respond(msg):\n    time.sleep(1)  # rate_limit\n    return client.chat.completions.create(messages=[{'content': msg}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let rate: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-rate-limit")
            .collect();
        assert!(
            rate.is_empty(),
            "should not flag when rate limiting is present"
        );
    }

    // --- excessive-tool-permissions ---

    #[test]
    fn test_excessive_tool_permissions() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "tools.py",
            "import openai\n\ntool = {'name': 'file_manager', 'permissions': ['read', 'write', 'delete']}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let perms: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "excessive-tool-permissions")
            .collect();
        assert!(
            !perms.is_empty(),
            "should detect excessive tool permissions"
        );
    }

    // --- unguarded-agent-loop ---

    #[test]
    fn test_unguarded_agent_loop() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "agent.py",
            "import openai\n\ndef run_agent():\n    while True:\n        response = agent.step()\n        if response.done:\n            return\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let loops: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unguarded-agent-loop")
            .collect();
        assert!(!loops.is_empty(), "should detect unguarded agent loop");
    }

    #[test]
    fn test_guarded_agent_loop_not_flagged() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "agent.py",
            "import openai\n\ndef run_agent():\n    max_iterations = 100\n    while True:\n        response = agent.step()\n        max_iterations -= 1\n        if max_iterations <= 0:\n            break\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let loops: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unguarded-agent-loop")
            .collect();
        assert!(loops.is_empty(), "should not flag guarded agent loop");
    }

    // --- explain ---

    #[test]
    fn test_explain_all_rules() {
        let module = LlmDefenseModule::new();
        let rule_ids = [
            "unsafe-tool-use",
            "prompt-injection-exposure",
            "missing-output-validation",
            "missing-rate-limit",
            "excessive-tool-permissions",
            "unguarded-agent-loop",
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
        let module = LlmDefenseModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    // --- fix ---

    #[test]
    fn test_fix_dry_run() {
        let module = LlmDefenseModule::new();
        let findings = vec![Finding {
            rule_id: "unsafe-tool-use".to_owned(),
            message: "unsafe".to_owned(),
            severity: Severity::Error,
            location: Location {
                file: "test.py".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.8,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
    }

    #[test]
    fn test_fix_non_dry_run() {
        let module = LlmDefenseModule::new();
        let findings = vec![Finding {
            rule_id: "unsafe-tool-use".to_owned(),
            message: "unsafe".to_owned(),
            severity: Severity::Error,
            location: Location {
                file: "test.py".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.8,
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
    fn test_non_llm_file_skipped() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file("utils.py", "def add(a, b):\n    return a + b\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(
            result.findings.is_empty(),
            "non-LLM file should have no findings"
        );
    }

    #[test]
    fn test_non_source_file_skipped() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file("readme.md", "# Hello\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_metrics() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file("app.py", "import openai\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert_eq!(result.metrics.files_analyzed, 1);
    }

    // --- helper function tests ---

    #[test]
    fn test_has_llm_imports_python() {
        let imports = vec![ImportInfo {
            path: "openai".to_owned(),
            alias: None,
            names: vec![],
            line: 1,
        }];
        assert!(has_llm_imports(&imports, Language::Python));
    }

    #[test]
    fn test_has_llm_imports_go() {
        let imports = vec![ImportInfo {
            path: "github.com/sashabaranov/go-openai".to_owned(),
            alias: None,
            names: vec![],
            line: 1,
        }];
        assert!(has_llm_imports(&imports, Language::Go));
    }

    #[test]
    fn test_no_llm_imports() {
        let imports = vec![ImportInfo {
            path: "os".to_owned(),
            alias: None,
            names: vec![],
            line: 1,
        }];
        assert!(!has_llm_imports(&imports, Language::Python));
    }

    #[test]
    fn test_has_llm_indicators() {
        assert!(has_llm_indicators("client = openai.OpenAI()"));
        assert!(has_llm_indicators("# Using anthropic SDK"));
        assert!(!has_llm_indicators("def add(a, b): return a + b"));
    }

    #[test]
    fn test_has_user_input_indicator() {
        assert!(has_user_input_indicator("prompt = f\"{user_input}\""));
        assert!(has_user_input_indicator("query = request.body"));
        assert!(!has_user_input_indicator("x = 42"));
    }

    #[test]
    fn test_is_in_agent_context() {
        let lines = vec!["import openai", "def agent_step():", "    while True:"];
        assert!(is_in_agent_context(&lines, 2));
    }

    #[test]
    fn test_check_loop_guards() {
        let lines = vec![
            "while True:",
            "    result = step()",
            "    max_iterations -= 1",
            "    if max_iterations <= 0:",
            "        break",
        ];
        assert!(check_loop_guards(&lines, 0));
    }

    #[test]
    fn test_check_loop_guards_no_guard() {
        let lines = vec!["while True:", "    result = step()", "    process(result)"];
        assert!(!check_loop_guards(&lines, 0));
    }

    #[test]
    fn test_find_llm_response_vars() {
        let lines = vec![
            "response = client.chat.completions.create(messages=[])",
            "cursor.execute(response)",
        ];
        let vars = find_llm_response_vars(&lines, Language::Python);
        assert!(vars.contains("response"));
    }

    #[test]
    fn test_find_llm_response_vars_requires_both_conditions() {
        let cases: &[(&[&str], &str, bool, &str)] = &[
            (
                &["result = some_function()"],
                "result",
                false,
                "LLM-like name without LLM call",
            ),
            (
                &["data = client.chat.completions.create(messages=[])"],
                "data",
                false,
                "LLM call without LLM-like name",
            ),
            (
                &["response = client.chat.completions.create(messages=[])"],
                "response",
                true,
                "both LLM name and LLM call",
            ),
        ];
        for (lines, var, expected, desc) in cases {
            let lines_owned: Vec<&str> = lines.to_vec();
            let vars = find_llm_response_vars(&lines_owned, Language::Python);
            assert_eq!(vars.contains(*var), *expected, "{}", desc);
        }
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("baz.txt"), None);
    }

    #[test]
    fn test_unguarded_go_agent_loop() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "agent.go",
            "package main\n\nimport openai \"github.com/sashabaranov/go-openai\"\n\nfunc runAgent() {\n\tfor {\n\t\tresp := agent.step()\n\t\tif resp.Done {\n\t\t\treturn\n\t\t}\n\t}\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let loops: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unguarded-agent-loop")
            .collect();
        assert!(!loops.is_empty(), "should detect unguarded Go agent loop");
    }

    // --- M3 regression: unsafe-tool-use only fires within tool defs ---

    #[test]
    fn test_unsafe_tool_use_not_fired_for_comment_with_tool() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "utils.py",
            "import openai\n\n# This is a tool for data processing\nimport subprocess\nsubprocess.run(['ls'])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unsafe_tools: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unsafe-tool-use")
            .collect();
        assert!(
            unsafe_tools.is_empty(),
            "should not flag subprocess outside of tool definitions"
        );
    }

    #[test]
    fn test_unsafe_tool_use_fires_within_tool_def() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "tools.py",
            "import openai\n\ndef tool_executor(cmd):\n    subprocess.run(cmd, shell=True)\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unsafe_tools: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unsafe-tool-use")
            .collect();
        assert!(
            !unsafe_tools.is_empty(),
            "should detect unsafe patterns within tool definitions"
        );
    }

    // --- M4 regression: .create( pattern not too broad ---

    #[test]
    fn test_create_call_not_false_positive() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "models.py",
            "import os\n\ndef setup():\n    db.create(table_name)\n    Widget.create(name='test')\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        // File should not be detected as having LLM calls
        assert!(
            result.findings.is_empty(),
            "should not treat generic .create() calls as LLM API calls"
        );
    }

    #[test]
    fn test_specific_llm_create_detected() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "bot.py",
            "import openai\n\ndef respond(msg):\n    return client.chat.completions.create(messages=[{'content': msg}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let rate: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "missing-rate-limit")
            .collect();
        assert!(
            !rate.is_empty(),
            "should detect specific LLM API create calls"
        );
    }

    // --- M1+M5 regression: suppression and fix capability ---

    #[test]
    fn test_fix_not_in_capabilities() {
        let module = LlmDefenseModule::new();
        let info = module.describe();
        assert!(
            !info.capabilities.contains(&"fix".to_owned()),
            "capabilities should not include 'fix'"
        );
    }

    #[test]
    fn test_suppression_same_line() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "chat.py",
            "import openai\n\ndef ask(user_input):\n    prompt = f\"Summarize: {user_input}\"  # chaffra:ignore prompt-injection-exposure\n    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let injections: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "prompt-injection-exposure")
            .collect();
        assert!(
            injections.is_empty(),
            "should suppress prompt-injection-exposure with inline chaffra:ignore"
        );
    }

    #[test]
    fn test_suppression_preceding_line() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "chat.py",
            "import openai\n\ndef ask(user_input):\n    # chaffra:ignore prompt-injection-exposure\n    prompt = f\"Summarize: {user_input}\"\n    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let injections: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "prompt-injection-exposure")
            .collect();
        assert!(
            injections.is_empty(),
            "should suppress with preceding-line chaffra:ignore"
        );
    }

    #[test]
    fn test_suppression_wrong_rule_not_suppressed() {
        let module = LlmDefenseModule::new();
        let files = vec![make_file(
            "chat.py",
            "import openai\n\ndef ask(user_input):\n    prompt = f\"Summarize: {user_input}\"  # chaffra:ignore missing-rate-limit\n    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let injections: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "prompt-injection-exposure")
            .collect();
        assert!(
            !injections.is_empty(),
            "should NOT suppress when chaffra:ignore targets a different rule"
        );
    }
}
