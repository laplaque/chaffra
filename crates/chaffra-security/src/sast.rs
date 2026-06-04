//! SAST — intraprocedural taint analysis for injection vulnerabilities.
//!
//! Detects tainted data flowing from sources (user input) to sinks (dangerous
//! operations) without sanitization, within a single function scope.

use chaffra_core::diagnostic::{Action, FileInfo, Finding, Language, Location, Severity};
use chaffra_parse::parser;
use std::collections::HashMap;
use tree_sitter::Node;

/// A taint source: where untrusted data enters.
#[derive(Debug, Clone)]
struct TaintSource {
    /// Name pattern to match (e.g. "Request", "request").
    pattern: &'static str,
    /// Language this source applies to.
    language: Language,
    /// Description for diagnostics.
    description: &'static str,
}

/// A taint sink: where tainted data becomes dangerous.
#[derive(Debug, Clone)]
struct TaintSink {
    /// Function or method name pattern.
    pattern: &'static str,
    /// Language this sink applies to.
    language: Language,
    /// Which SAST rule this sink maps to.
    rule_id: &'static str,
    /// Description for diagnostics.
    description: &'static str,
}

/// Known taint sources per language.
const SOURCES: &[TaintSource] = &[
    // Go sources
    TaintSource {
        pattern: "r.URL",
        language: Language::Go,
        description: "HTTP request URL query",
    },
    TaintSource {
        pattern: "r.Body",
        language: Language::Go,
        description: "HTTP request body",
    },
    TaintSource {
        pattern: "r.FormValue",
        language: Language::Go,
        description: "HTTP form value",
    },
    TaintSource {
        pattern: "r.Header",
        language: Language::Go,
        description: "HTTP request header",
    },
    TaintSource {
        pattern: "r.PostForm",
        language: Language::Go,
        description: "HTTP POST form data",
    },
    TaintSource {
        pattern: "Request",
        language: Language::Go,
        description: "HTTP request object",
    },
    TaintSource {
        pattern: "Query",
        language: Language::Go,
        description: "URL query parameters",
    },
    // Python sources
    TaintSource {
        pattern: "request.args",
        language: Language::Python,
        description: "Flask request args",
    },
    TaintSource {
        pattern: "request.form",
        language: Language::Python,
        description: "Flask request form data",
    },
    TaintSource {
        pattern: "request.data",
        language: Language::Python,
        description: "Flask request body",
    },
    TaintSource {
        pattern: "request.json",
        language: Language::Python,
        description: "Flask request JSON body",
    },
    TaintSource {
        pattern: "request.headers",
        language: Language::Python,
        description: "HTTP request headers",
    },
    TaintSource {
        pattern: "request.GET",
        language: Language::Python,
        description: "Django GET parameters",
    },
    TaintSource {
        pattern: "request.POST",
        language: Language::Python,
        description: "Django POST parameters",
    },
    TaintSource {
        pattern: "input(",
        language: Language::Python,
        description: "User input via stdin",
    },
    TaintSource {
        pattern: "sys.argv",
        language: Language::Python,
        description: "Command-line arguments",
    },
];

/// Known taint sinks per language and rule.
const SINKS: &[TaintSink] = &[
    // SQL injection sinks
    TaintSink {
        pattern: "db.Query",
        language: Language::Go,
        rule_id: "sql-injection",
        description: "SQL query execution",
    },
    TaintSink {
        pattern: "db.Exec",
        language: Language::Go,
        rule_id: "sql-injection",
        description: "SQL statement execution",
    },
    TaintSink {
        pattern: "db.QueryRow",
        language: Language::Go,
        rule_id: "sql-injection",
        description: "SQL query row execution",
    },
    TaintSink {
        pattern: "cursor.execute",
        language: Language::Python,
        rule_id: "sql-injection",
        description: "SQL cursor execution",
    },
    TaintSink {
        pattern: "execute(",
        language: Language::Python,
        rule_id: "sql-injection",
        description: "SQL execution",
    },
    TaintSink {
        pattern: "raw(",
        language: Language::Python,
        rule_id: "sql-injection",
        description: "Django raw SQL query",
    },
    // Command injection sinks
    TaintSink {
        pattern: "exec.Command",
        language: Language::Go,
        rule_id: "command-injection",
        description: "OS command execution",
    },
    TaintSink {
        pattern: "os.system",
        language: Language::Python,
        rule_id: "command-injection",
        description: "OS system command",
    },
    TaintSink {
        pattern: "subprocess.call",
        language: Language::Python,
        rule_id: "command-injection",
        description: "Subprocess call",
    },
    TaintSink {
        pattern: "subprocess.run",
        language: Language::Python,
        rule_id: "command-injection",
        description: "Subprocess run",
    },
    TaintSink {
        pattern: "subprocess.Popen",
        language: Language::Python,
        rule_id: "command-injection",
        description: "Subprocess Popen",
    },
    // XSS sinks
    TaintSink {
        pattern: "fmt.Fprintf",
        language: Language::Go,
        rule_id: "xss",
        description: "Direct write to HTTP response",
    },
    TaintSink {
        pattern: "w.Write",
        language: Language::Go,
        rule_id: "xss",
        description: "Direct write to response writer",
    },
    TaintSink {
        pattern: "render_template_string",
        language: Language::Python,
        rule_id: "xss",
        description: "Template string rendering",
    },
    TaintSink {
        pattern: "Markup(",
        language: Language::Python,
        rule_id: "xss",
        description: "Unsafe HTML markup",
    },
    // SSRF sinks
    TaintSink {
        pattern: "http.Get",
        language: Language::Go,
        rule_id: "ssrf",
        description: "HTTP GET with user-controlled URL",
    },
    TaintSink {
        pattern: "http.Post",
        language: Language::Go,
        rule_id: "ssrf",
        description: "HTTP POST with user-controlled URL",
    },
    TaintSink {
        pattern: "requests.get",
        language: Language::Python,
        rule_id: "ssrf",
        description: "HTTP GET with user-controlled URL",
    },
    TaintSink {
        pattern: "requests.post",
        language: Language::Python,
        rule_id: "ssrf",
        description: "HTTP POST with user-controlled URL",
    },
    TaintSink {
        pattern: "urllib.request.urlopen",
        language: Language::Python,
        rule_id: "ssrf",
        description: "URL open with user-controlled URL",
    },
    // Path traversal sinks
    TaintSink {
        pattern: "os.Open",
        language: Language::Go,
        rule_id: "path-traversal",
        description: "File open with user-controlled path",
    },
    TaintSink {
        pattern: "os.ReadFile",
        language: Language::Go,
        rule_id: "path-traversal",
        description: "File read with user-controlled path",
    },
    TaintSink {
        pattern: "ioutil.ReadFile",
        language: Language::Go,
        rule_id: "path-traversal",
        description: "File read with user-controlled path",
    },
    TaintSink {
        pattern: "open(",
        language: Language::Python,
        rule_id: "path-traversal",
        description: "File open with user-controlled path",
    },
    TaintSink {
        pattern: "os.path.join",
        language: Language::Python,
        rule_id: "path-traversal",
        description: "Path join with user-controlled component",
    },
    // Unsafe deserialization sinks
    TaintSink {
        pattern: "json.Unmarshal",
        language: Language::Go,
        rule_id: "unsafe-deserialization",
        description: "JSON deserialization of untrusted data",
    },
    TaintSink {
        pattern: "yaml.Unmarshal",
        language: Language::Go,
        rule_id: "unsafe-deserialization",
        description: "YAML deserialization of untrusted data",
    },
    TaintSink {
        pattern: "pickle.loads",
        language: Language::Python,
        rule_id: "unsafe-deserialization",
        description: "Pickle deserialization of untrusted data",
    },
    TaintSink {
        pattern: "pickle.load",
        language: Language::Python,
        rule_id: "unsafe-deserialization",
        description: "Pickle deserialization of untrusted data",
    },
    TaintSink {
        pattern: "yaml.load",
        language: Language::Python,
        rule_id: "unsafe-deserialization",
        description: "YAML load without safe loader",
    },
    TaintSink {
        pattern: "marshal.loads",
        language: Language::Python,
        rule_id: "unsafe-deserialization",
        description: "Marshal deserialization of untrusted data",
    },
];

/// Perform intraprocedural taint analysis on a single file.
pub fn analyze_file(file: &FileInfo) -> Vec<Finding> {
    let lang = detect_language(&file.path);
    let lang = match lang {
        Some(l) => l,
        None => return vec![],
    };

    let tree = match parser::parse(&file.content, lang) {
        Ok(t) => t,
        Err(_) => return vec![],
    };

    let source_text = String::from_utf8_lossy(&file.content);
    let lines: Vec<&str> = source_text.lines().collect();

    let mut findings = Vec::new();

    // Extract function bodies and analyze each one for taint flow.
    let root = tree.root_node();
    analyze_node_for_taint(root, &lines, lang, &file.path, &mut findings);

    findings
}

/// Recursively walk the AST looking for function bodies that contain
/// both taint sources and sinks.
fn analyze_node_for_taint(
    node: Node<'_>,
    lines: &[&str],
    lang: Language,
    file_path: &str,
    findings: &mut Vec<Finding>,
) {
    let kind = node.kind();

    // Identify function bodies.
    let is_function = matches!(
        kind,
        "function_declaration"
            | "method_declaration"
            | "function_definition"
            | "func_literal"
            | "lambda"
    );

    if is_function {
        analyze_function_taint(node, lines, lang, file_path, findings);
    }

    // Recurse into children.
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i as u32) {
            analyze_node_for_taint(child, lines, lang, file_path, findings);
        }
    }
}

/// Analyze a single function for taint propagation from sources to sinks.
fn analyze_function_taint(
    func_node: Node<'_>,
    lines: &[&str],
    lang: Language,
    file_path: &str,
    findings: &mut Vec<Finding>,
) {
    let start = func_node.start_position().row;
    let end = func_node.end_position().row;

    // Collect the function text lines.
    let func_lines: Vec<&str> = lines
        .iter()
        .skip(start)
        .take(end - start + 1)
        .copied()
        .collect();
    // Check for taint sources in this function.
    let sources_for_lang: Vec<&TaintSource> =
        SOURCES.iter().filter(|s| s.language == lang).collect();
    let sinks_for_lang: Vec<&TaintSink> = SINKS.iter().filter(|s| s.language == lang).collect();

    // Track tainted variables: variable name -> source description.
    let mut tainted_vars: HashMap<String, &str> = HashMap::new();

    // First pass: identify tainted variables via assignment from sources.
    for (line_offset, line) in func_lines.iter().enumerate() {
        let trimmed = line.trim();
        for source in &sources_for_lang {
            if trimmed.contains(source.pattern) {
                // Extract variable names from assignments.
                let var_names = extract_assigned_vars(trimmed, lang);
                for var in var_names {
                    tainted_vars.insert(var, source.description);
                }
                // The whole line is a potential source context.
                if var_names_from_line(trimmed, lang).is_empty() {
                    // If we can't extract a var, mark any function parameter
                    // that matches as tainted.
                    mark_source_params(
                        trimmed,
                        source.pattern,
                        &mut tainted_vars,
                        source.description,
                    );
                }
            }
        }

        // Propagate taint through simple assignments.
        propagate_taint(trimmed, lang, &mut tainted_vars, line_offset);
    }

    // Also check function parameters for taint sources (e.g., http.Request param).
    check_parameter_taint(func_node, lines, lang, &mut tainted_vars);

    // Second pass: check if tainted data reaches sinks.
    for (line_offset, line) in func_lines.iter().enumerate() {
        let trimmed = line.trim();
        for sink in &sinks_for_lang {
            if trimmed.contains(sink.pattern) {
                // Check if any tainted variable is used in this sink call.
                let (is_tainted, source_desc) =
                    check_taint_reaches_sink(trimmed, &tainted_vars, lang);
                if is_tainted {
                    let abs_line = (start + line_offset + 1) as u32;
                    findings.push(Finding {
                        rule_id: sink.rule_id.to_owned(),
                        message: format!(
                            "tainted data from {} flows to {} without sanitization",
                            source_desc, sink.description
                        ),
                        severity: Severity::Error,
                        location: Location {
                            file: file_path.to_owned(),
                            start_line: abs_line,
                            end_line: abs_line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: compute_taint_confidence(trimmed, &tainted_vars),
                        actions: vec![Action {
                            description: format!(
                                "Sanitize or parameterize data before passing to {}",
                                sink.description
                            ),
                            auto_fixable: false,
                            edits: vec![],
                        }],
                        metadata: {
                            let mut m = HashMap::new();
                            m.insert("sink".to_owned(), sink.pattern.to_owned());
                            m.insert("source".to_owned(), source_desc.to_owned());
                            m
                        },
                    });
                }
            }
        }
    }
}

/// Extract variable names from an assignment statement.
fn extract_assigned_vars(line: &str, lang: Language) -> Vec<String> {
    let mut vars = Vec::new();
    match lang {
        Language::Go => {
            // Go: `x := expr`, `x, y := expr`, `x = expr`
            if let Some(pos) = line.find(":=") {
                let lhs = line[..pos].trim();
                for v in lhs.split(',') {
                    let v = v.trim();
                    if !v.is_empty() && is_identifier(v) {
                        vars.push(v.to_owned());
                    }
                }
            } else if let Some(pos) = line.find('=') {
                // Make sure it's not ==, !=, <=, >=
                if pos > 0 {
                    let before = line.as_bytes()[pos - 1];
                    if before != b'!' && before != b'<' && before != b'>' && before != b'=' {
                        let lhs = line[..pos].trim();
                        for v in lhs.split(',') {
                            let v = v.trim();
                            if !v.is_empty() && is_identifier(v) {
                                vars.push(v.to_owned());
                            }
                        }
                    }
                }
            }
        }
        Language::Python => {
            // Python: `x = expr`
            if let Some(pos) = line.find('=') {
                if pos > 0 && pos + 1 < line.len() {
                    let before = line.as_bytes()[pos - 1];
                    let after = line.as_bytes()[pos + 1];
                    if before != b'!'
                        && before != b'<'
                        && before != b'>'
                        && before != b'='
                        && after != b'='
                    {
                        let lhs = line[..pos].trim();
                        for v in lhs.split(',') {
                            let v = v.trim();
                            if !v.is_empty() && is_identifier(v) {
                                vars.push(v.to_owned());
                            }
                        }
                    }
                }
            }
        }
    }
    vars
}

/// Extract variable names mentioned on a line (simple identifier extraction).
fn var_names_from_line(line: &str, _lang: Language) -> Vec<String> {
    extract_assigned_vars(line, _lang)
}

/// Mark function parameters as tainted if the source pattern appears in them.
fn mark_source_params(
    _line: &str,
    _pattern: &str,
    _tainted: &mut HashMap<String, &str>,
    _desc: &str,
) {
    // This is a best-effort heuristic; the main parameter taint is handled
    // by check_parameter_taint which inspects AST parameters.
}

/// Propagate taint through simple assignments: if RHS uses a tainted var,
/// LHS becomes tainted.
fn propagate_taint(
    line: &str,
    lang: Language,
    tainted: &mut HashMap<String, &str>,
    _line_offset: usize,
) {
    let assigned = extract_assigned_vars(line, lang);
    if assigned.is_empty() {
        return;
    }

    // Check if RHS mentions any tainted variable.
    let eq_pos = match lang {
        Language::Go => line.find(":=").map(|p| p + 2).or_else(|| {
            line.find('=').and_then(|p| {
                if p > 0 {
                    let before = line.as_bytes()[p - 1];
                    if before != b'!' && before != b'<' && before != b'>' && before != b'=' {
                        Some(p + 1)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }),
        Language::Python => line.find('=').and_then(|p| {
            if p > 0 && p + 1 < line.len() {
                let before = line.as_bytes()[p - 1];
                let after = line.as_bytes()[p + 1];
                if before != b'!'
                    && before != b'<'
                    && before != b'>'
                    && before != b'='
                    && after != b'='
                {
                    Some(p + 1)
                } else {
                    None
                }
            } else {
                None
            }
        }),
    };

    if let Some(rhs_start) = eq_pos {
        let rhs = &line[rhs_start..];
        // Collect sources first to avoid borrow conflict.
        let source_desc: Option<&str> = {
            let mut found = None;
            for (var, desc) in tainted.iter() {
                if rhs.contains(var.as_str()) {
                    found = Some(*desc);
                    break;
                }
            }
            found
        };
        if let Some(desc) = source_desc {
            for var in &assigned {
                tainted.insert(var.clone(), desc);
            }
        }
    }
}

/// Check function parameters for common taint patterns (e.g., *http.Request).
fn check_parameter_taint(
    func_node: Node<'_>,
    lines: &[&str],
    lang: Language,
    tainted: &mut HashMap<String, &str>,
) {
    let start = func_node.start_position().row;
    let end = func_node.end_position().row.min(start + 5); // Only check first few lines.
    let header: String = lines
        .iter()
        .skip(start)
        .take(end - start + 1)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    match lang {
        Language::Go => {
            // Look for *http.Request parameter.
            if header.contains("http.Request") {
                // Extract the parameter name (typically w, r pattern).
                // Look for patterns like `r *http.Request` or `req *http.Request`.
                for param_pattern in [
                    "r *http.Request",
                    "req *http.Request",
                    "request *http.Request",
                ] {
                    if header.contains(param_pattern) {
                        let name = param_pattern.split_whitespace().next().unwrap_or("r");
                        tainted.insert(name.to_owned(), "HTTP request parameter");
                    }
                }
                // Generic fallback.
                if !tainted.values().any(|v| *v == "HTTP request parameter") {
                    tainted.insert("r".to_owned(), "HTTP request parameter");
                }
            }
        }
        Language::Python => {
            // Flask/Django views often have `request` as a global or parameter.
            if header.contains("request") {
                tainted.insert("request".to_owned(), "HTTP request object");
            }
        }
    }
}

/// Check if a character is a valid identifier character (alphanumeric or underscore).
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Check if `var` appears as a whole identifier in `line` (not as a substring
/// of another identifier or function name).
fn contains_identifier(line: &str, var: &str) -> bool {
    let var_bytes = var.as_bytes();
    let line_bytes = line.as_bytes();
    if var_bytes.len() > line_bytes.len() {
        return false;
    }
    let mut start = 0;
    while let Some(pos) = line[start..].find(var) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !is_ident_char(line.as_bytes()[abs_pos - 1] as char);
        let after_pos = abs_pos + var.len();
        let after_ok =
            after_pos >= line.len() || !is_ident_char(line.as_bytes()[after_pos] as char);
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// Check if any tainted variable is used in the sink call line.
/// Returns (is_tainted, source_description).
fn check_taint_reaches_sink(
    line: &str,
    tainted: &HashMap<String, &str>,
    _lang: Language,
) -> (bool, String) {
    for (var, desc) in tainted {
        if contains_identifier(line, var) {
            return (true, desc.to_string());
        }
    }
    (false, String::new())
}

/// Compute confidence based on how directly the taint flows.
fn compute_taint_confidence(line: &str, tainted: &HashMap<String, &str>) -> f32 {
    // If a tainted variable appears directly in the sink call arguments,
    // higher confidence. If it appears via string concatenation/formatting,
    // slightly lower.
    let has_direct_ref = tainted.keys().any(|v| contains_identifier(line, v));
    let has_concat = line.contains('+') || line.contains("fmt.Sprintf") || line.contains("format(");
    let has_fstring = line.contains("f\"") || line.contains("f'");

    if has_direct_ref && (has_concat || has_fstring) {
        0.9 // String interpolation with tainted var -- high confidence
    } else if has_direct_ref {
        0.85 // Direct reference in sink call
    } else {
        0.7 // Indirect or uncertain
    }
}

/// Check if a string is a valid identifier.
fn is_identifier(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

fn detect_language(path: &str) -> Option<Language> {
    if path.ends_with(".go") {
        Some(Language::Go)
    } else if path.ends_with(".py") {
        Some(Language::Python)
    } else {
        None
    }
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

    // --- is_identifier tests ---

    #[test]
    fn test_is_identifier() {
        let cases = vec![
            ("foo", true),
            ("_bar", true),
            ("x1", true),
            ("123", false),
            ("", false),
            ("a.b", true),
            ("hello_world", true),
        ];
        for (input, expected) in cases {
            assert_eq!(
                is_identifier(input),
                expected,
                "is_identifier({input:?}) should be {expected}"
            );
        }
    }

    // --- extract_assigned_vars tests ---

    #[test]
    fn test_extract_assigned_vars_go() {
        let cases = vec![
            ("x := r.FormValue(\"name\")", vec!["x"]),
            ("a, b := f()", vec!["a", "b"]),
            ("y = something", vec!["y"]),
            ("if x == 1 {", Vec::<&str>::new()),
            ("x != 1", Vec::<&str>::new()),
        ];
        for (line, expected) in cases {
            let result = extract_assigned_vars(line, Language::Go);
            assert_eq!(
                result,
                expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "extract_assigned_vars Go: {line:?}"
            );
        }
    }

    #[test]
    fn test_extract_assigned_vars_python() {
        let cases = vec![
            ("x = request.args.get('name')", vec!["x"]),
            ("y = 42", vec!["y"]),
            ("if x == 1:", Vec::<&str>::new()),
        ];
        for (line, expected) in cases {
            let result = extract_assigned_vars(line, Language::Python);
            assert_eq!(
                result,
                expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "extract_assigned_vars Python: {line:?}"
            );
        }
    }

    // --- detect_language tests ---

    #[test]
    fn test_detect_language() {
        let cases = vec![
            ("handler.go", Some(Language::Go)),
            ("app.py", Some(Language::Python)),
            ("main.rs", None),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_language(path), expected, "detect_language({path:?})");
        }
    }

    // --- Go taint flow tests ---

    #[test]
    fn test_go_sql_injection() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    db.Query(query)
}
"#,
        );
        let findings = analyze_file(&file);
        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "sql-injection")
            .collect();
        assert!(
            !sql_findings.is_empty(),
            "should detect SQL injection in Go handler"
        );
    }

    #[test]
    fn test_go_command_injection() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command(cmd)
}
"#,
        );
        let findings = analyze_file(&file);
        let cmd_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "command-injection")
            .collect();
        assert!(
            !cmd_findings.is_empty(),
            "should detect command injection in Go handler"
        );
    }

    #[test]
    fn test_go_xss() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
"#,
        );
        let findings = analyze_file(&file);
        let xss_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == "xss").collect();
        assert!(!xss_findings.is_empty(), "should detect XSS in Go handler");
    }

    #[test]
    fn test_go_ssrf() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    url := r.FormValue("url")
    http.Get(url)
}
"#,
        );
        let findings = analyze_file(&file);
        let ssrf_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == "ssrf").collect();
        assert!(
            !ssrf_findings.is_empty(),
            "should detect SSRF in Go handler"
        );
    }

    #[test]
    fn test_go_path_traversal() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "net/http"
    "os"
)

func handler(w http.ResponseWriter, r *http.Request) {
    path := r.FormValue("file")
    os.Open(path)
}
"#,
        );
        let findings = analyze_file(&file);
        let pt_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "path-traversal")
            .collect();
        assert!(
            !pt_findings.is_empty(),
            "should detect path traversal in Go handler"
        );
    }

    // --- Python taint flow tests ---

    #[test]
    fn test_python_sql_injection() {
        let file = make_file(
            "app.py",
            r#"def search(request):
    name = request.args.get('name')
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
"#,
        );
        let findings = analyze_file(&file);
        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "sql-injection")
            .collect();
        assert!(
            !sql_findings.is_empty(),
            "should detect SQL injection in Python"
        );
    }

    #[test]
    fn test_python_command_injection() {
        let file = make_file(
            "app.py",
            r#"def run_cmd(request):
    cmd = request.args.get('cmd')
    os.system(cmd)
"#,
        );
        let findings = analyze_file(&file);
        let cmd_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "command-injection")
            .collect();
        assert!(
            !cmd_findings.is_empty(),
            "should detect command injection in Python"
        );
    }

    #[test]
    fn test_python_unsafe_deserialization() {
        let file = make_file(
            "app.py",
            r#"import pickle

def load_data(request):
    data = request.data
    obj = pickle.loads(data)
"#,
        );
        let findings = analyze_file(&file);
        let deser_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unsafe-deserialization")
            .collect();
        assert!(
            !deser_findings.is_empty(),
            "should detect unsafe deserialization in Python"
        );
    }

    #[test]
    fn test_python_path_traversal() {
        let file = make_file(
            "app.py",
            r#"def read_file(request):
    filename = request.args.get('file')
    f = open(filename)
"#,
        );
        let findings = analyze_file(&file);
        let pt_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "path-traversal")
            .collect();
        assert!(
            !pt_findings.is_empty(),
            "should detect path traversal in Python"
        );
    }

    // --- Safe code (no findings) ---

    #[test]
    fn test_safe_go_parameterized_query() {
        let file = make_file(
            "handler.go",
            r#"package main

func handler() {
    name := "hardcoded"
    db.Query("SELECT * FROM users WHERE id = ?", name)
}
"#,
        );
        let findings = analyze_file(&file);
        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "sql-injection")
            .collect();
        assert!(
            sql_findings.is_empty(),
            "parameterized query should not flag as SQL injection"
        );
    }

    #[test]
    fn test_non_source_file_skipped() {
        let file = make_file("main.rs", "fn main() {}");
        let findings = analyze_file(&file);
        assert!(findings.is_empty(), "non Go/Python files should be skipped");
    }

    // --- Confidence scoring ---

    #[test]
    fn test_compute_taint_confidence() {
        let mut tainted = HashMap::new();
        tainted.insert("name".to_owned(), "HTTP request");

        // Direct reference with concatenation.
        assert!(
            compute_taint_confidence("query + name", &tainted) > 0.85,
            "concat with tainted var should have high confidence"
        );

        // Direct reference without concat.
        assert!(
            compute_taint_confidence("db.Query(name)", &tainted) > 0.8,
            "direct reference should have moderate-high confidence"
        );
    }

    // --- Taint propagation ---

    #[test]
    fn test_propagate_taint() {
        let mut tainted: HashMap<String, &str> = HashMap::new();
        tainted.insert("x".to_owned(), "HTTP input");

        propagate_taint("y := x + \"suffix\"", Language::Go, &mut tainted, 0);
        assert!(
            tainted.contains_key("y"),
            "y should become tainted through assignment from x"
        );
    }

    #[test]
    fn test_propagate_taint_python() {
        let mut tainted: HashMap<String, &str> = HashMap::new();
        tainted.insert("user_input".to_owned(), "request args");

        propagate_taint(
            "query = \"SELECT * FROM t WHERE n='\" + user_input",
            Language::Python,
            &mut tainted,
            0,
        );
        assert!(
            tainted.contains_key("query"),
            "query should become tainted through assignment from user_input"
        );
    }

    #[test]
    fn test_contains_identifier_word_boundary() {
        assert!(contains_identifier("db.Query(r.FormValue(\"id\"))", "r"));
        assert!(!contains_identifier("fmt.Fprintf(w, \"ok\")", "r"));
        assert!(!contains_identifier(
            "exec.Command(\"echo\", \"hello\")",
            "r"
        ));
        assert!(contains_identifier(
            "exec.Command(r.FormValue(\"cmd\"))",
            "r"
        ));
        assert!(contains_identifier("os.Open(req.URL.Path)", "req"));
        assert!(!contains_identifier("require(\"something\")", "req"));
        assert!(contains_identifier(
            "cursor.execute(request.args.get('q'))",
            "request"
        ));
        assert!(!contains_identifier("unrequested = True", "request"));
    }

    #[test]
    fn test_clean_go_handler_no_false_positive() {
        let file = make_file(
            "handler.go",
            r#"package main

import (
    "fmt"
    "net/http"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "ok")
}
"#,
        );
        let findings = analyze_file(&file);
        assert!(
            findings.is_empty(),
            "clean handler with sinks but no taint flow should produce no findings, got: {findings:?}"
        );
    }

    #[test]
    fn test_clean_go_exec_no_false_positive() {
        let file = make_file(
            "safe_exec.go",
            r#"package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func safeExec(w http.ResponseWriter, r *http.Request) {
    cmd := exec.Command("echo", "hello")
    output, _ := cmd.Output()
    fmt.Fprintf(w, "%s", output)
}
"#,
        );
        let findings = analyze_file(&file);
        assert!(
            findings.is_empty(),
            "exec with hardcoded args should not be flagged, got: {findings:?}"
        );
    }
}
