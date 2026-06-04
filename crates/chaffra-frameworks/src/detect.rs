//! Unified framework detection dispatcher.
//!
//! Parses source files with tree-sitter and delegates to language-specific
//! detectors to find framework entry points.

use crate::go;
use crate::python;
use chaffra_core::diagnostic::Language;
use serde::{Deserialize, Serialize};

/// A detected framework entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkEntry {
    /// Framework name (e.g. "gin", "fastapi", "flask").
    pub framework: String,
    /// Kind of entry (e.g. "handler", "route", "command").
    pub kind: String,
    /// Symbol name (function or handler identifier).
    pub name: String,
    /// File path.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// Detection confidence 0.0..1.0.
    pub confidence: f32,
}

/// Detect framework entry points in a single file.
pub fn detect_framework_entries(
    source: &[u8],
    language: Language,
    file: &str,
) -> Vec<FrameworkEntry> {
    let tree = match chaffra_parse::parser::parse(source, language) {
        Ok(t) => t,
        Err(_) => return vec![],
    };

    match language {
        Language::Go => go::detect_go_frameworks(&tree, source, file),
        Language::Python => python::detect_python_frameworks(&tree, source, file),
        // Other languages: no framework detectors registered yet.
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_go_gin() {
        let source = br#"package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/hello", helloHandler)
    r.Run()
}
"#;
        let entries = detect_framework_entries(source, Language::Go, "main.go");
        assert!(!entries.is_empty(), "should detect gin handlers");
        assert!(
            entries.iter().any(|e| e.framework == "gin"),
            "should identify gin framework"
        );
    }

    #[test]
    fn test_detect_python_fastapi() {
        let source = br#"from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"msg": "hello"}
"#;
        let entries = detect_framework_entries(source, Language::Python, "app.py");
        assert!(!entries.is_empty(), "should detect FastAPI routes");
        assert!(
            entries.iter().any(|e| e.framework == "fastapi"),
            "should identify fastapi framework"
        );
    }

    #[test]
    fn test_detect_no_framework() {
        let source = b"package main\n\nfunc main() {}\n";
        let entries = detect_framework_entries(source, Language::Go, "main.go");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_detect_invalid_source() {
        // Garbage input should return empty, not panic.
        let entries = detect_framework_entries(b"{{{{", Language::Go, "bad.go");
        assert!(entries.is_empty());
    }
}
