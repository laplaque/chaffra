//! Converters from various tool configs to `.chaffra.toml` format.

use crate::{MigrateError, MigrationResult};

/// Convert a knip configuration (JSON) to `.chaffra.toml`.
///
/// Knip detects dead code in JS/TS projects: unused files, exports, dependencies.
/// Maps to chaffra's dead-code module with ignore patterns.
pub fn convert_knip(content: &str) -> Result<MigrationResult, MigrateError> {
    let parsed: serde_json::Value =
        serde_json::from_str(content).map_err(|e| MigrateError::ParseError(e.to_string()))?;

    let mut toml_parts = Vec::new();
    let mut notes = Vec::new();

    toml_parts.push("# Migrated from knip configuration".to_owned());
    toml_parts.push("# Review and adjust settings as needed".to_owned());
    toml_parts.push(String::new());

    // Map entry patterns
    let mut entries = Vec::new();
    if let Some(entry) = parsed.get("entry") {
        if let Some(arr) = entry.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    entries.push(format!("\"{}\"", s));
                }
            }
        }
    }

    // Map ignore patterns
    let mut ignores = Vec::new();
    if let Some(ignore) = parsed.get("ignore") {
        if let Some(arr) = ignore.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    ignores.push(format!("\"{}\"", s));
                }
            }
        }
    }
    if let Some(ignore_deps) = parsed.get("ignoreDependencies") {
        notes.push(
            "ignoreDependencies: not directly mapped; add dependency patterns to [project].ignore"
                .to_owned(),
        );
        if let Some(arr) = ignore_deps.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    ignores.push(format!("\"{}\"", s));
                }
            }
        }
    }

    toml_parts.push("[project]".to_owned());
    if !entries.is_empty() {
        toml_parts.push(format!("entry = [{}]", entries.join(", ")));
    }
    if !ignores.is_empty() {
        toml_parts.push(format!("ignore = [{}]", ignores.join(", ")));
    }

    toml_parts.push(String::new());

    // Map rule overrides
    toml_parts.push("[rules]".to_owned());
    toml_parts.push("unused-function = \"error\"".to_owned());
    toml_parts.push("unused-import = \"error\"".to_owned());
    toml_parts.push("unused-file = \"warn\"".to_owned());

    // Handle workspace-specific config
    if parsed.get("workspaces").is_some() {
        notes.push(
            "workspaces: knip workspace configs need manual review for chaffra monorepo setup"
                .to_owned(),
        );
    }

    // Handle plugins
    if let Some(plugins) = parsed.as_object() {
        for key in plugins.keys() {
            if ![
                "entry",
                "ignore",
                "ignoreDependencies",
                "workspaces",
                "project",
            ]
            .contains(&key.as_str())
            {
                notes.push(format!(
                    "{key}: knip plugin not directly mapped; review manually"
                ));
            }
        }
    }

    Ok(MigrationResult {
        toml_content: toml_parts.join("\n"),
        notes,
    })
}

/// Convert a jscpd configuration (JSON) to `.chaffra.toml`.
///
/// jscpd detects code duplication. Maps to chaffra's duplication module.
pub fn convert_jscpd(content: &str) -> Result<MigrationResult, MigrateError> {
    let parsed: serde_json::Value =
        serde_json::from_str(content).map_err(|e| MigrateError::ParseError(e.to_string()))?;

    let mut toml_parts = Vec::new();
    let mut notes = Vec::new();

    toml_parts.push("# Migrated from jscpd configuration".to_owned());
    toml_parts.push("# Review and adjust settings as needed".to_owned());
    toml_parts.push(String::new());

    // Map ignore patterns
    let mut ignores = Vec::new();
    if let Some(ignore) = parsed.get("ignore") {
        if let Some(arr) = ignore.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    ignores.push(format!("\"{}\"", s));
                }
            }
        }
    }

    toml_parts.push("[project]".to_owned());
    if !ignores.is_empty() {
        toml_parts.push(format!("ignore = [{}]", ignores.join(", ")));
    }
    toml_parts.push(String::new());

    // Map duplication settings
    toml_parts.push("[duplication]".to_owned());

    if let Some(min_lines) = parsed.get("minLines").and_then(|v| v.as_u64()) {
        // jscpd uses lines, chaffra uses tokens; approximate conversion
        let min_tokens = min_lines * 10; // rough approximation
        toml_parts.push(format!("min-tokens = {min_tokens}"));
        notes.push(format!(
            "minLines={min_lines} converted to min-tokens={min_tokens} (approximate; 1 line ~ 10 tokens)"
        ));
    }

    if let Some(min_tokens) = parsed.get("minTokens").and_then(|v| v.as_u64()) {
        toml_parts.push(format!("min-tokens = {min_tokens}"));
    }

    if let Some(threshold) = parsed.get("threshold").and_then(|v| v.as_f64()) {
        notes.push(format!(
            "threshold={threshold}: jscpd percentage threshold not directly mapped; use duplication.mode instead"
        ));
    }

    // Map mode based on settings
    let mode = if parsed.get("formatsExts").is_some() {
        "semantic"
    } else {
        "mild"
    };
    toml_parts.push(format!("mode = \"{mode}\""));

    if let Some(reporters) = parsed.get("reporters") {
        notes.push(format!(
            "reporters: {:?} not mapped; use chaffra --format flag",
            reporters
        ));
    }

    Ok(MigrationResult {
        toml_content: toml_parts.join("\n"),
        notes,
    })
}

/// Convert a golangci-lint YAML config to `.chaffra.toml`.
///
/// golangci-lint is a Go linter aggregator. Maps linter enables/disables
/// to chaffra rule severity overrides and module config.
pub fn convert_golangci_lint(content: &str) -> Result<MigrationResult, MigrateError> {
    // Simple YAML-like parsing without a YAML dependency.
    // Handles the most common golangci-lint patterns.
    let mut toml_parts = Vec::new();
    let mut notes = Vec::new();

    toml_parts.push("# Migrated from golangci-lint configuration".to_owned());
    toml_parts.push("# Review and adjust settings as needed".to_owned());
    toml_parts.push(String::new());

    toml_parts.push("[project]".to_owned());

    // Extract skip-dirs patterns
    let mut ignores = Vec::new();
    let mut in_skip_dirs = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("skip-dirs:") || trimmed.starts_with("skip-dirs-use-default:") {
            in_skip_dirs = trimmed.starts_with("skip-dirs:");
            continue;
        }
        if in_skip_dirs {
            if let Some(dir) = trimmed.strip_prefix("- ") {
                ignores.push(format!("\"{}/**\"", dir.trim()));
            } else if !trimmed.starts_with('-') && !trimmed.is_empty() {
                in_skip_dirs = false;
            }
        }
    }
    if !ignores.is_empty() {
        toml_parts.push(format!("ignore = [{}]", ignores.join(", ")));
    }

    toml_parts.push(String::new());

    // Map linter enables to rule severities
    toml_parts.push("[rules]".to_owned());

    let linter_to_rule = [
        ("deadcode", "unused-function"),
        ("unused", "unused-function"),
        ("structcheck", "unused-type"),
        ("varcheck", "unused-type"),
        ("gocyclo", "high-cyclomatic"),
        ("cyclop", "high-cyclomatic"),
        ("gocognit", "high-cognitive"),
        ("dupl", "code-duplicate"),
        ("importorder", "import-boundary"),
    ];

    let mut enabled_linters = Vec::new();
    let mut in_enable = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("enable:") {
            in_enable = true;
            continue;
        }
        if in_enable {
            if let Some(linter) = trimmed.strip_prefix("- ") {
                enabled_linters.push(linter.trim().to_owned());
            } else if !trimmed.starts_with('-') && !trimmed.is_empty() {
                in_enable = false;
            }
        }
    }

    for (linter, rule) in &linter_to_rule {
        if enabled_linters.iter().any(|l| l == linter) {
            toml_parts.push(format!("{rule} = \"error\""));
        }
    }

    // Map complexity settings
    let mut max_cyclomatic = None;
    let mut max_cognitive = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("max-complexity:") {
            if let Ok(val) = rest.trim().parse::<u32>() {
                max_cyclomatic = Some(val);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("min-complexity:") {
            if let Ok(val) = rest.trim().parse::<u32>() {
                max_cyclomatic = Some(val);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("max-cognitive-complexity:") {
            if let Ok(val) = rest.trim().parse::<u32>() {
                max_cognitive = Some(val);
            }
        }
    }

    if max_cyclomatic.is_some() || max_cognitive.is_some() {
        toml_parts.push(String::new());
        toml_parts.push("[health]".to_owned());
        if let Some(val) = max_cyclomatic {
            toml_parts.push(format!("max-cyclomatic = {val}"));
        }
        if let Some(val) = max_cognitive {
            toml_parts.push(format!("max-cognitive = {val}"));
        }
    }

    // Note unmapped linters
    let mapped_linters: Vec<&str> = linter_to_rule.iter().map(|(l, _)| *l).collect();
    for linter in &enabled_linters {
        if !mapped_linters.contains(&linter.as_str()) {
            notes.push(format!(
                "{linter}: no direct chaffra equivalent; review manually"
            ));
        }
    }

    toml_parts.push(String::new());
    toml_parts.push("[framework]".to_owned());
    toml_parts.push("go = []".to_owned());

    Ok(MigrationResult {
        toml_content: toml_parts.join("\n"),
        notes,
    })
}

/// Convert a ruff configuration (TOML) to `.chaffra.toml`.
///
/// Ruff is a fast Python linter. Maps select/ignore rules to chaffra
/// rule severities and configuration.
pub fn convert_ruff(content: &str) -> Result<MigrationResult, MigrateError> {
    let parsed: toml::Value =
        toml::from_str(content).map_err(|e| MigrateError::ParseError(e.to_string()))?;

    let mut toml_parts = Vec::new();
    let mut notes = Vec::new();

    toml_parts.push("# Migrated from ruff configuration".to_owned());
    toml_parts.push("# Review and adjust settings as needed".to_owned());
    toml_parts.push(String::new());

    // Extract exclude patterns
    let mut ignores = Vec::new();

    // Try both ruff.toml format and pyproject.toml format
    let ruff_section = parsed
        .get("tool")
        .and_then(|t| t.get("ruff"))
        .unwrap_or(&parsed);

    if let Some(exclude) = ruff_section.get("exclude").and_then(|e| e.as_array()) {
        for v in exclude {
            if let Some(s) = v.as_str() {
                ignores.push(format!("\"{}\"", s));
            }
        }
    }

    toml_parts.push("[project]".to_owned());
    if !ignores.is_empty() {
        toml_parts.push(format!("ignore = [{}]", ignores.join(", ")));
    }
    toml_parts.push(String::new());

    // Map selected rules to chaffra equivalents
    toml_parts.push("[rules]".to_owned());

    let lint_section = ruff_section.get("lint").unwrap_or(ruff_section);

    if let Some(select) = lint_section.get("select").and_then(|s| s.as_array()) {
        let selected: Vec<&str> = select.iter().filter_map(|v| v.as_str()).collect();

        // F = Pyflakes (unused imports, variables)
        if selected.iter().any(|s| *s == "F" || s.starts_with("F4")) {
            toml_parts.push("unused-import = \"error\"".to_owned());
            toml_parts.push("unused-function = \"warn\"".to_owned());
        }

        // C90 = McCabe complexity
        if selected.iter().any(|s| *s == "C90" || s.starts_with("C9")) {
            toml_parts.push("high-cyclomatic = \"warn\"".to_owned());
        }

        // E = pycodestyle errors
        if selected.contains(&"E") {
            notes.push(
                "E (pycodestyle): style rules not mapped; chaffra focuses on structural analysis"
                    .to_owned(),
            );
        }

        // I = isort
        if selected.contains(&"I") {
            notes.push("I (isort): import ordering not mapped; use architecture module".to_owned());
        }
    }

    // Map line-length to a note
    if let Some(line_length) = ruff_section.get("line-length") {
        notes.push(format!(
            "line-length={}: style formatting not mapped to chaffra",
            line_length
        ));
    }

    // Map max-complexity
    if let Some(mccabe) = lint_section.get("mccabe") {
        if let Some(max_complexity) = mccabe.get("max-complexity").and_then(|v| v.as_integer()) {
            toml_parts.push(String::new());
            toml_parts.push("[health]".to_owned());
            toml_parts.push(format!("max-cyclomatic = {max_complexity}"));
        }
    }

    toml_parts.push(String::new());
    toml_parts.push("[framework]".to_owned());
    toml_parts.push("python = []".to_owned());

    Ok(MigrationResult {
        toml_content: toml_parts.join("\n"),
        notes,
    })
}

/// Convert an import-linter configuration to `.chaffra.toml`.
///
/// import-linter enforces Python import boundaries via contracts.
/// Maps to chaffra's architecture boundary configuration.
pub fn convert_import_linter(content: &str) -> Result<MigrationResult, MigrateError> {
    let mut toml_parts = Vec::new();
    let mut notes = Vec::new();

    toml_parts.push("# Migrated from import-linter configuration".to_owned());
    toml_parts.push("# Review and adjust settings as needed".to_owned());
    toml_parts.push(String::new());

    toml_parts.push("[project]".to_owned());
    toml_parts.push(String::new());

    // Parse ini-like format
    let mut contracts: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_pairs: Vec<(String, String)> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Some(section) = current_section.take() {
                contracts.push((section, std::mem::take(&mut current_pairs)));
            }
            current_section = Some(trimmed[1..trimmed.len() - 1].to_owned());
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            current_pairs.push((key.trim().to_owned(), value.trim().to_owned()));
        } else if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line: append to the last key-value pair's value
            if let Some(last) = current_pairs.last_mut() {
                if !last.1.is_empty() {
                    last.1.push('\n');
                }
                last.1.push_str(trimmed);
            }
        }
    }
    if let Some(section) = current_section {
        contracts.push((section, current_pairs));
    }

    // Map contracts to boundary zones and rules
    let mut zones = Vec::new();
    let mut rules = Vec::new();

    for (section, pairs) in &contracts {
        if section.starts_with("importlinter:contract:") {
            let contract_name = section
                .strip_prefix("importlinter:contract:")
                .unwrap_or(section);

            let contract_type = pairs
                .iter()
                .find(|(k, _)| k == "type")
                .map(|(_, v)| v.as_str())
                .unwrap_or("unknown");

            match contract_type {
                "layers" => {
                    // Layers contract: defines ordered layers where each can import from below
                    if let Some((_, layers_str)) = pairs.iter().find(|(k, _)| k == "layers") {
                        let layers: Vec<&str> = layers_str
                            .split('\n')
                            .flat_map(|s| s.split('|'))
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .collect();

                        for layer in &layers {
                            zones.push(format!(
                                "{{ name = \"{layer}\", patterns = [\"{layer}/**\"] }}"
                            ));
                        }

                        // Each layer can import from layers below it
                        for (i, layer) in layers.iter().enumerate() {
                            if i + 1 < layers.len() {
                                let allowed: Vec<String> =
                                    layers[i + 1..].iter().map(|l| format!("\"{l}\"")).collect();
                                rules.push(format!(
                                    "{{ from = \"{layer}\", allow = [{}] }}",
                                    allowed.join(", ")
                                ));
                            }
                        }
                    }
                }
                "forbidden" => {
                    notes.push(format!(
                        "{contract_name}: forbidden contract mapped to deny rules"
                    ));
                    if let Some((_, source)) = pairs.iter().find(|(k, _)| k == "source_modules") {
                        if let Some((_, forbidden)) =
                            pairs.iter().find(|(k, _)| k == "forbidden_modules")
                        {
                            let denied: Vec<String> = forbidden
                                .split('\n')
                                .flat_map(|s| s.split('|'))
                                .map(|s| format!("\"{}\"", s.trim()))
                                .filter(|s| s != "\"\"")
                                .collect();
                            if !denied.is_empty() {
                                let src = source.trim();
                                rules.push(format!(
                                    "{{ from = \"{src}\", deny = [{}] }}",
                                    denied.join(", ")
                                ));
                            }
                        }
                    }
                }
                _ => {
                    notes.push(format!(
                        "{contract_name}: contract type '{contract_type}' not mapped"
                    ));
                }
            }
        }
    }

    toml_parts.push("[boundaries]".to_owned());
    if !zones.is_empty() {
        toml_parts.push(format!("zones = [\n  {}\n]", zones.join(",\n  ")));
    }
    if !rules.is_empty() {
        toml_parts.push(format!("rules = [\n  {}\n]", rules.join(",\n  ")));
    }

    toml_parts.push(String::new());
    toml_parts.push("[framework]".to_owned());
    toml_parts.push("python = []".to_owned());

    Ok(MigrationResult {
        toml_content: toml_parts.join("\n"),
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- knip converter tests ---

    #[test]
    fn test_convert_knip_basic() {
        let config = r#"{
            "entry": ["src/index.ts", "src/main.ts"],
            "ignore": ["**/*.test.ts", "dist/**"]
        }"#;

        let result = convert_knip(config).unwrap();
        assert!(result.toml_content.contains("[project]"));
        assert!(result.toml_content.contains("src/index.ts"));
        assert!(result.toml_content.contains("src/main.ts"));
        assert!(result.toml_content.contains("**/*.test.ts"));
        assert!(result.toml_content.contains("[rules]"));
        assert!(result.toml_content.contains("unused-function = \"error\""));
    }

    #[test]
    fn test_convert_knip_with_workspaces() {
        let config = r#"{
            "workspaces": {"packages/*": {"entry": ["src/index.ts"]}},
            "entry": ["src/index.ts"]
        }"#;

        let result = convert_knip(config).unwrap();
        assert!(result.notes.iter().any(|n| n.contains("workspaces")));
    }

    #[test]
    fn test_convert_knip_with_ignore_deps() {
        let config = r#"{
            "entry": ["index.ts"],
            "ignoreDependencies": ["lodash"]
        }"#;

        let result = convert_knip(config).unwrap();
        assert!(
            result
                .notes
                .iter()
                .any(|n| n.contains("ignoreDependencies"))
        );
    }

    #[test]
    fn test_convert_knip_invalid_json() {
        let result = convert_knip("not json");
        assert!(result.is_err());
    }

    // --- jscpd converter tests ---

    #[test]
    fn test_convert_jscpd_basic() {
        let config = r#"{
            "minTokens": 50,
            "ignore": ["node_modules/**", "dist/**"]
        }"#;

        let result = convert_jscpd(config).unwrap();
        assert!(result.toml_content.contains("[duplication]"));
        assert!(result.toml_content.contains("min-tokens = 50"));
        assert!(result.toml_content.contains("node_modules/**"));
    }

    #[test]
    fn test_convert_jscpd_with_min_lines() {
        let config = r#"{"minLines": 5}"#;

        let result = convert_jscpd(config).unwrap();
        assert!(result.toml_content.contains("min-tokens = 50"));
        assert!(result.notes.iter().any(|n| n.contains("minLines")));
    }

    #[test]
    fn test_convert_jscpd_with_threshold() {
        let config = r#"{"threshold": 10.5}"#;

        let result = convert_jscpd(config).unwrap();
        assert!(result.notes.iter().any(|n| n.contains("threshold")));
    }

    #[test]
    fn test_convert_jscpd_invalid_json() {
        let result = convert_jscpd("{bad json");
        assert!(result.is_err());
    }

    // --- golangci-lint converter tests ---

    #[test]
    fn test_convert_golangci_lint_basic() {
        let config = r#"
linters:
  enable:
    - deadcode
    - gocyclo
    - unused

linters-settings:
  gocyclo:
    max-complexity: 15
"#;

        let result = convert_golangci_lint(config).unwrap();
        assert!(result.toml_content.contains("[rules]"));
        assert!(result.toml_content.contains("unused-function = \"error\""));
        assert!(result.toml_content.contains("high-cyclomatic = \"error\""));
        assert!(result.toml_content.contains("[health]"));
        assert!(result.toml_content.contains("max-cyclomatic = 15"));
    }

    #[test]
    fn test_convert_golangci_lint_with_skip_dirs() {
        let config = r#"
run:
  skip-dirs:
    - vendor
    - generated
"#;

        let result = convert_golangci_lint(config).unwrap();
        assert!(result.toml_content.contains("vendor/**"));
        assert!(result.toml_content.contains("generated/**"));
    }

    #[test]
    fn test_convert_golangci_lint_unmapped_linters() {
        let config = r#"
linters:
  enable:
    - govet
    - errcheck
"#;

        let result = convert_golangci_lint(config).unwrap();
        assert!(result.notes.iter().any(|n| n.contains("govet")));
        assert!(result.notes.iter().any(|n| n.contains("errcheck")));
    }

    // --- ruff converter tests ---

    #[test]
    fn test_convert_ruff_basic() {
        let config = r#"
exclude = ["__pycache__", ".venv"]

[lint]
select = ["F", "C90"]

[lint.mccabe]
max-complexity = 10
"#;

        let result = convert_ruff(config).unwrap();
        assert!(result.toml_content.contains("[rules]"));
        assert!(result.toml_content.contains("unused-import = \"error\""));
        assert!(result.toml_content.contains("high-cyclomatic = \"warn\""));
        assert!(result.toml_content.contains("max-cyclomatic = 10"));
        assert!(result.toml_content.contains("__pycache__"));
    }

    #[test]
    fn test_convert_ruff_pyproject_format() {
        let config = r#"
[tool.ruff]
line-length = 88
exclude = ["migrations"]

[tool.ruff.lint]
select = ["F"]
"#;

        let result = convert_ruff(config).unwrap();
        assert!(result.toml_content.contains("unused-import"));
        assert!(result.toml_content.contains("migrations"));
        assert!(result.notes.iter().any(|n| n.contains("line-length")));
    }

    #[test]
    fn test_convert_ruff_invalid_toml() {
        let result = convert_ruff("not [valid toml");
        assert!(result.is_err());
    }

    // --- import-linter converter tests ---

    #[test]
    fn test_convert_import_linter_layers() {
        let config = r#"
[importlinter]
root_package = myapp

[importlinter:contract:main]
name = Main Contract
type = layers
layers =
    api
    service
    repository
"#;

        let result = convert_import_linter(config).unwrap();
        assert!(result.toml_content.contains("[boundaries]"));
        assert!(result.toml_content.contains("api"));
        assert!(result.toml_content.contains("service"));
        assert!(result.toml_content.contains("repository"));
    }

    #[test]
    fn test_convert_import_linter_forbidden() {
        let config = r#"
[importlinter:contract:no-django]
name = No Django in Core
type = forbidden
source_modules = myapp.core
forbidden_modules = django
"#;

        let result = convert_import_linter(config).unwrap();
        assert!(result.toml_content.contains("[boundaries]"));
        assert!(result.notes.iter().any(|n| n.contains("forbidden")));
    }

    #[test]
    fn test_convert_import_linter_empty() {
        let result = convert_import_linter("").unwrap();
        assert!(result.toml_content.contains("[boundaries]"));
    }
}
