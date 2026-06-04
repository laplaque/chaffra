//! Workspace detection for each supported ecosystem.

use crate::{Workspace, WorkspaceKind, WorkspaceMember};
use std::path::{Path, PathBuf};

/// Detect a Go workspace from `go.work` in the given root.
///
/// Parses `use` directives from the go.work file.
pub fn detect_go_work(root: &Path) -> Option<Workspace> {
    let go_work = root.join("go.work");
    let content = std::fs::read_to_string(&go_work).ok()?;

    let mut members = Vec::new();
    let mut in_use_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "use (" {
            in_use_block = true;
            continue;
        }
        if trimmed == ")" {
            in_use_block = false;
            continue;
        }

        if in_use_block {
            let path = trimmed.trim_start_matches("./");
            if !path.is_empty() && !path.starts_with("//") {
                let member_path = PathBuf::from(path);
                let name = member_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_owned());
                members.push(WorkspaceMember {
                    name,
                    path: member_path,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("use ") {
            // Single-line use directive: `use ./path`
            let path = rest.trim().trim_start_matches("./");
            if !path.is_empty() {
                let member_path = PathBuf::from(path);
                let name = member_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_owned());
                members.push(WorkspaceMember {
                    name,
                    path: member_path,
                });
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::GoWork,
        members,
    })
}

/// Detect a Rust workspace from `Cargo.toml` `[workspace]` section.
///
/// Expands glob patterns in `members` against the filesystem.
pub fn detect_rust_cargo(root: &Path) -> Option<Workspace> {
    let cargo_toml = root.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_toml).ok()?;

    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let workspace = parsed.get("workspace")?;
    let members_arr = workspace.get("members")?.as_array()?;

    let mut members = Vec::new();
    for member_val in members_arr {
        let pattern = member_val.as_str()?;
        // Try to expand globs against the filesystem
        let expanded = expand_glob(root, pattern);
        if expanded.is_empty() {
            // Keep the pattern as-is if no matches (workspace member may not exist yet)
            let member_path = PathBuf::from(pattern);
            let name = member_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| pattern.to_owned());
            members.push(WorkspaceMember {
                name,
                path: member_path,
            });
        } else {
            for path in expanded {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_string_lossy().into_owned());
                members.push(WorkspaceMember { name, path });
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::RustCargo,
        members,
    })
}

/// Detect a JS/TS workspace from `package.json` `workspaces` field.
pub fn detect_js_package_json(root: &Path) -> Option<Workspace> {
    let pkg_json = root.join("package.json");
    let content = std::fs::read_to_string(&pkg_json).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let workspaces = parsed.get("workspaces")?;

    // workspaces can be an array of strings or an object with "packages" key
    let patterns: Vec<&str> = if let Some(arr) = workspaces.as_array() {
        arr.iter().filter_map(|v| v.as_str()).collect()
    } else if let Some(obj) = workspaces.as_object() {
        obj.get("packages")
            .and_then(|p| p.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default()
    } else {
        return None;
    };

    let mut members = Vec::new();
    for pattern in patterns {
        let expanded = expand_glob(root, pattern);
        if expanded.is_empty() {
            let member_path = PathBuf::from(pattern.trim_end_matches("/*"));
            let name = member_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| pattern.to_owned());
            members.push(WorkspaceMember {
                name,
                path: member_path,
            });
        } else {
            for path in expanded {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_string_lossy().into_owned());
                members.push(WorkspaceMember { name, path });
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::JsPackageJson,
        members,
    })
}

/// Detect a pnpm workspace from `pnpm-workspace.yaml`.
///
/// Parses the YAML-like format manually (no YAML dependency) for the
/// `packages:` list.
pub fn detect_pnpm_workspace(root: &Path) -> Option<Workspace> {
    let yaml_path = root.join("pnpm-workspace.yaml");
    let content = std::fs::read_to_string(&yaml_path).ok()?;

    let mut members = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        // Another top-level key ends the packages section
        if !trimmed.is_empty() && !trimmed.starts_with('-') && !trimmed.starts_with('#') {
            in_packages = false;
        }
        if in_packages {
            if let Some(entry) = trimmed.strip_prefix("- ") {
                let pattern = entry.trim().trim_matches('\'').trim_matches('"');
                let expanded = expand_glob(root, pattern);
                if expanded.is_empty() {
                    let clean = pattern.trim_end_matches("/*").trim_end_matches("/**");
                    let member_path = PathBuf::from(clean);
                    let name = member_path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| clean.to_owned());
                    members.push(WorkspaceMember {
                        name,
                        path: member_path,
                    });
                } else {
                    for path in expanded {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.to_string_lossy().into_owned());
                        members.push(WorkspaceMember { name, path });
                    }
                }
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::PnpmWorkspace,
        members,
    })
}

/// Detect a Python workspace from `pyproject.toml` with workspace members.
///
/// Looks for `[tool.chaffra.workspaces]` or poetry workspaces.
pub fn detect_python_pyproject(root: &Path) -> Option<Workspace> {
    let pyproject = root.join("pyproject.toml");
    let content = std::fs::read_to_string(&pyproject).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;

    // Try [tool.chaffra.workspaces] first
    let members_val = parsed
        .get("tool")
        .and_then(|t| t.get("chaffra"))
        .and_then(|c| c.get("workspaces"))
        .and_then(|w| w.as_array())
        // Fall back to [tool.poetry.packages]
        .or_else(|| {
            parsed
                .get("tool")
                .and_then(|t| t.get("poetry"))
                .and_then(|p| p.get("packages"))
                .and_then(|p| p.as_array())
        });

    let patterns: Vec<&str> = members_val?
        .iter()
        .filter_map(|v| {
            v.as_str().or_else(|| {
                // Poetry packages format: {include = "pkg", from = "src"}
                v.get("include").and_then(|i| i.as_str())
            })
        })
        .collect();

    let mut members = Vec::new();
    for pattern in patterns {
        let expanded = expand_glob(root, pattern);
        if expanded.is_empty() {
            let member_path = PathBuf::from(pattern);
            let name = member_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| pattern.to_owned());
            members.push(WorkspaceMember {
                name,
                path: member_path,
            });
        } else {
            for path in expanded {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_string_lossy().into_owned());
                members.push(WorkspaceMember { name, path });
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::PythonPyproject,
        members,
    })
}

/// Detect a Java workspace from `settings.gradle` or `settings.gradle.kts`.
///
/// Parses `include` directives.
pub fn detect_java_gradle(root: &Path) -> Option<Workspace> {
    let settings_path = root.join("settings.gradle");
    let content = if settings_path.exists() {
        std::fs::read_to_string(&settings_path).ok()?
    } else {
        let kts_path = root.join("settings.gradle.kts");
        std::fs::read_to_string(&kts_path).ok()?
    };

    let mut members = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Match: include 'project-name' or include ':project-name'
        // Also: include("project-name") (Kotlin DSL)
        if let Some(rest) = trimmed
            .strip_prefix("include ")
            .or_else(|| trimmed.strip_prefix("include("))
        {
            let cleaned = rest
                .trim_end_matches(')')
                .trim()
                .trim_matches('\'')
                .trim_matches('"');

            for project in cleaned.split(',') {
                let name = project
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .trim_start_matches(':');

                if !name.is_empty() {
                    // Gradle convention: :foo:bar maps to foo/bar
                    let path_str = name.replace(':', "/");
                    members.push(WorkspaceMember {
                        name: name.to_owned(),
                        path: PathBuf::from(path_str),
                    });
                }
            }
        }
    }

    if members.is_empty() {
        return None;
    }

    Some(Workspace {
        root: root.to_path_buf(),
        kind: WorkspaceKind::JavaGradle,
        members,
    })
}

/// Expand a glob pattern relative to a root directory.
///
/// Returns relative paths for directories that match.
fn expand_glob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let full_pattern = root.join(pattern);
    let pattern_str = full_pattern.to_string_lossy();

    let mut results = Vec::new();
    if let Ok(paths) = glob::glob(&pattern_str) {
        for entry in paths.flatten() {
            if entry.is_dir() {
                if let Ok(rel) = entry.strip_prefix(root) {
                    results.push(rel.to_path_buf());
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    // --- Go workspace tests ---

    #[test]
    fn test_detect_go_work_multi_line() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("go.work"),
            "go 1.21\n\nuse (\n\t./services/auth\n\t./services/api\n\t./pkg/common\n)\n",
        )
        .unwrap();

        let ws = detect_go_work(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::GoWork);
        assert_eq!(ws.members.len(), 3);
        assert_eq!(ws.members[0].name, "auth");
        assert_eq!(ws.members[0].path, PathBuf::from("services/auth"));
        assert_eq!(ws.members[1].name, "api");
        assert_eq!(ws.members[2].name, "common");
    }

    #[test]
    fn test_detect_go_work_single_line() {
        let dir = setup_dir();
        fs::write(dir.path().join("go.work"), "go 1.21\n\nuse ./mymodule\n").unwrap();

        let ws = detect_go_work(dir.path()).unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].name, "mymodule");
    }

    #[test]
    fn test_detect_go_work_missing() {
        let dir = setup_dir();
        assert!(detect_go_work(dir.path()).is_none());
    }

    #[test]
    fn test_detect_go_work_empty_uses() {
        let dir = setup_dir();
        fs::write(dir.path().join("go.work"), "go 1.21\n").unwrap();
        assert!(detect_go_work(dir.path()).is_none());
    }

    // --- Rust workspace tests ---

    #[test]
    fn test_detect_rust_cargo_workspace() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("crates/core")).unwrap();
        fs::create_dir_all(dir.path().join("crates/cli")).unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/core\", \"crates/cli\"]\n",
        )
        .unwrap();

        let ws = detect_rust_cargo(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::RustCargo);
        assert_eq!(ws.members.len(), 2);
        assert_eq!(ws.members[0].name, "core");
        assert_eq!(ws.members[0].path, PathBuf::from("crates/core"));
    }

    #[test]
    fn test_detect_rust_cargo_no_workspace() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"single\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        assert!(detect_rust_cargo(dir.path()).is_none());
    }

    #[test]
    fn test_detect_rust_cargo_missing() {
        let dir = setup_dir();
        assert!(detect_rust_cargo(dir.path()).is_none());
    }

    // --- JS package.json tests ---

    #[test]
    fn test_detect_js_package_json_array() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("packages/ui")).unwrap();
        fs::create_dir_all(dir.path().join("packages/core")).unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root", "workspaces": ["packages/ui", "packages/core"]}"#,
        )
        .unwrap();

        let ws = detect_js_package_json(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::JsPackageJson);
        assert_eq!(ws.members.len(), 2);
        assert_eq!(ws.members[0].name, "ui");
        assert_eq!(ws.members[1].name, "core");
    }

    #[test]
    fn test_detect_js_package_json_object() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("packages/lib")).unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root", "workspaces": {"packages": ["packages/lib"]}}"#,
        )
        .unwrap();

        let ws = detect_js_package_json(dir.path()).unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].name, "lib");
    }

    #[test]
    fn test_detect_js_package_json_missing() {
        let dir = setup_dir();
        assert!(detect_js_package_json(dir.path()).is_none());
    }

    #[test]
    fn test_detect_js_package_json_no_workspaces() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "simple", "version": "1.0.0"}"#,
        )
        .unwrap();
        assert!(detect_js_package_json(dir.path()).is_none());
    }

    // --- pnpm workspace tests ---

    #[test]
    fn test_detect_pnpm_workspace() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("packages/shared")).unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/shared'\n  - 'apps/web'\n",
        )
        .unwrap();

        let ws = detect_pnpm_workspace(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::PnpmWorkspace);
        assert_eq!(ws.members.len(), 2);
        assert_eq!(ws.members[0].name, "shared");
        assert_eq!(ws.members[1].name, "web");
    }

    #[test]
    fn test_detect_pnpm_workspace_missing() {
        let dir = setup_dir();
        assert!(detect_pnpm_workspace(dir.path()).is_none());
    }

    // --- Python pyproject tests ---

    #[test]
    fn test_detect_python_pyproject_chaffra_workspaces() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("packages/core")).unwrap();
        fs::create_dir_all(dir.path().join("packages/api")).unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[tool.chaffra]\nworkspaces = [\"packages/core\", \"packages/api\"]\n",
        )
        .unwrap();

        let ws = detect_python_pyproject(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::PythonPyproject);
        assert_eq!(ws.members.len(), 2);
    }

    #[test]
    fn test_detect_python_pyproject_missing() {
        let dir = setup_dir();
        assert!(detect_python_pyproject(dir.path()).is_none());
    }

    #[test]
    fn test_detect_python_pyproject_no_workspaces() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"my-project\"\n",
        )
        .unwrap();
        assert!(detect_python_pyproject(dir.path()).is_none());
    }

    // --- Java Gradle tests ---

    #[test]
    fn test_detect_java_gradle_groovy() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("settings.gradle"),
            "rootProject.name = 'myapp'\ninclude ':core', ':api'\ninclude ':web'\n",
        )
        .unwrap();

        let ws = detect_java_gradle(dir.path()).unwrap();
        assert_eq!(ws.kind, WorkspaceKind::JavaGradle);
        assert_eq!(ws.members.len(), 3);
        assert_eq!(ws.members[0].name, "core");
        assert_eq!(ws.members[0].path, PathBuf::from("core"));
        assert_eq!(ws.members[1].name, "api");
        assert_eq!(ws.members[2].name, "web");
    }

    #[test]
    fn test_detect_java_gradle_kotlin_dsl() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("settings.gradle.kts"),
            "rootProject.name = \"myapp\"\ninclude(\":core\")\ninclude(\":api\")\n",
        )
        .unwrap();

        let ws = detect_java_gradle(dir.path()).unwrap();
        assert_eq!(ws.members.len(), 2);
        assert_eq!(ws.members[0].name, "core");
    }

    #[test]
    fn test_detect_java_gradle_missing() {
        let dir = setup_dir();
        assert!(detect_java_gradle(dir.path()).is_none());
    }

    #[test]
    fn test_detect_java_gradle_no_includes() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("settings.gradle"),
            "rootProject.name = 'myapp'\n",
        )
        .unwrap();
        assert!(detect_java_gradle(dir.path()).is_none());
    }

    // --- expand_glob tests ---

    #[test]
    fn test_expand_glob_with_existing_dirs() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("crates/alpha")).unwrap();
        fs::create_dir_all(dir.path().join("crates/beta")).unwrap();
        // Create a file to ensure only dirs are returned
        fs::write(dir.path().join("crates/file.txt"), "").unwrap();

        let results = expand_glob(dir.path(), "crates/*");
        assert_eq!(results.len(), 2);
        // Results should be relative paths
        for r in &results {
            assert!(r.starts_with("crates/"));
        }
    }

    #[test]
    fn test_expand_glob_no_matches() {
        let dir = setup_dir();
        let results = expand_glob(dir.path(), "nonexistent/*");
        assert!(results.is_empty());
    }
}
