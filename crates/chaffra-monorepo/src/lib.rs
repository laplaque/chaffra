//! Monorepo workspace detection and per-workspace analysis scoping.
//!
//! Detects workspaces across multiple ecosystems: Go (`go.work`), Rust
//! (`Cargo.toml` `[workspace]`), JS/TS (`package.json` workspaces,
//! `pnpm-workspace.yaml`), Python (`pyproject.toml` workspaces), and
//! Java (`settings.gradle` includes).

pub mod detect;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A detected workspace member within a monorepo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMember {
    /// Human-readable name (from package manifest or directory name).
    pub name: String,
    /// Path relative to the monorepo root.
    pub path: PathBuf,
}

/// The type of workspace manifest that was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceKind {
    /// Go workspace via `go.work`.
    GoWork,
    /// Rust workspace via `Cargo.toml` `[workspace]`.
    RustCargo,
    /// JS/TS workspace via `package.json` `workspaces` field.
    JsPackageJson,
    /// JS/TS workspace via `pnpm-workspace.yaml`.
    PnpmWorkspace,
    /// Python workspace via `pyproject.toml` workspaces.
    PythonPyproject,
    /// Java workspace via `settings.gradle` includes.
    JavaGradle,
}

impl std::fmt::Display for WorkspaceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceKind::GoWork => write!(f, "go-work"),
            WorkspaceKind::RustCargo => write!(f, "rust-cargo"),
            WorkspaceKind::JsPackageJson => write!(f, "js-package-json"),
            WorkspaceKind::PnpmWorkspace => write!(f, "pnpm-workspace"),
            WorkspaceKind::PythonPyproject => write!(f, "python-pyproject"),
            WorkspaceKind::JavaGradle => write!(f, "java-gradle"),
        }
    }
}

/// A detected monorepo workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Root directory of the monorepo.
    pub root: PathBuf,
    /// The kind of workspace manifest found.
    pub kind: WorkspaceKind,
    /// Workspace members.
    pub members: Vec<WorkspaceMember>,
}

/// Detect all workspace configurations in the given directory.
///
/// Scans for all supported workspace manifest files and returns one
/// `Workspace` per detected configuration. A repo may have multiple
/// (e.g. a Rust workspace root with a JS package.json).
pub fn detect_workspaces(root: &Path) -> Vec<Workspace> {
    let mut workspaces = Vec::new();

    if let Some(ws) = detect::detect_go_work(root) {
        workspaces.push(ws);
    }
    if let Some(ws) = detect::detect_rust_cargo(root) {
        workspaces.push(ws);
    }
    if let Some(ws) = detect::detect_js_package_json(root) {
        workspaces.push(ws);
    }
    if let Some(ws) = detect::detect_pnpm_workspace(root) {
        workspaces.push(ws);
    }
    if let Some(ws) = detect::detect_python_pyproject(root) {
        workspaces.push(ws);
    }
    if let Some(ws) = detect::detect_java_gradle(root) {
        workspaces.push(ws);
    }

    workspaces
}

/// Filter workspace members to only those that changed between two git refs.
///
/// This is a simplified implementation that checks which member directories
/// contain changed files. Takes a list of changed file paths (relative to root)
/// and returns only members whose path is a prefix of at least one changed file.
pub fn changed_workspaces(workspace: &Workspace, changed_files: &[String]) -> Vec<WorkspaceMember> {
    workspace
        .members
        .iter()
        .filter(|member| {
            let prefix = member.path.to_string_lossy();
            changed_files.iter().any(|f| f.starts_with(prefix.as_ref()))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_kind_display() {
        let cases = vec![
            (WorkspaceKind::GoWork, "go-work"),
            (WorkspaceKind::RustCargo, "rust-cargo"),
            (WorkspaceKind::JsPackageJson, "js-package-json"),
            (WorkspaceKind::PnpmWorkspace, "pnpm-workspace"),
            (WorkspaceKind::PythonPyproject, "python-pyproject"),
            (WorkspaceKind::JavaGradle, "java-gradle"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.to_string(), expected);
        }
    }

    #[test]
    fn test_changed_workspaces_filtering() {
        let workspace = Workspace {
            root: PathBuf::from("/repo"),
            kind: WorkspaceKind::GoWork,
            members: vec![
                WorkspaceMember {
                    name: "svc-a".to_owned(),
                    path: PathBuf::from("services/svc-a"),
                },
                WorkspaceMember {
                    name: "svc-b".to_owned(),
                    path: PathBuf::from("services/svc-b"),
                },
                WorkspaceMember {
                    name: "lib-common".to_owned(),
                    path: PathBuf::from("libs/common"),
                },
            ],
        };

        let changed = vec![
            "services/svc-a/main.go".to_owned(),
            "libs/common/util.go".to_owned(),
        ];

        let result = changed_workspaces(&workspace, &changed);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "svc-a");
        assert_eq!(result[1].name, "lib-common");
    }

    #[test]
    fn test_changed_workspaces_no_matches() {
        let workspace = Workspace {
            root: PathBuf::from("/repo"),
            kind: WorkspaceKind::RustCargo,
            members: vec![WorkspaceMember {
                name: "crate-a".to_owned(),
                path: PathBuf::from("crates/a"),
            }],
        };

        let changed = vec!["README.md".to_owned()];
        let result = changed_workspaces(&workspace, &changed);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_workspaces_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = detect_workspaces(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_workspace_member_equality() {
        let a = WorkspaceMember {
            name: "foo".to_owned(),
            path: PathBuf::from("pkg/foo"),
        };
        let b = WorkspaceMember {
            name: "foo".to_owned(),
            path: PathBuf::from("pkg/foo"),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_workspace_serialization_roundtrip() {
        let ws = Workspace {
            root: PathBuf::from("/repo"),
            kind: WorkspaceKind::GoWork,
            members: vec![WorkspaceMember {
                name: "svc".to_owned(),
                path: PathBuf::from("cmd/svc"),
            }],
        };
        let json = serde_json::to_string(&ws).unwrap();
        let deserialized: Workspace = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.kind, WorkspaceKind::GoWork);
        assert_eq!(deserialized.members.len(), 1);
    }
}
