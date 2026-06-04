//! Pre-commit hook installation and management.
//!
//! Provides `install` and `uninstall` operations for a git pre-commit hook
//! that runs chaffra analysis on staged files before each commit.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Marker comment used to identify chaffra-managed hooks.
const HOOK_MARKER: &str = "# chaffra-managed-hook";

/// The shell script content for the pre-commit hook.
const HOOK_SCRIPT: &str = r#"#!/bin/sh
# chaffra-managed-hook
# Pre-commit hook: run chaffra analysis on staged files.
# Installed by `chaffra hooks install`. Remove with `chaffra hooks uninstall`.

set -e

# Collect staged files.
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
    exit 0
fi

# Run chaffra dead-code analysis on the repo root.
if command -v chaffra >/dev/null 2>&1; then
    echo "chaffra: analyzing staged files..."
    chaffra dead-code . --format terminal
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo "chaffra: analysis found issues. Commit blocked."
        exit 1
    fi
else
    echo "chaffra: binary not found, skipping pre-commit check."
fi
"#;

/// Result of a hook operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookResult {
    /// Hook was installed successfully.
    Installed,
    /// Hook was uninstalled successfully.
    Uninstalled,
    /// Hook was already installed; no changes made.
    AlreadyInstalled,
    /// No chaffra hook found to uninstall.
    NotInstalled,
}

impl std::fmt::Display for HookResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookResult::Installed => write!(f, "Pre-commit hook installed."),
            HookResult::Uninstalled => write!(f, "Pre-commit hook uninstalled."),
            HookResult::AlreadyInstalled => write!(f, "Pre-commit hook is already installed."),
            HookResult::NotInstalled => write!(f, "No chaffra pre-commit hook found."),
        }
    }
}

/// Install the chaffra pre-commit hook into the given repository.
///
/// If a pre-commit hook already exists and is chaffra-managed, returns
/// `AlreadyInstalled`. If a non-chaffra hook exists, it is preserved by
/// appending the chaffra hook script.
pub fn install_hook(repo_root: &Path) -> Result<HookResult, String> {
    let hooks_dir = repo_root.join(".git").join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    if !hooks_dir.exists() {
        return Err(format!(
            "not a git repository (no .git/hooks at {})",
            repo_root.display()
        ));
    }

    // Check for existing hook.
    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .map_err(|e| format!("failed to read existing hook: {e}"))?;

        if existing.contains(HOOK_MARKER) {
            return Ok(HookResult::AlreadyInstalled);
        }

        // Existing non-chaffra hook: append our script.
        let combined = format!("{existing}\n{HOOK_SCRIPT}");
        fs::write(&hook_path, combined).map_err(|e| format!("failed to write hook: {e}"))?;
    } else {
        fs::write(&hook_path, HOOK_SCRIPT).map_err(|e| format!("failed to write hook: {e}"))?;
    }

    // Make executable.
    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&hook_path, perms)
        .map_err(|e| format!("failed to set hook permissions: {e}"))?;

    Ok(HookResult::Installed)
}

/// Uninstall the chaffra pre-commit hook from the given repository.
///
/// If the hook file contains only the chaffra hook, the file is removed.
/// If it also contains other hook content, only the chaffra portion is removed.
pub fn uninstall_hook(repo_root: &Path) -> Result<HookResult, String> {
    let hook_path = repo_root.join(".git").join("hooks").join("pre-commit");

    if !hook_path.exists() {
        return Ok(HookResult::NotInstalled);
    }

    let content =
        fs::read_to_string(&hook_path).map_err(|e| format!("failed to read hook: {e}"))?;

    if !content.contains(HOOK_MARKER) {
        return Ok(HookResult::NotInstalled);
    }

    // If the file is purely our hook, remove it.
    let trimmed = content.trim();
    let hook_trimmed = HOOK_SCRIPT.trim();
    if trimmed == hook_trimmed {
        fs::remove_file(&hook_path).map_err(|e| format!("failed to remove hook: {e}"))?;
        return Ok(HookResult::Uninstalled);
    }

    // Otherwise, strip only the chaffra portion.
    let cleaned = content.replace(HOOK_SCRIPT, "");
    let cleaned = cleaned.replace(&format!("\n{HOOK_SCRIPT}"), "");
    fs::write(&hook_path, cleaned.trim_end())
        .map_err(|e| format!("failed to write cleaned hook: {e}"))?;

    Ok(HookResult::Uninstalled)
}

/// Check whether a chaffra pre-commit hook is installed.
pub fn is_hook_installed(repo_root: &Path) -> bool {
    let hook_path = repo_root.join(".git").join("hooks").join("pre-commit");
    if let Ok(content) = fs::read_to_string(&hook_path) {
        content.contains(HOOK_MARKER)
    } else {
        false
    }
}

/// Return the hook script content (for testing or display).
pub fn hook_script() -> &'static str {
    HOOK_SCRIPT
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        dir
    }

    #[test]
    fn test_install_fresh_repo() {
        let repo = setup_repo();
        let result = install_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::Installed);

        let hook = repo.path().join(".git/hooks/pre-commit");
        assert!(hook.exists());

        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.contains(HOOK_MARKER));
        assert!(content.contains("chaffra dead-code"));

        let meta = fs::metadata(&hook).unwrap();
        assert!(meta.permissions().mode() & 0o111 != 0);
    }

    #[test]
    fn test_install_already_installed() {
        let repo = setup_repo();
        install_hook(repo.path()).unwrap();
        let result = install_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::AlreadyInstalled);
    }

    #[test]
    fn test_install_preserves_existing_hook() {
        let repo = setup_repo();
        let hook_path = repo.path().join(".git/hooks/pre-commit");
        fs::write(&hook_path, "#!/bin/sh\necho 'existing hook'\n").unwrap();

        let result = install_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::Installed);

        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(content.contains("existing hook"));
        assert!(content.contains(HOOK_MARKER));
    }

    #[test]
    fn test_install_no_git_dir() {
        let dir = TempDir::new().unwrap();
        let result = install_hook(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a git repository"));
    }

    #[test]
    fn test_uninstall_chaffra_only() {
        let repo = setup_repo();
        install_hook(repo.path()).unwrap();

        let result = uninstall_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::Uninstalled);

        let hook_path = repo.path().join(".git/hooks/pre-commit");
        assert!(!hook_path.exists());
    }

    #[test]
    fn test_uninstall_not_installed() {
        let repo = setup_repo();
        let result = uninstall_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::NotInstalled);
    }

    #[test]
    fn test_uninstall_no_hook_file() {
        let repo = setup_repo();
        let result = uninstall_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::NotInstalled);
    }

    #[test]
    fn test_uninstall_non_chaffra_hook() {
        let repo = setup_repo();
        let hook_path = repo.path().join(".git/hooks/pre-commit");
        fs::write(&hook_path, "#!/bin/sh\necho 'other hook'\n").unwrap();

        let result = uninstall_hook(repo.path()).unwrap();
        assert_eq!(result, HookResult::NotInstalled);

        // Non-chaffra hook should be untouched.
        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(content.contains("other hook"));
    }

    #[test]
    fn test_is_hook_installed() {
        let repo = setup_repo();
        assert!(!is_hook_installed(repo.path()));

        install_hook(repo.path()).unwrap();
        assert!(is_hook_installed(repo.path()));

        uninstall_hook(repo.path()).unwrap();
        assert!(!is_hook_installed(repo.path()));
    }

    #[test]
    fn test_hook_script_content() {
        let script = hook_script();
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains(HOOK_MARKER));
    }

    #[test]
    fn test_hook_result_display() {
        let cases = vec![
            (HookResult::Installed, "Pre-commit hook installed."),
            (HookResult::Uninstalled, "Pre-commit hook uninstalled."),
            (
                HookResult::AlreadyInstalled,
                "Pre-commit hook is already installed.",
            ),
            (
                HookResult::NotInstalled,
                "No chaffra pre-commit hook found.",
            ),
        ];
        for (result, expected) in cases {
            assert_eq!(result.to_string(), expected);
        }
    }
}
