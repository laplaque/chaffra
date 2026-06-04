//! File discovery: walk directories, detect languages, respect ignore patterns.

use chaffra_core::diagnostic::Language;
use std::path::{Path, PathBuf};

/// A discovered source file with its detected language.
#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Path relative to the analysis root.
    pub relative_path: String,
    /// Detected programming language.
    pub language: Language,
}

/// Default ignore patterns.
const DEFAULT_IGNORE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
];

/// Discover source files in a directory tree.
///
/// Respects `.gitignore` and `.chafframeignore` patterns, plus default ignores.
pub fn discover_files(root: &Path, ignore_patterns: &[String]) -> Vec<DiscoveredFile> {
    let mut files = Vec::new();
    let gitignore_patterns = load_ignore_file(root, ".gitignore");
    let chaffra_ignore_patterns = load_ignore_file(root, ".chafframeignore");

    let all_ignore: Vec<String> = ignore_patterns
        .iter()
        .cloned()
        .chain(gitignore_patterns)
        .chain(chaffra_ignore_patterns)
        .collect();

    walk_dir(root, root, &all_ignore, &mut files);
    files
}

fn walk_dir(root: &Path, dir: &Path, ignore_patterns: &[String], files: &mut Vec<DiscoveredFile>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            // Skip default ignore directories.
            if DEFAULT_IGNORE_DIRS.contains(&name.as_ref()) {
                continue;
            }
            // Check custom ignore patterns.
            let rel = relative_path(root, &path);
            if is_ignored(&rel, ignore_patterns) {
                continue;
            }
            walk_dir(root, &path, ignore_patterns, files);
        } else if path.is_file() {
            let rel = relative_path(root, &path);
            if is_ignored(&rel, ignore_patterns) {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if let Some(lang) = Language::from_extension(ext) {
                    files.push(DiscoveredFile {
                        path: path.clone(),
                        relative_path: rel,
                        language: lang,
                    });
                }
            }
        }
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn load_ignore_file(root: &Path, filename: &str) -> Vec<String> {
    let path = root.join(filename);
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn is_ignored(relative_path: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        // Simple glob matching.
        if let Ok(matcher) = glob::Pattern::new(pattern) {
            if matcher.matches(relative_path) {
                return true;
            }
        }
        // Also try matching as a directory prefix.
        if relative_path.starts_with(pattern.trim_end_matches("/**")) && pattern.ends_with("/**") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_discover_empty_dir() {
        let dir = std::env::temp_dir().join("chaffra_test_discover_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let files = discover_files(&dir, &[]);
        assert!(files.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_go_files() {
        let dir = std::env::temp_dir().join("chaffra_test_discover_go");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("main.go"), "package main").unwrap();
        fs::write(dir.join("readme.md"), "# readme").unwrap();

        let files = discover_files(&dir, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, Language::Go);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_respects_ignore() {
        let dir = std::env::temp_dir().join("chaffra_test_discover_ignore");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("vendor")).unwrap();
        fs::write(dir.join("main.go"), "package main").unwrap();
        fs::write(dir.join("vendor/dep.go"), "package dep").unwrap();

        let files = discover_files(&dir, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative_path, "main.go");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_python_files() {
        let dir = std::env::temp_dir().join("chaffra_test_discover_py");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("app.py"), "def main(): pass").unwrap();

        let files = discover_files(&dir, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, Language::Python);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_ignored() {
        assert!(is_ignored("vendor/foo.go", &["vendor/**".to_owned()]));
        assert!(!is_ignored("src/main.go", &["vendor/**".to_owned()]));
        assert!(is_ignored("test_foo.py", &["test_*.py".to_owned()]));
    }
}
