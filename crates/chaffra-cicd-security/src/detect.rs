//! Auto-detection of CI/CD file types by path patterns.

/// Known CI/CD file types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CicdFileType {
    GitHubActions,
    GitLabCi,
    Dockerfile,
    DockerCompose,
    Systemd,
    Unknown,
}

/// Detect CI/CD file type from a file path.
///
/// Uses path patterns to classify files:
/// - `.github/workflows/*.yml` or `.yaml` -> GitHub Actions
/// - `.gitlab-ci.yml` or files including `gitlab-ci` -> GitLab CI
/// - `Dockerfile*` or `*.dockerfile` -> Dockerfile
/// - `docker-compose*.yml` or `compose*.yml` -> Docker Compose
/// - `*.service` under systemd-like paths -> systemd
pub fn detect_file_type(path: &str) -> CicdFileType {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_lowercase();
    let filename = normalized.rsplit('/').next().unwrap_or(&normalized);
    let filename_lower = filename.to_lowercase();

    // GitHub Actions: .github/workflows/*.yml or .yaml
    if lower.contains(".github/workflows/")
        && (filename_lower.ends_with(".yml") || filename_lower.ends_with(".yaml"))
    {
        return CicdFileType::GitHubActions;
    }

    // GitLab CI: .gitlab-ci.yml or files that include "gitlab-ci"
    if filename_lower == ".gitlab-ci.yml" || filename_lower == ".gitlab-ci.yaml" {
        return CicdFileType::GitLabCi;
    }

    // Docker Compose: docker-compose*.yml, compose*.yml, compose*.yaml
    if (filename_lower.starts_with("docker-compose") || filename_lower.starts_with("compose"))
        && (filename_lower.ends_with(".yml") || filename_lower.ends_with(".yaml"))
    {
        return CicdFileType::DockerCompose;
    }

    // Dockerfile: Dockerfile*, *.dockerfile
    if filename_lower.starts_with("dockerfile") || filename_lower.ends_with(".dockerfile") {
        return CicdFileType::Dockerfile;
    }

    // systemd: *.service files
    if filename_lower.ends_with(".service") {
        return CicdFileType::Systemd;
    }

    CicdFileType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_actions() {
        let cases = vec![
            (".github/workflows/ci.yml", CicdFileType::GitHubActions),
            (".github/workflows/deploy.yaml", CicdFileType::GitHubActions),
            (
                "repo/.github/workflows/test.yml",
                CicdFileType::GitHubActions,
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_file_type(path), expected, "path: {path}");
        }
    }

    #[test]
    fn test_gitlab_ci() {
        let cases = vec![
            (".gitlab-ci.yml", CicdFileType::GitLabCi),
            (".gitlab-ci.yaml", CicdFileType::GitLabCi),
            ("repo/.gitlab-ci.yml", CicdFileType::GitLabCi),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_file_type(path), expected, "path: {path}");
        }
    }

    #[test]
    fn test_dockerfile() {
        let cases = vec![
            ("Dockerfile", CicdFileType::Dockerfile),
            ("Dockerfile.prod", CicdFileType::Dockerfile),
            ("app.dockerfile", CicdFileType::Dockerfile),
            ("services/Dockerfile", CicdFileType::Dockerfile),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_file_type(path), expected, "path: {path}");
        }
    }

    #[test]
    fn test_docker_compose() {
        let cases = vec![
            ("docker-compose.yml", CicdFileType::DockerCompose),
            ("docker-compose.yaml", CicdFileType::DockerCompose),
            ("docker-compose.override.yml", CicdFileType::DockerCompose),
            ("compose.yml", CicdFileType::DockerCompose),
            ("compose.yaml", CicdFileType::DockerCompose),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_file_type(path), expected, "path: {path}");
        }
    }

    #[test]
    fn test_systemd() {
        let cases = vec![
            ("myapp.service", CicdFileType::Systemd),
            ("/etc/systemd/system/myapp.service", CicdFileType::Systemd),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_file_type(path), expected, "path: {path}");
        }
    }

    #[test]
    fn test_unknown() {
        let cases = vec!["main.go", "app.py", "README.md", "package.json"];
        for path in cases {
            assert_eq!(
                detect_file_type(path),
                CicdFileType::Unknown,
                "path: {path}"
            );
        }
    }

    #[test]
    fn test_windows_paths() {
        assert_eq!(
            detect_file_type(".github\\workflows\\ci.yml"),
            CicdFileType::GitHubActions
        );
    }
}
