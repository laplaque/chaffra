# CI/CD Security Module

**Module ID:** `cicd-security`
**Crate:** `chaffra-cicd-security`
**File Types:** YAML (GitHub Actions, GitLab CI, Docker Compose), Dockerfile, INI (systemd)

Detects security misconfigurations in CI/CD pipeline definitions, container build files, and service units.

## Rules

### GitHub Actions

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `actions-dangerous-trigger` | Dangerous workflow trigger | error | Workflow uses `pull_request_target` or `workflow_run` with checkout, enabling code execution from forks |
| `actions-unpinned-action` | Unpinned action reference | warning | Action uses a mutable tag instead of a pinned SHA commit hash |
| `actions-excessive-permissions` | Excessive workflow permissions | warning | Workflow grants `write-all` or broad write permissions without restriction |
| `actions-script-injection` | Script injection via untrusted input | error | Workflow interpolates user-controlled context into a `run` step, enabling command injection |

### GitLab CI

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `gitlab-mutable-image` | Mutable container image tag | warning | Job uses `:latest` or an untagged image, risking supply-chain attacks |
| `gitlab-unpinned-include` | Unpinned remote include | warning | Pipeline includes a remote YAML without a pinned ref or hash |
| `gitlab-literal-secret` | Literal secret in pipeline | error | A variable value appears to contain a hardcoded credential |
| `gitlab-insecure-runner` | Insecure runner tag | info | Job requests a shared or untagged runner, increasing attack surface |

### Dockerfile

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `dockerfile-run-as-root` | Container runs as root | warning | No `USER` directive sets a non-root user before the final stage entrypoint |
| `dockerfile-remote-add` | Remote ADD from URL | warning | `ADD` fetches content from a URL without checksum verification |
| `dockerfile-unpinned-base` | Unpinned base image | warning | `FROM` uses `:latest` or an untagged base image |
| `dockerfile-secrets-in-layer` | Secrets exposed in layer | error | `ENV`, `ARG`, or `COPY` exposes a secret value that persists in the image layer |

### Docker Compose

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `compose-privileged` | Privileged container | error | Service runs in privileged mode, granting full host access |
| `compose-host-network` | Host network mode | warning | Service uses host network mode, bypassing container network isolation |
| `compose-host-mount` | Sensitive host path mount | error | Service mounts a sensitive host path like `/`, `/etc`, or the Docker socket |

### systemd

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `systemd-root-execution` | Service runs as root | warning | Service unit does not specify `User=` or runs explicitly as root |
| `systemd-missing-hardening` | Missing systemd hardening | info | Service unit does not enable recommended sandboxing directives |

## File Detection

Files are classified by path patterns:

| Pattern | Type |
|---------|------|
| `.github/workflows/*.yml` / `.yaml` | GitHub Actions |
| `.gitlab-ci.yml` / `.gitlab-ci.yaml` | GitLab CI |
| `Dockerfile*`, `*.dockerfile` | Dockerfile |
| `docker-compose*.yml`, `compose*.yml` | Docker Compose |
| `*.service` | systemd |

## Confidence Scoring

| Scenario | Confidence |
|----------|-----------|
| Deterministic pattern match (e.g., `write-all`, `:latest`) | 1.0 |
| Dangerous trigger with checkout | 0.9 |
| Heuristic secret detection | 0.85 |
| Missing hardening directives | 0.8 |
| Insecure runner (no tags) | 0.7 |

## CLI Usage

```bash
chaffra cicd-security .                     # Analyze current directory
chaffra cicd-security ./infra --format json # JSON output
chaffra explain cicd-security:actions-unpinned-action  # Explain a rule
```
