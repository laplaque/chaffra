//! External module configuration parsing.
//!
//! Reads `[[modules]]` entries from `.chaffra.toml` that define external
//! analysis modules reachable over gRPC.

use crate::error::PluginError;
use serde::{Deserialize, Serialize};

/// How the plugin host connects to an external module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// Spawn a local process and connect over localhost gRPC.
    #[default]
    Command,
    /// Connect to a running gRPC server at a given endpoint.
    Grpc,
    /// Run a Docker container and connect over localhost gRPC.
    Container,
}

/// Configuration for a single external module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalModuleConfig {
    /// Unique module identifier (e.g. "gin", "fastapi").
    pub id: String,

    /// Transport mode: command, grpc, or container.
    #[serde(default)]
    pub mode: TransportMode,

    /// Command to spawn (for `command` mode).
    pub command: Option<String>,

    /// gRPC endpoint (for `grpc` mode), e.g. "http://localhost:50051".
    pub endpoint: Option<String>,

    /// Docker image (for `container` mode), e.g. "chaffra/module-gin:latest".
    pub image: Option<String>,

    /// Optional port for gRPC communication. Defaults to an ephemeral port.
    pub port: Option<u16>,
}

impl ExternalModuleConfig {
    /// Validate that the required fields are present for the chosen mode.
    pub fn validate(&self) -> Result<(), PluginError> {
        match self.mode {
            TransportMode::Command => {
                if self.command.is_none() {
                    return Err(PluginError::Config(format!(
                        "module '{}': command mode requires 'command' field",
                        self.id
                    )));
                }
            }
            TransportMode::Grpc => {
                if self.endpoint.is_none() {
                    return Err(PluginError::Config(format!(
                        "module '{}': grpc mode requires 'endpoint' field",
                        self.id
                    )));
                }
            }
            TransportMode::Container => {
                if self.image.is_none() {
                    return Err(PluginError::Config(format!(
                        "module '{}': container mode requires 'image' field",
                        self.id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Resolve the gRPC endpoint for this module.
    pub fn resolve_endpoint(&self) -> String {
        match self.mode {
            TransportMode::Command | TransportMode::Container => {
                let port = self.port.unwrap_or(0);
                format!("http://127.0.0.1:{port}")
            }
            TransportMode::Grpc => self
                .endpoint
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:50051".to_owned()),
        }
    }
}

/// Wrapper for parsing the `[[external_modules]]` array from `.chaffra.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalModulesConfig {
    /// List of external module definitions.
    #[serde(default, rename = "external_modules")]
    pub modules: Vec<ExternalModuleConfig>,
}

/// Parse external module configs from a TOML string.
pub fn parse_external_modules(
    toml_content: &str,
) -> Result<Vec<ExternalModuleConfig>, PluginError> {
    let config: ExternalModulesConfig = toml::from_str(toml_content)
        .map_err(|e| PluginError::Config(format!("invalid TOML: {e}")))?;

    for module in &config.modules {
        module.validate()?;
    }

    Ok(config.modules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_mode() {
        let toml = r#"
[[external_modules]]
id = "gin"
command = "chaffra-module-gin"
"#;
        let modules = parse_external_modules(toml).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].id, "gin");
        assert_eq!(modules[0].mode, TransportMode::Command);
        assert_eq!(modules[0].command.as_deref(), Some("chaffra-module-gin"));
    }

    #[test]
    fn test_parse_grpc_mode() {
        let toml = r#"
[[external_modules]]
id = "fastapi"
mode = "grpc"
endpoint = "http://localhost:50051"
"#;
        let modules = parse_external_modules(toml).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].id, "fastapi");
        assert_eq!(modules[0].mode, TransportMode::Grpc);
        assert_eq!(
            modules[0].endpoint.as_deref(),
            Some("http://localhost:50051")
        );
    }

    #[test]
    fn test_parse_container_mode() {
        let toml = r#"
[[external_modules]]
id = "django"
mode = "container"
image = "chaffra/module-django:latest"
port = 50052
"#;
        let modules = parse_external_modules(toml).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].id, "django");
        assert_eq!(modules[0].mode, TransportMode::Container);
        assert_eq!(
            modules[0].image.as_deref(),
            Some("chaffra/module-django:latest")
        );
        assert_eq!(modules[0].port, Some(50052));
    }

    #[test]
    fn test_parse_multiple_modules() {
        let toml = r#"
[[external_modules]]
id = "gin"
command = "chaffra-module-gin"

[[external_modules]]
id = "echo"
command = "chaffra-module-echo"
"#;
        let modules = parse_external_modules(toml).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].id, "gin");
        assert_eq!(modules[1].id, "echo");
    }

    #[test]
    fn test_validate_command_mode_missing_command() {
        let toml = r#"
[[external_modules]]
id = "broken"
"#;
        let err = parse_external_modules(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("command mode requires 'command' field"),
            "{msg}"
        );
    }

    #[test]
    fn test_validate_grpc_mode_missing_endpoint() {
        let toml = r#"
[[external_modules]]
id = "broken"
mode = "grpc"
"#;
        let err = parse_external_modules(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("grpc mode requires 'endpoint' field"), "{msg}");
    }

    #[test]
    fn test_validate_container_mode_missing_image() {
        let toml = r#"
[[external_modules]]
id = "broken"
mode = "container"
"#;
        let err = parse_external_modules(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("container mode requires 'image' field"),
            "{msg}"
        );
    }

    #[test]
    fn test_resolve_endpoint_command() {
        let config = ExternalModuleConfig {
            id: "test".to_owned(),
            mode: TransportMode::Command,
            command: Some("test-cmd".to_owned()),
            endpoint: None,
            image: None,
            port: Some(9999),
        };
        assert_eq!(config.resolve_endpoint(), "http://127.0.0.1:9999");
    }

    #[test]
    fn test_resolve_endpoint_grpc() {
        let config = ExternalModuleConfig {
            id: "test".to_owned(),
            mode: TransportMode::Grpc,
            command: None,
            endpoint: Some("http://remote:50051".to_owned()),
            image: None,
            port: None,
        };
        assert_eq!(config.resolve_endpoint(), "http://remote:50051");
    }

    #[test]
    fn test_resolve_endpoint_grpc_default() {
        let config = ExternalModuleConfig {
            id: "test".to_owned(),
            mode: TransportMode::Grpc,
            command: None,
            endpoint: None,
            image: None,
            port: None,
        };
        assert_eq!(config.resolve_endpoint(), "http://127.0.0.1:50051");
    }

    #[test]
    fn test_resolve_endpoint_container() {
        let config = ExternalModuleConfig {
            id: "test".to_owned(),
            mode: TransportMode::Container,
            command: None,
            endpoint: None,
            image: Some("img:latest".to_owned()),
            port: Some(8080),
        };
        assert_eq!(config.resolve_endpoint(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_parse_empty_modules() {
        let toml = "";
        let modules = parse_external_modules(toml).unwrap();
        assert!(modules.is_empty());
    }

    #[test]
    fn test_parse_invalid_toml() {
        let toml = "this is not valid toml [[[";
        let err = parse_external_modules(toml).unwrap_err();
        assert!(err.to_string().contains("invalid TOML"));
    }

    #[test]
    fn test_default_transport_mode() {
        assert_eq!(TransportMode::default(), TransportMode::Command);
    }
}
