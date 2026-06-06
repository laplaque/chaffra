//! Built-in architecture presets: layered, hexagonal, feature-sliced, clean.

use crate::{ArchConfig, DependencyRule, Zone};

/// Preset architecture patterns.
#[derive(Debug, Clone, Copy)]
pub enum ArchPreset {
    Layered,
    Hexagonal,
    FeatureSliced,
    Clean,
}

impl ArchPreset {
    /// Parse a preset name (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "layered" | "layers" => Some(ArchPreset::Layered),
            "hexagonal" | "hex" | "ports-and-adapters" => Some(ArchPreset::Hexagonal),
            "feature-sliced" | "feature_sliced" | "fsd" => Some(ArchPreset::FeatureSliced),
            "clean" | "clean-architecture" => Some(ArchPreset::Clean),
            _ => None,
        }
    }

    /// Convert a preset to a full ArchConfig.
    pub fn to_config(self) -> ArchConfig {
        match self {
            ArchPreset::Layered => layered_config(),
            ArchPreset::Hexagonal => hexagonal_config(),
            ArchPreset::FeatureSliced => feature_sliced_config(),
            ArchPreset::Clean => clean_config(),
        }
    }
}

/// Layered architecture: presentation -> application -> domain -> infrastructure.
/// Domain must not import from infrastructure or presentation.
fn layered_config() -> ArchConfig {
    ArchConfig {
        zones: vec![
            Zone {
                name: "presentation".to_owned(),
                patterns: vec![
                    "presentation/**".to_owned(),
                    "api/**".to_owned(),
                    "handler/**".to_owned(),
                    "handlers/**".to_owned(),
                    "controller/**".to_owned(),
                    "controllers/**".to_owned(),
                    "cmd/**".to_owned(),
                    "ui/**".to_owned(),
                ],
            },
            Zone {
                name: "application".to_owned(),
                patterns: vec![
                    "application/**".to_owned(),
                    "service/**".to_owned(),
                    "services/**".to_owned(),
                    "usecase/**".to_owned(),
                    "usecases/**".to_owned(),
                ],
            },
            Zone {
                name: "domain".to_owned(),
                patterns: vec![
                    "domain/**".to_owned(),
                    "model/**".to_owned(),
                    "models/**".to_owned(),
                    "entity/**".to_owned(),
                    "entities/**".to_owned(),
                    "core/**".to_owned(),
                ],
            },
            Zone {
                name: "infrastructure".to_owned(),
                patterns: vec![
                    "infrastructure/**".to_owned(),
                    "infra/**".to_owned(),
                    "db/**".to_owned(),
                    "repository/**".to_owned(),
                    "repositories/**".to_owned(),
                    "adapter/**".to_owned(),
                    "adapters/**".to_owned(),
                    "external/**".to_owned(),
                ],
            },
        ],
        rules: vec![
            // Domain must not import from infrastructure.
            DependencyRule {
                from: "domain".to_owned(),
                to: "infrastructure".to_owned(),
                allow: false,
            },
            // Domain must not import from presentation.
            DependencyRule {
                from: "domain".to_owned(),
                to: "presentation".to_owned(),
                allow: false,
            },
            // Domain must not import from application.
            DependencyRule {
                from: "domain".to_owned(),
                to: "application".to_owned(),
                allow: false,
            },
            // Application must not import from presentation.
            DependencyRule {
                from: "application".to_owned(),
                to: "presentation".to_owned(),
                allow: false,
            },
            // Infrastructure must not import from presentation.
            DependencyRule {
                from: "infrastructure".to_owned(),
                to: "presentation".to_owned(),
                allow: false,
            },
            // Presentation must not import from infrastructure directly.
            DependencyRule {
                from: "presentation".to_owned(),
                to: "infrastructure".to_owned(),
                allow: false,
            },
        ],
    }
}

/// Hexagonal (ports & adapters): core/domain has no outbound dependencies.
/// Adapters depend on ports (interfaces), not on each other.
fn hexagonal_config() -> ArchConfig {
    ArchConfig {
        zones: vec![
            Zone {
                name: "core".to_owned(),
                patterns: vec![
                    "core/**".to_owned(),
                    "domain/**".to_owned(),
                    "model/**".to_owned(),
                    "models/**".to_owned(),
                ],
            },
            Zone {
                name: "ports".to_owned(),
                patterns: vec![
                    "port/**".to_owned(),
                    "ports/**".to_owned(),
                    "interface/**".to_owned(),
                    "interfaces/**".to_owned(),
                ],
            },
            Zone {
                name: "adapters".to_owned(),
                patterns: vec![
                    "adapter/**".to_owned(),
                    "adapters/**".to_owned(),
                    "infrastructure/**".to_owned(),
                    "infra/**".to_owned(),
                    "driven/**".to_owned(),
                    "driving/**".to_owned(),
                ],
            },
        ],
        rules: vec![
            // Core must not import from adapters.
            DependencyRule {
                from: "core".to_owned(),
                to: "adapters".to_owned(),
                allow: false,
            },
            // Ports must not import from adapters.
            DependencyRule {
                from: "ports".to_owned(),
                to: "adapters".to_owned(),
                allow: false,
            },
        ],
    }
}

/// Feature-sliced design: features are isolated, shared layer at bottom.
fn feature_sliced_config() -> ArchConfig {
    ArchConfig {
        zones: vec![
            Zone {
                name: "app".to_owned(),
                patterns: vec!["app/**".to_owned()],
            },
            Zone {
                name: "features".to_owned(),
                patterns: vec![
                    "features/**".to_owned(),
                    "feature/**".to_owned(),
                    "modules/**".to_owned(),
                ],
            },
            Zone {
                name: "shared".to_owned(),
                patterns: vec![
                    "shared/**".to_owned(),
                    "common/**".to_owned(),
                    "lib/**".to_owned(),
                    "pkg/**".to_owned(),
                ],
            },
        ],
        rules: vec![
            // Shared must not import from features.
            DependencyRule {
                from: "shared".to_owned(),
                to: "features".to_owned(),
                allow: false,
            },
            // Shared must not import from app.
            DependencyRule {
                from: "shared".to_owned(),
                to: "app".to_owned(),
                allow: false,
            },
        ],
    }
}

/// Clean architecture: entities -> use cases -> interface adapters -> frameworks.
fn clean_config() -> ArchConfig {
    ArchConfig {
        zones: vec![
            Zone {
                name: "entities".to_owned(),
                patterns: vec![
                    "entity/**".to_owned(),
                    "entities/**".to_owned(),
                    "domain/**".to_owned(),
                    "model/**".to_owned(),
                    "models/**".to_owned(),
                ],
            },
            Zone {
                name: "usecases".to_owned(),
                patterns: vec![
                    "usecase/**".to_owned(),
                    "usecases/**".to_owned(),
                    "use_case/**".to_owned(),
                    "application/**".to_owned(),
                    "service/**".to_owned(),
                    "services/**".to_owned(),
                ],
            },
            Zone {
                name: "adapters".to_owned(),
                patterns: vec![
                    "adapter/**".to_owned(),
                    "adapters/**".to_owned(),
                    "controller/**".to_owned(),
                    "controllers/**".to_owned(),
                    "presenter/**".to_owned(),
                    "presenters/**".to_owned(),
                    "gateway/**".to_owned(),
                    "gateways/**".to_owned(),
                ],
            },
            Zone {
                name: "frameworks".to_owned(),
                patterns: vec![
                    "framework/**".to_owned(),
                    "frameworks/**".to_owned(),
                    "infrastructure/**".to_owned(),
                    "infra/**".to_owned(),
                    "db/**".to_owned(),
                    "web/**".to_owned(),
                    "external/**".to_owned(),
                ],
            },
        ],
        rules: vec![
            // Entities must not import from anything else.
            DependencyRule {
                from: "entities".to_owned(),
                to: "usecases".to_owned(),
                allow: false,
            },
            DependencyRule {
                from: "entities".to_owned(),
                to: "adapters".to_owned(),
                allow: false,
            },
            DependencyRule {
                from: "entities".to_owned(),
                to: "frameworks".to_owned(),
                allow: false,
            },
            // Use cases must not import from adapters or frameworks.
            DependencyRule {
                from: "usecases".to_owned(),
                to: "adapters".to_owned(),
                allow: false,
            },
            DependencyRule {
                from: "usecases".to_owned(),
                to: "frameworks".to_owned(),
                allow: false,
            },
            // Adapters must not import from frameworks.
            DependencyRule {
                from: "adapters".to_owned(),
                to: "frameworks".to_owned(),
                allow: false,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_have_zones_and_rules() {
        for name in &["layered", "hexagonal", "feature-sliced", "clean"] {
            let preset = ArchPreset::from_name(name);
            assert!(preset.is_some(), "preset {name} should be recognized");
            let config = preset.unwrap().to_config();
            assert!(!config.zones.is_empty(), "preset {name} should have zones");
            assert!(!config.rules.is_empty(), "preset {name} should have rules");
        }
    }

    #[test]
    fn test_preset_aliases() {
        assert!(ArchPreset::from_name("layers").is_some());
        assert!(ArchPreset::from_name("hex").is_some());
        assert!(ArchPreset::from_name("ports-and-adapters").is_some());
        assert!(ArchPreset::from_name("fsd").is_some());
        assert!(ArchPreset::from_name("clean-architecture").is_some());
    }

    #[test]
    fn test_layered_domain_cannot_import_infra() {
        let config = layered_config();
        let deny_rules: Vec<_> = config
            .rules
            .iter()
            .filter(|r| !r.allow && r.from == "domain" && r.to == "infrastructure")
            .collect();
        assert!(
            !deny_rules.is_empty(),
            "layered: domain->infrastructure should be denied"
        );
    }

    #[test]
    fn test_hexagonal_core_cannot_import_adapters() {
        let config = hexagonal_config();
        let deny_rules: Vec<_> = config
            .rules
            .iter()
            .filter(|r| !r.allow && r.from == "core" && r.to == "adapters")
            .collect();
        assert!(
            !deny_rules.is_empty(),
            "hexagonal: core->adapters should be denied"
        );
    }

    #[test]
    fn test_clean_entities_isolated() {
        let config = clean_config();
        let entity_denies: Vec<_> = config
            .rules
            .iter()
            .filter(|r| !r.allow && r.from == "entities")
            .collect();
        assert!(
            entity_denies.len() >= 3,
            "clean: entities should be denied from importing usecases, adapters, frameworks"
        );
    }
}
