//! PR risk assessment and audit gating.
//!
//! Compares current analysis results against a stored baseline to determine
//! whether a pull request introduces new issues. Supports `new-only` and `all`
//! gating modes with configurable tolerance thresholds. Emits a structured
//! verdict (pass / warn / fail) consumed by CI and the CLI `audit` subcommand.
