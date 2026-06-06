//! Conversion functions between core diagnostic types and proto types.

use crate::diagnostic;
use chaffra_proto::proto;

// --- FileInfo ---

pub fn file_info_to_proto(fi: &diagnostic::FileInfo) -> proto::FileInfo {
    proto::FileInfo {
        path: fi.path.clone(),
        content: fi.content.clone(),
        nodes: vec![],
    }
}

pub fn file_info_from_proto(fi: &proto::FileInfo) -> diagnostic::FileInfo {
    diagnostic::FileInfo {
        path: fi.path.clone(),
        content: fi.content.clone(),
    }
}

// --- Location ---

pub fn location_to_proto(loc: &diagnostic::Location) -> proto::Location {
    proto::Location {
        file: loc.file.clone(),
        start_line: loc.start_line,
        end_line: loc.end_line,
        start_column: loc.start_column,
        end_column: loc.end_column,
    }
}

pub fn location_from_proto(loc: &proto::Location) -> diagnostic::Location {
    diagnostic::Location {
        file: loc.file.clone(),
        start_line: loc.start_line,
        end_line: loc.end_line,
        start_column: loc.start_column,
        end_column: loc.end_column,
    }
}

// --- TextEdit ---

pub fn text_edit_to_proto(edit: &diagnostic::TextEdit) -> proto::TextEdit {
    proto::TextEdit {
        file: edit.file.clone(),
        start_line: edit.start_line,
        end_line: edit.end_line,
        new_text: edit.new_text.clone(),
    }
}

pub fn text_edit_from_proto(edit: &proto::TextEdit) -> diagnostic::TextEdit {
    diagnostic::TextEdit {
        file: edit.file.clone(),
        start_line: edit.start_line,
        end_line: edit.end_line,
        new_text: edit.new_text.clone(),
    }
}

// --- Action ---

pub fn action_to_proto(action: &diagnostic::Action) -> proto::Action {
    proto::Action {
        description: action.description.clone(),
        auto_fixable: action.auto_fixable,
        edits: action.edits.iter().map(text_edit_to_proto).collect(),
    }
}

pub fn action_from_proto(action: &proto::Action) -> diagnostic::Action {
    diagnostic::Action {
        description: action.description.clone(),
        auto_fixable: action.auto_fixable,
        edits: action.edits.iter().map(text_edit_from_proto).collect(),
    }
}

// --- Severity ---

fn severity_to_string(sev: diagnostic::Severity) -> String {
    sev.to_string()
}

fn severity_from_string(s: &str) -> crate::error::Result<diagnostic::Severity> {
    diagnostic::Severity::from_str_loose(s).ok_or_else(|| {
        crate::error::ChaffraError::ProtoConversion(format!("unknown severity value: '{s}'"))
    })
}

// --- Finding ---

pub fn finding_to_proto(f: &diagnostic::Finding) -> proto::Finding {
    proto::Finding {
        rule_id: f.rule_id.clone(),
        message: f.message.clone(),
        severity: severity_to_string(f.severity),
        location: Some(location_to_proto(&f.location)),
        confidence: f.confidence,
        actions: f.actions.iter().map(action_to_proto).collect(),
        metadata: f.metadata.clone(),
    }
}

pub fn finding_from_proto(f: &proto::Finding) -> crate::error::Result<diagnostic::Finding> {
    let location = f
        .location
        .as_ref()
        .map(location_from_proto)
        .ok_or_else(|| {
            crate::error::ChaffraError::ProtoConversion(format!(
                "finding '{}' is missing required location field",
                f.rule_id
            ))
        })?;

    Ok(diagnostic::Finding {
        rule_id: f.rule_id.clone(),
        message: f.message.clone(),
        severity: severity_from_string(&f.severity)?,
        location,
        confidence: f.confidence,
        actions: f.actions.iter().map(action_from_proto).collect(),
        metadata: f.metadata.clone(),
    })
}

// --- ModuleMetrics ---

pub fn module_metrics_to_proto(m: &diagnostic::ModuleMetrics) -> proto::ModuleMetrics {
    proto::ModuleMetrics {
        files_analyzed: m.files_analyzed,
        duration_ms: m.duration_ms,
        counters: m.counters.clone(),
        metrics: vec![],
        spans: vec![],
    }
}

pub fn module_metrics_from_proto(m: &proto::ModuleMetrics) -> diagnostic::ModuleMetrics {
    diagnostic::ModuleMetrics {
        files_analyzed: m.files_analyzed,
        duration_ms: m.duration_ms,
        counters: m.counters.clone(),
    }
}

// --- AnalysisResult ---

pub fn analysis_result_to_proto(r: &diagnostic::AnalysisResult) -> proto::AnalysisResponse {
    proto::AnalysisResponse {
        findings: r.findings.iter().map(finding_to_proto).collect(),
        metrics: Some(module_metrics_to_proto(&r.metrics)),
    }
}

pub fn analysis_result_from_proto(
    r: &proto::AnalysisResponse,
) -> crate::error::Result<diagnostic::AnalysisResult> {
    let metrics = r
        .metrics
        .as_ref()
        .map(module_metrics_from_proto)
        .ok_or_else(|| {
            crate::error::ChaffraError::ProtoConversion(
                "AnalysisResponse is missing required metrics field".to_owned(),
            )
        })?;

    let findings: crate::error::Result<Vec<_>> =
        r.findings.iter().map(finding_from_proto).collect();

    Ok(diagnostic::AnalysisResult {
        findings: findings?,
        metrics,
    })
}

// --- Rule ---

pub fn rule_to_proto(r: &diagnostic::Rule) -> proto::RuleInfo {
    proto::RuleInfo {
        id: r.id.clone(),
        name: r.name.clone(),
        description: r.description.clone(),
        default_severity: severity_to_string(r.default_severity),
        category: r.category.clone(),
    }
}

pub fn rule_from_proto(r: &proto::RuleInfo) -> crate::error::Result<diagnostic::Rule> {
    Ok(diagnostic::Rule {
        id: r.id.clone(),
        name: r.name.clone(),
        description: r.description.clone(),
        default_severity: severity_from_string(&r.default_severity)?,
        category: r.category.clone(),
    })
}

// --- ModuleInfo ---

pub fn module_info_to_proto(info: &diagnostic::ModuleInfo) -> proto::ModuleInfo {
    proto::ModuleInfo {
        id: info.id.clone(),
        name: info.name.clone(),
        version: info.version.clone(),
        languages: info.languages.clone(),
        capabilities: info.capabilities.clone(),
        rules: info.rules.iter().map(rule_to_proto).collect(),
    }
}

pub fn module_info_from_proto(
    info: &proto::ModuleInfo,
) -> crate::error::Result<diagnostic::ModuleInfo> {
    let rules: crate::error::Result<Vec<_>> = info.rules.iter().map(rule_from_proto).collect();
    Ok(diagnostic::ModuleInfo {
        id: info.id.clone(),
        name: info.name.clone(),
        version: info.version.clone(),
        languages: info.languages.clone(),
        capabilities: info.capabilities.clone(),
        rules: rules?,
    })
}

// --- RuleExplanation ---

pub fn rule_explanation_to_proto(e: &diagnostic::RuleExplanation) -> proto::ExplainResponse {
    proto::ExplainResponse {
        rule_id: e.rule_id.clone(),
        name: e.name.clone(),
        description: e.description.clone(),
        rationale: e.rationale.clone(),
        default_severity: severity_to_string(e.default_severity),
        suppression_syntax: e.suppression_syntax.clone(),
        examples: e.examples.clone(),
    }
}

pub fn rule_explanation_from_proto(
    e: &proto::ExplainResponse,
) -> crate::error::Result<diagnostic::RuleExplanation> {
    Ok(diagnostic::RuleExplanation {
        rule_id: e.rule_id.clone(),
        name: e.name.clone(),
        description: e.description.clone(),
        rationale: e.rationale.clone(),
        default_severity: severity_from_string(&e.default_severity)?,
        suppression_syntax: e.suppression_syntax.clone(),
        examples: e.examples.clone(),
    })
}

// --- FixResult ---

pub fn fix_result_to_proto(r: &diagnostic::FixResult) -> proto::FixResult {
    proto::FixResult {
        rule_id: r.rule_id.clone(),
        applied: r.applied,
        edits: r.edits.iter().map(text_edit_to_proto).collect(),
        reason: r.reason.clone(),
    }
}

pub fn fix_result_from_proto(r: &proto::FixResult) -> diagnostic::FixResult {
    diagnostic::FixResult {
        rule_id: r.rule_id.clone(),
        applied: r.applied,
        edits: r.edits.iter().map(text_edit_from_proto).collect(),
        reason: r.reason.clone(),
    }
}
