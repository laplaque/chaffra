//! Tarjan's strongly connected components algorithm for circular dependency detection.

use chaffra_parse::graph::ImportGraph;
use std::collections::HashMap;

/// Build an adjacency list from the import graph.
///
/// Edges are: file A -> file B if A imports a path that matches B.
pub fn build_adjacency(graph: &ImportGraph) -> HashMap<String, Vec<String>> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();

    // Initialize all nodes.
    for file in graph.nodes.keys() {
        adj.entry(file.clone()).or_default();
    }

    // Build edges from imports.
    for node in graph.nodes.values() {
        for imp in &node.imports {
            for target_file in graph.nodes.keys() {
                if *target_file == node.file {
                    continue;
                }
                // Heuristic: match import path to target file.
                let target_base = target_file
                    .trim_end_matches(".go")
                    .trim_end_matches(".py")
                    .trim_end_matches(".js")
                    .trim_end_matches(".ts")
                    .trim_end_matches(".tsx")
                    .trim_end_matches(".jsx")
                    .trim_end_matches(".java");
                if target_file.contains(&imp.path) || imp.path.contains(target_base) {
                    adj.entry(node.file.clone())
                        .or_default()
                        .push(target_file.clone());
                }
            }
        }
    }

    adj
}

/// Run Tarjan's SCC algorithm on the adjacency list.
///
/// Returns all strongly connected components with more than one node
/// (i.e., actual cycles).
pub fn tarjan_scc(adj: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut state = TarjanState {
        index: 0,
        stack: Vec::new(),
        on_stack: HashMap::new(),
        indices: HashMap::new(),
        lowlinks: HashMap::new(),
        sccs: Vec::new(),
    };

    for node in adj.keys() {
        if !state.indices.contains_key(node) {
            strongconnect(node, adj, &mut state);
        }
    }

    // Filter to only SCCs with > 1 node (actual cycles).
    state.sccs.into_iter().filter(|scc| scc.len() > 1).collect()
}

struct TarjanState {
    index: u32,
    stack: Vec<String>,
    on_stack: HashMap<String, bool>,
    indices: HashMap<String, u32>,
    lowlinks: HashMap<String, u32>,
    sccs: Vec<Vec<String>>,
}

fn strongconnect(v: &str, adj: &HashMap<String, Vec<String>>, state: &mut TarjanState) {
    state.indices.insert(v.to_owned(), state.index);
    state.lowlinks.insert(v.to_owned(), state.index);
    state.index += 1;
    state.stack.push(v.to_owned());
    state.on_stack.insert(v.to_owned(), true);

    if let Some(neighbors) = adj.get(v) {
        for w in neighbors {
            if !state.indices.contains_key(w) {
                strongconnect(w, adj, state);
                let low_w = state.lowlinks[w];
                let low_v = state.lowlinks[v];
                state.lowlinks.insert(v.to_owned(), low_v.min(low_w));
            } else if state.on_stack.get(w).copied().unwrap_or(false) {
                let idx_w = state.indices[w];
                let low_v = state.lowlinks[v];
                state.lowlinks.insert(v.to_owned(), low_v.min(idx_w));
            }
        }
    }

    if state.lowlinks[v] == state.indices[v] {
        let mut scc = Vec::new();
        loop {
            let w = state.stack.pop().unwrap();
            state.on_stack.insert(w.clone(), false);
            scc.push(w.clone());
            if w == v {
                break;
            }
        }
        state.sccs.push(scc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_cycle() {
        let adj = HashMap::from([
            ("a".to_owned(), vec!["b".to_owned()]),
            ("b".to_owned(), vec!["c".to_owned()]),
            ("c".to_owned(), vec!["a".to_owned()]),
        ]);
        let sccs = tarjan_scc(&adj);
        assert_eq!(sccs.len(), 1, "should find one SCC");
        assert_eq!(sccs[0].len(), 3, "SCC should have 3 nodes");
    }

    #[test]
    fn test_no_cycle() {
        let adj = HashMap::from([
            ("a".to_owned(), vec!["b".to_owned()]),
            ("b".to_owned(), vec!["c".to_owned()]),
            ("c".to_owned(), vec![]),
        ]);
        let sccs = tarjan_scc(&adj);
        assert!(sccs.is_empty(), "DAG should have no multi-node SCCs");
    }

    #[test]
    fn test_self_loop() {
        let adj = HashMap::from([("a".to_owned(), vec!["a".to_owned()])]);
        let sccs = tarjan_scc(&adj);
        // A self-loop is a single-node SCC which we filter out.
        // However, with our filter (len > 1), self-loops are excluded.
        // This is intentional: self-imports are not meaningful cycles.
        assert!(sccs.is_empty(), "self-loop should not be reported as cycle");
    }

    #[test]
    fn test_two_cycles() {
        let adj = HashMap::from([
            ("a".to_owned(), vec!["b".to_owned()]),
            ("b".to_owned(), vec!["a".to_owned()]),
            ("c".to_owned(), vec!["d".to_owned()]),
            ("d".to_owned(), vec!["c".to_owned()]),
        ]);
        let sccs = tarjan_scc(&adj);
        assert_eq!(sccs.len(), 2, "should find two SCCs");
    }

    #[test]
    fn test_empty_graph() {
        let adj: HashMap<String, Vec<String>> = HashMap::new();
        let sccs = tarjan_scc(&adj);
        assert!(sccs.is_empty());
    }

    #[test]
    fn test_disconnected_nodes() {
        let adj = HashMap::from([
            ("a".to_owned(), vec![]),
            ("b".to_owned(), vec![]),
            ("c".to_owned(), vec![]),
        ]);
        let sccs = tarjan_scc(&adj);
        assert!(sccs.is_empty(), "disconnected nodes have no cycles");
    }
}
