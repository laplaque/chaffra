//! Python framework detection: FastAPI, Django, Flask.
//!
//! Walks the tree-sitter AST looking for patterns specific to each framework:
//! - **FastAPI**: `@app.get("/path")`, `@app.post(...)` decorators
//! - **Django**: `path("url", view)` in URL patterns, class-based views
//! - **Flask**: `@app.route("/path")` decorators

use crate::detect::FrameworkEntry;
use tree_sitter::{Node, Tree};

/// HTTP method decorators used by FastAPI and Flask.
const ROUTE_DECORATORS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "route",
];

/// Detect Python framework entry points in a parsed tree.
pub fn detect_python_frameworks(tree: &Tree, source: &[u8], file: &str) -> Vec<FrameworkEntry> {
    let root = tree.root_node();
    let src = std::str::from_utf8(source).unwrap_or("");

    let mut entries = Vec::new();

    // Detect which frameworks are imported.
    let has_fastapi = src.contains("fastapi") || src.contains("FastAPI");
    let has_flask = src.contains("flask") || src.contains("Flask");
    let has_django = src.contains("django");

    walk_python_node(
        root,
        source,
        file,
        has_fastapi,
        has_flask,
        has_django,
        &mut entries,
    );

    entries
}

/// Recursively walk the AST for Python framework patterns.
fn walk_python_node(
    node: Node,
    source: &[u8],
    file: &str,
    has_fastapi: bool,
    has_flask: bool,
    has_django: bool,
    entries: &mut Vec<FrameworkEntry>,
) {
    // Check decorated function definitions for route patterns.
    if node.kind() == "decorated_definition" {
        check_decorated_definition(node, source, file, has_fastapi, has_flask, entries);
    }

    // Check function calls for Django URL patterns.
    if has_django && node.kind() == "call" {
        if let Some(entry) = check_django_url_pattern(node, source, file) {
            entries.push(entry);
        }
    }

    // Check class definitions for Django class-based views.
    if has_django && node.kind() == "class_definition" {
        if let Some(entry) = check_django_class_view(node, source, file) {
            entries.push(entry);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_python_node(
            child,
            source,
            file,
            has_fastapi,
            has_flask,
            has_django,
            entries,
        );
    }
}

/// Check a decorated definition for FastAPI/Flask route patterns.
///
/// Matches `@app.get("/path")` or `@router.post("/path")` style decorators.
fn check_decorated_definition(
    node: Node,
    source: &[u8],
    file: &str,
    has_fastapi: bool,
    has_flask: bool,
    entries: &mut Vec<FrameworkEntry>,
) {
    // Find all decorator nodes.
    let mut cursor = node.walk();
    let decorators: Vec<Node> = node
        .children(&mut cursor)
        .filter(|c| c.kind() == "decorator")
        .collect();

    // Find the function definition that follows.
    let mut cursor2 = node.walk();
    let func_def = node
        .children(&mut cursor2)
        .find(|c| c.kind() == "function_definition");

    let func_name = func_def.and_then(|f| {
        f.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(String::from)
    });

    for decorator in decorators {
        if let Some(entry) =
            check_route_decorator(decorator, source, file, has_fastapi, has_flask, &func_name)
        {
            entries.push(entry);
        }
    }
}

/// Check a single decorator for route pattern.
fn check_route_decorator(
    decorator: Node,
    source: &[u8],
    file: &str,
    has_fastapi: bool,
    has_flask: bool,
    func_name: &Option<String>,
) -> Option<FrameworkEntry> {
    // Decorator text typically starts with @.
    let dec_text = decorator.utf8_text(source).ok()?;

    // Match `@app.get(...)`, `@router.post(...)`, `@app.route(...)` etc.
    for method in ROUTE_DECORATORS {
        let pattern = format!(".{method}(");
        if dec_text.contains(&pattern) {
            let framework = if has_fastapi && *method != "route" {
                "fastapi"
            } else if has_flask {
                "flask"
            } else if has_fastapi {
                "fastapi"
            } else {
                continue;
            };

            let name = func_name
                .clone()
                .unwrap_or_else(|| format!("{method} handler"));

            return Some(FrameworkEntry {
                framework: framework.to_owned(),
                kind: "route".to_owned(),
                name,
                file: file.to_owned(),
                line: decorator.start_position().row as u32 + 1,
                confidence: 0.9,
            });
        }
    }

    None
}

/// Check a function call for Django URL pattern registration.
///
/// Matches `path("url/", view_func)` or `re_path(r"^url/$", view_func)`.
fn check_django_url_pattern(node: Node, source: &[u8], file: &str) -> Option<FrameworkEntry> {
    let func = node.child_by_field_name("function")?;
    let func_text = func.utf8_text(source).ok()?;

    if func_text != "path" && func_text != "re_path" {
        return None;
    }

    let args = node.child_by_field_name("arguments")?;
    // The view is typically the second argument.
    let view_arg = args.named_child(1)?;
    let view_text = view_arg.utf8_text(source).ok()?;

    // Skip if it looks like include() or similar.
    if view_text.contains("include(") {
        return None;
    }

    Some(FrameworkEntry {
        framework: "django".to_owned(),
        kind: "url-pattern".to_owned(),
        name: view_text.to_owned(),
        file: file.to_owned(),
        line: node.start_position().row as u32 + 1,
        confidence: 0.85,
    })
}

/// Check a class definition for Django class-based view pattern.
///
/// Matches classes that inherit from common Django view bases.
fn check_django_class_view(node: Node, source: &[u8], file: &str) -> Option<FrameworkEntry> {
    let name_node = node.child_by_field_name("name")?;
    let class_name = name_node.utf8_text(source).ok()?;

    // Look for superclass list.
    let superclasses = node.child_by_field_name("superclasses")?;
    let bases_text = superclasses.utf8_text(source).ok()?;

    let django_view_bases = [
        "View",
        "TemplateView",
        "ListView",
        "DetailView",
        "CreateView",
        "UpdateView",
        "DeleteView",
        "FormView",
        "APIView",
        "ModelViewSet",
        "ViewSet",
        "GenericAPIView",
    ];

    let is_view = django_view_bases
        .iter()
        .any(|base| bases_text.contains(base));

    if !is_view {
        return None;
    }

    Some(FrameworkEntry {
        framework: "django".to_owned(),
        kind: "view".to_owned(),
        name: class_name.to_owned(),
        file: file.to_owned(),
        line: node.start_position().row as u32 + 1,
        confidence: 0.85,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::Language;
    use chaffra_parse::parser;

    fn parse_python(source: &[u8]) -> Tree {
        parser::parse(source, Language::Python).unwrap()
    }

    #[test]
    fn test_detect_fastapi_get() {
        let source = br#"from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"msg": "hello"}
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "app.py");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].framework, "fastapi");
        assert_eq!(entries[0].kind, "route");
        assert_eq!(entries[0].name, "hello");
    }

    #[test]
    fn test_detect_fastapi_multiple_routes() {
        let source = br#"from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"msg": "hello"}

@app.post("/users")
def create_user():
    return {"msg": "created"}

@app.put("/users/{user_id}")
def update_user():
    return {"msg": "updated"}

@app.delete("/users/{user_id}")
def delete_user():
    return {"msg": "deleted"}
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "app.py");
        assert_eq!(entries.len(), 4, "should detect all 4 routes: {entries:?}");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hello"));
        assert!(names.contains(&"create_user"));
        assert!(names.contains(&"update_user"));
        assert!(names.contains(&"delete_user"));
    }

    #[test]
    fn test_detect_flask_route() {
        let source = br#"from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "hello"

@app.route("/about", methods=["GET"])
def about():
    return "about"
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "app.py");
        assert_eq!(entries.len(), 2, "should detect flask routes: {entries:?}");
        assert!(entries.iter().all(|e| e.framework == "flask"));
    }

    #[test]
    fn test_detect_flask_method_decorators() {
        let source = br#"from flask import Flask

app = Flask(__name__)

@app.get("/api/users")
def list_users():
    return []

@app.post("/api/users")
def create_user():
    return {}
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "app.py");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_detect_django_url_patterns() {
        let source = br#"from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("about/", views.about, name="about"),
]
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "urls.py");
        assert_eq!(
            entries.len(),
            2,
            "should detect Django URL patterns: {entries:?}"
        );
        assert!(entries.iter().all(|e| e.framework == "django"));
        assert!(entries.iter().all(|e| e.kind == "url-pattern"));
    }

    #[test]
    fn test_detect_django_class_view() {
        let source = br#"from django.views import View

class MyView(View):
    def get(self, request):
        return HttpResponse("hello")

class MyListView(ListView):
    model = MyModel
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "views.py");
        assert_eq!(
            entries.len(),
            2,
            "should detect Django class views: {entries:?}"
        );
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"MyView"));
        assert!(names.contains(&"MyListView"));
    }

    #[test]
    fn test_no_framework_plain_python() {
        let source = b"def hello():\n    print('hello')\n";
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "app.py");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_django_skip_include() {
        let source = br#"from django.urls import path, include

urlpatterns = [
    path("api/", include("api.urls")),
]
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "urls.py");
        // include() calls should be skipped.
        let url_entries: Vec<_> = entries.iter().filter(|e| e.kind == "url-pattern").collect();
        assert!(
            url_entries.is_empty(),
            "should skip include() URL patterns: {url_entries:?}"
        );
    }

    #[test]
    fn test_fastapi_router() {
        let source = br#"from fastapi import APIRouter

router = APIRouter()

@router.get("/items")
def list_items():
    return []

@router.post("/items")
def create_item():
    return {}
"#;
        let tree = parse_python(source);
        let entries = detect_python_frameworks(&tree, source, "routes.py");
        assert_eq!(
            entries.len(),
            2,
            "should detect FastAPI router routes: {entries:?}"
        );
    }
}
