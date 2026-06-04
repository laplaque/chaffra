package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func sqlInjection(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}

func commandInjection(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command(cmd)
}

func xssVuln(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func ssrfVuln(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	http.Get(url)
}

func pathTraversal(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("file")
	os.Open(path)
}
