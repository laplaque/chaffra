package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}

func safeExec(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("echo", "hello")
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}
