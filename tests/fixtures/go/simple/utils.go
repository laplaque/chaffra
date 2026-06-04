package main

// chaffra:ignore unused-function
func suppressedFunc() {
	// This should not be flagged due to suppression.
}

func OrphanFunc() {
	// This is exported but in main package, so it's alive.
}
