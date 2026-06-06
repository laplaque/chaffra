package presentation

import "example.com/app/infrastructure"

// Handler is an HTTP handler that incorrectly imports from infrastructure.
// In a layered architecture, presentation should go through application, not
// directly to infrastructure.
type Handler struct {
    repo infrastructure.UserRepo
}
