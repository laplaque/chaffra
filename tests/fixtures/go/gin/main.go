package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/ping", pingHandler)
	r.POST("/users", createUserHandler)
	r.PUT("/users/:id", updateUserHandler)
	r.DELETE("/users/:id", deleteUserHandler)

	api := r.Group("/api")
	api.GET("/items", listItemsHandler)

	r.Run(":8080")
}

func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func createUserHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "created"})
}

func updateUserHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func deleteUserHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func listItemsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": []string{}})
}

func unusedHelper() string {
	return "not called anywhere"
}
