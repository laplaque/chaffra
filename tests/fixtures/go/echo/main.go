package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.GET("/hello", helloHandler)
	e.POST("/users", createHandler)
	e.PUT("/users/:id", updateHandler)

	e.Start(":8080")
}

func helloHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"msg": "hello"})
}

func createHandler(c echo.Context) error {
	return c.JSON(http.StatusCreated, map[string]string{"msg": "created"})
}

func updateHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"msg": "updated"})
}
