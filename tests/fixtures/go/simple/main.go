package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("hello")
	helper()
}

func helper() {
	fmt.Println("helper")
}

func unused() {
	fmt.Println("never called")
}

type UsedType struct {
	Name string
}

type UnusedType struct {
	Value int
}
