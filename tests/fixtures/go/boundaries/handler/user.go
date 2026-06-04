package handler

import "myapp/service"

func GetUser(id string) string {
	return service.FindUser(id)
}
