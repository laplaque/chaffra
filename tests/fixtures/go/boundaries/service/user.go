package service

import "myapp/repo"

func FindUser(id string) string {
	return repo.GetByID(id)
}
