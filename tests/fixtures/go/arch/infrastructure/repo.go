package infrastructure

import "example.com/app/domain"

// UserRepo persists users to a database.
type UserRepo struct{}

// Save stores a user entity.
func (r *UserRepo) Save(u domain.User) error {
    return nil
}
