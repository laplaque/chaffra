package domain

// User is a core domain entity.
type User struct {
    ID   int
    Name string
}

// NewUser creates a domain user.
func NewUser(id int, name string) User {
    return User{ID: id, Name: name}
}
