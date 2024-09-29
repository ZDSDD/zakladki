package users

type Permissions int

const (
	CanView   Permissions = 1 << iota // 1
	CanEdit                           // 2
	CanDelete                         // 4
	CanCreate                         // 8
)

type Role int

// Define constants for each role
const (
	Viewer    Role = Role(CanView)
	Moderator      = Role(CanView | CanEdit)
	Admin          = Role(CanView | CanEdit | CanDelete | CanCreate)
)

// Check if a role is valid
func IsValidRole(role Role) bool {
	switch role {
	case Admin, Moderator, Viewer:
		return true
	}
	return false
}

// Check if a role has a specific permission
func (r Role) HasPermission(p Permissions) bool {
	return int(r)&int(p) != 0
}
