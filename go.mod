module github.com/the-muppet/mtgban-auth

go 1.21

require (
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/the-muppet/mtgban-auth/pkg/auth v0.0.0
	github.com/the-muppet/mtgban-auth/pkg/authclient v0.0.0
	github.com/the-muppet/mtgban-auth/pkg/middleware v0.0.0
)

replace github.com/the-muppet/mtgban-auth/pkg/auth => ./pkg/auth
replace github.com/the-muppet/mtgban-auth/pkg/authclient => ./pkg/authclient
replace github.com/the-muppet/mtgban-auth/pkg/middleware => ./pkg/middleware
