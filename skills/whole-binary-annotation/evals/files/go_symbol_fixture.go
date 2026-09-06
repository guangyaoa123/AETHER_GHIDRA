package main

import (
	"fmt"
	"os"
	"strings"
)

type Session struct {
	User       string
	Requests   uint64
	Authorized bool
}

func (session *Session) Authorize(token string) bool {
	session.Requests++
	session.Authorized = strings.HasPrefix(token, "token:")
	return session.Authorized
}

func renderGreeting(session *Session) string {
	if !session.Authorized {
		return "access denied"
	}
	return "hello " + session.User
}

func main() {
	user := "guest"
	token := "invalid"
	if len(os.Args) > 2 {
		user = os.Args[1]
		token = os.Args[2]
	}
	session := &Session{User: user}
	session.Authorize(token)
	fmt.Println(renderGreeting(session))
}
