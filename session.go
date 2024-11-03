package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var ErrAuth = errors.New("Unauthorized")

type RequestBody struct {
	Username string `json:"username"`
}

func Authorize(r *http.Request) (string, error) {
	var body RequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return "", ErrAuth
	}

	userName := body.Username
	user, ok := users[userName]
	if !ok {
		fmt.Println("User does not exist!")
		return "", ErrAuth
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		fmt.Println("Invalid session token!")
		return "", ErrAuth
	}

	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" || csrf != user.CSFRToken {
		fmt.Println("Invalid CSRF token!")
		return "", ErrAuth
	}

	return userName, nil
}
