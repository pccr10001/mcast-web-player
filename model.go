package main

type LoginRequest struct {
	IdToken string `json:"idToken"`
}

type User struct {
	Name  string `json:"name" yaml:"name"`
	Email string `json:"email" yaml:"email"`
}

type Channel struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
	Url  string `json:"-"`
}
