package middleware

import (
	"fmt"
	"net/http"

	"../sessions"
)

//AdminAuthRequired exported
func AdminAuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := sessions.Store.Get(r, "session")
		email, ok := session.Values["admin_email"]
		if !ok || email == "" {
			fmt.Println("Redireting to /admin/login")
			http.Redirect(w, r, "/admin/login", 302)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

//UserAuthRequired exported
func UserAuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := sessions.Store.Get(r, "session")
		email, ok := session.Values["user_email"]
		if !ok || email == "" {
			fmt.Println("Redireting to /login")
			http.Redirect(w, r, "/login", 302)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
