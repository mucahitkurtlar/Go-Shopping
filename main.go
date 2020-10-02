package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"strconv"

	"./middleware"
	"./models"
	"./secrets"
	"./sessions"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var activeAdmin models.Admin
var activeUser models.User
var templates *template.Template

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/admin", middleware.AdminAuthRequired(adminIndexHandler))
	r.HandleFunc("/admin/login", adminLoginGetHandler).Methods("GET")
	r.HandleFunc("/admin/login", adminLoginPostHandler).Methods("POST")
	r.HandleFunc("/admin/register", adminRegisterGetHandler).Methods("GET")
	r.HandleFunc("/admin/register", adminRegisterPostHandler).Methods("POST")
	r.HandleFunc("/admin/forget-pass", adminForgetGetHandler).Methods("GET")
	r.HandleFunc("/admin/forget-pass", adminForgetPostHandler).Methods("POST")
	r.HandleFunc("/admin/logout", adminLogoutGetHandler).Methods("GET")
	r.HandleFunc("/admin/list-admin", middleware.AdminAuthRequired(adminListAdminHandler)).Methods("GET")

	r.HandleFunc("/register", registerGetHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	r.HandleFunc("/login", loginGetHandler).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/logout", logoutGetHandler).Methods("GET")

	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	fmt.Println("Hi!")
	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)

}

func adminIndexHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_index.html", activeAdmin)
}

func adminLoginGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_login.html", nil)
}

func adminLoginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	admin, err := models.GetAdmin(email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.Hash), []byte(password))
	if err != nil {
		log.Fatal(err)

	}
	fmt.Println("Login successful")
	session, err := sessions.Store.Get(r, "session")
	if err != nil {
		log.Fatal(err)
	}
	session.Values["admin_email"] = email
	fmt.Println(email)
	err = session.Save(r, w)
	if err != nil {
		log.Fatal(err)
	}
	activeAdmin, err = models.GetAdmin(email)
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, "/admin", 302)
}

func adminRegisterGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_register.html", nil)
}

func adminRegisterPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.PostForm.Get("name")
	surname := r.PostForm.Get("surname")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	cost := bcrypt.DefaultCost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		log.Fatal(err)

	}
	err = models.InsertAdmin(email, string(hash), name, surname)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}
	http.Redirect(w, r, "/admin/login", 302)
}

func adminForgetGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_forget-pass.html", nil)
}

func adminForgetPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.PostForm.Get("email")
	admin, err := models.GetAdmin(email)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Alzheimer admin id: " + strconv.Itoa(admin.ID))
	err = sendRecovery(email, strconv.Itoa(admin.ID))
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, "/admin/login", 302)
}

func adminLogoutGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessions.Store.Get(r, "session")
	session.Values["admin_email"] = ""
	err := session.Save(r, w)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, "/admin/login", 302)
}

func adminListAdminHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_list-admin.html", models.GetAdmins())
}

//*****************************************************************
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessions.Store.Get(r, "session")
	username, ok := session.Values["username"]
	fmt.Println(username, ok)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", 302)
		return
	}
	templates.ExecuteTemplate(w, "a.html", nil)
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_login.html", nil)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	user, err := models.GetUser(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(password))
	if err != nil {
		log.Fatal(err)

	}
	session, _ := sessions.Store.Get(r, "session")
	session.Values["username"] = username
	fmt.Println(username)
	session.Save(r, w)
	http.Redirect(w, r, "/", 302)
}

func registerGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.PostForm.Get("name")
	surname := r.PostForm.Get("surname")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	cost := bcrypt.DefaultCost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		log.Fatal(err)

	}
	err = models.InsertUser(email, string(hash), name, surname)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}
	http.Redirect(w, r, "/login", 302)

}

func logoutGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessions.Store.Get(r, "session")
	session.Values["username"] = ""
	err := session.Save(r, w)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, "/login", 302)
}

func sendRecovery(to, id string) error {
	fmt.Println("sendRecovery running..")
	msg := []byte("To:  " + to + "\r\n" +
		"Subject: Password Recovery\r\n" +
		"\r\n" +
		"Follow this link to reset your password: localhost:8080/admin/reset-pass?id=" + id + "\r\n")
	err := sendMail(to, msg)
	return err
}

func sendMail(to string, msg []byte) error {
	from := secrets.GetSMTPMail()
	pass := secrets.GetSMTPPass()
	auth := smtp.PlainAuth("", from, pass, "smtp.gmail.com")
	/*
		msg := []byte("To:  " + to + "\r\n" +
			"Subject: discount Gophers!\r\n" +
			"\r\n" +
			"This is the email body.\r\n")
	*/
	err := smtp.SendMail("smtp.gmail.com:587",
		auth,
		from, []string{to}, msg)

	return err
}
