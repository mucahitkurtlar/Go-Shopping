package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"./dbconn"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

//User ..
type User struct {
	UserID   int
	Username string
	UserHash string
}

//Admin ..
type Admin struct {
	AdminID      int
	AdminEmail   string
	AdminHash    string
	AdminName    string
	AdminSurname string
}

var activeAdmin Admin
var activeUser User
var templates *template.Template
var store = sessions.NewCookieStore([]byte("t0p-s3cr3t"))

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/admin", adminIndexHandler)
	r.HandleFunc("/admin/login", adminLoginGetHandler).Methods("GET")
	r.HandleFunc("/admin/login", adminLoginPostHandler).Methods("POST")
	r.HandleFunc("/admin/register", adminRegisterGetHandler).Methods("GET")
	r.HandleFunc("/admin/register", adminRegisterPostHandler).Methods("POST")
	r.HandleFunc("/admin/logout", adminLogoutGetHandler).Methods("GET")

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
	session, _ := store.Get(r, "session")
	email, ok := session.Values["admin_email"]
	fmt.Println(email, ok)
	if !ok || email == "" {
		fmt.Println("Redireting to /admin/login")
		http.Redirect(w, r, "/admin/login", 302)
		return
	}
	templates.ExecuteTemplate(w, "admin_index.html", activeAdmin)
}

func adminLoginGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin_login.html", nil)
}

func adminLoginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	admin, err := getActiveAdmin(email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.AdminHash), []byte(password))
	if err != nil {
		log.Fatal(err)

	}
	fmt.Println("Login successful")
	session, err := store.Get(r, "session")
	if err != nil {
		log.Fatal(err)
	}
	session.Values["admin_email"] = email
	fmt.Println(email)
	err = session.Save(r, w)
	if err != nil {
		log.Fatal(err)
	}
	activeAdmin, err = getActiveAdmin(email)
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
	insertAdmin(email, string(hash), name, surname)
	http.Redirect(w, r, "/admin/login", 302)

}

func adminLogoutGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["admin_email"] = ""
	err := session.Save(r, w)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, "/admin/login", 302)
}

//*****************************************************************
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
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
	hash, err := getHash(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error!"))
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Fatal(err)

	}
	session, _ := store.Get(r, "session")
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
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	cost := bcrypt.DefaultCost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		log.Fatal(err)

	}
	insertUser(username, string(hash))
	http.Redirect(w, r, "/login", 302)

}

func logoutGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["username"] = ""
	err := session.Save(r, w)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, "/login", 302)
}

func insertUser(username, hash string) error {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	sqlStr := "INSERT INTO users(username, user_hash) VALUES(?,?)"
	insertQuery, err := db.Prepare(sqlStr)
	if err != nil {
		log.Fatal(err)
	}

	_, err = insertQuery.Exec(username, hash)
	if err != nil {
		panic(err)
	}
	return nil
}

func insertAdmin(email, hash, name, surname string) error {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	sqlStr := "INSERT INTO admins(admin_email, admin_hash, admin_name, admin_surname) VALUES(?,?,?,?)"
	insertQuery, err := db.Prepare(sqlStr)
	if err != nil {
		log.Fatal(err)
	}

	_, err = insertQuery.Exec(email, hash, name, surname)
	if err != nil {
		panic(err)
	}
	return nil
}

func getActiveAdmin(email string) (Admin, error) {
	/*
		AdminID int
		AdminEmail string
		AdminHash string
		AdminName string
		AdminSurname string
	*/

	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	selDB, err := db.Query("SELECT * FROM admins WHERE admin_email=?", email)
	if err != nil {
		panic(err.Error())
	}

	admin := Admin{}

	for selDB.Next() {

		var adminID int
		var adminEmail, adminHash, adminName, adminSurname string

		err = selDB.Scan(&adminID, &adminEmail, &adminHash, &adminName, &adminSurname)
		if err != nil {
			panic(err.Error())
		}

		admin.AdminID = adminID
		admin.AdminEmail = adminEmail
		admin.AdminHash = adminHash
		admin.AdminName = adminName
		admin.AdminSurname = adminSurname
	}
	return admin, nil
}

func getActiveUser(username string) (User, error) {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	selDB, err := db.Query("SELECT * FROM users WHERE username=?", username)
	if err != nil {
		panic(err.Error())
	}

	user := User{}

	for selDB.Next() {

		var id int
		var userName, hash string

		err = selDB.Scan(&id, &userName, &hash)
		if err != nil {
			panic(err.Error())
		}

		user.UserID = id
		user.Username = userName
		user.UserHash = hash
	}
	return user, nil
}

func getHash(username string) (string, error) {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	selDB, err := db.Query("SELECT * FROM users WHERE username=?", username)
	if err != nil {
		panic(err.Error())
	}

	user := User{}

	for selDB.Next() {

		var id int
		var userName, hash string

		err = selDB.Scan(&id, &userName, &hash)
		if err != nil {
			panic(err.Error())
		}

		user.UserID = id
		user.Username = userName
		user.UserHash = hash
	}
	fmt.Println("User hash: " + user.UserHash)
	return user.UserHash, nil
}
