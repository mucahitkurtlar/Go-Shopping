package models

import (
	"log"

	"../dbconn"
)

//User exported
type User struct {
	ID      int
	Email   string
	Hash    string
	Name    string
	Surname string
}

//GetUsers exported
func GetUsers() []User {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	selDB, err := db.Query("SELECT * FROM users")
	if err != nil {
		panic(err.Error())
	}

	user := User{}
	users := []User{}

	for selDB.Next() {

		var userID int
		var userEmail, userHash, userName, userSurname string

		err = selDB.Scan(&userID, &userEmail, &userHash, &userName, &userSurname)
		if err != nil {
			panic(err.Error())
		}

		user.ID = userID
		user.Email = userEmail
		user.Hash = userHash
		user.Name = userName
		user.Surname = userSurname
		users = append(users, user)
	}
	return users
}

//GetUser exported
func GetUser(username string) (User, error) {
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

		var userID int
		var userEmail, userHash, userName, userSurname string

		err = selDB.Scan(&userID, &userEmail, &userHash, &userName, &userSurname)
		if err != nil {
			panic(err.Error())
		}

		user.ID = userID
		user.Email = userEmail
		user.Hash = userHash
		user.Name = userName
		user.Surname = userSurname
	}
	return user, nil
}
