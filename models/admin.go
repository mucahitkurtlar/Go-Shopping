package models

import (
	"log"

	"../dbconn"
)

//Admin exported
type Admin struct {
	ID      int
	Email   string
	Hash    string
	Name    string
	Surname string
}

//GetAdmin exported
func GetAdmin(email string) (Admin, error) {
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

		admin.ID = adminID
		admin.Email = adminEmail
		admin.Hash = adminHash
		admin.Name = adminName
		admin.Surname = adminSurname
	}
	return admin, nil
}

//GetAdmins exported
func GetAdmins() []Admin {
	db, err := dbconn.NewDB()
	if err != nil {
		log.Fatal(err)
	}
	selDB, err := db.Query("SELECT * FROM admins")
	if err != nil {
		panic(err.Error())
	}

	admin := Admin{}
	admins := []Admin{}

	for selDB.Next() {

		var adminID int
		var adminEmail, adminHash, adminName, adminSurname string

		err = selDB.Scan(&adminID, &adminEmail, &adminHash, &adminName, &adminSurname)
		if err != nil {
			panic(err.Error())
		}

		admin.ID = adminID
		admin.Email = adminEmail
		admin.Hash = adminHash
		admin.Name = adminName
		admin.Surname = adminSurname
		admins = append(admins, admin)
	}
	return admins
}
