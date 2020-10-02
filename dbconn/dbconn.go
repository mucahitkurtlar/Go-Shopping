package dbconn

import (
	"database/sql"

	"../secrets"
)

//NewDB exported
func NewDB() (db *sql.DB, err error) {

	dbDriver := "mysql"
	dbUser := secrets.GetDBUsername()
	dbPass := secrets.GetDBPass()
	dbName := secrets.GetDBName()
	db, err = sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	return
}
