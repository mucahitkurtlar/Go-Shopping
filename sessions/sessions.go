package sessions

import (
	"../secrets"
	"github.com/gorilla/sessions"
)

//Store exported
var Store = sessions.NewCookieStore(secrets.GetKeyPair())
