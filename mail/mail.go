package mail

import (
	"log"
	"net/smtp"
	"os"
)

var (
	from, password, host, port string
)

func init() {
	from = os.Getenv("EMAIL_USER")
	password = os.Getenv("EMAIL_PASS")
	host = os.Getenv("EMAIL_HOST")
	port = os.Getenv("EMAIL_PORT")
}

func Notify(uid string) {
	//В будущем предпологается получение адреса по userID
	email := "stanbekov05@gmail.com"

	msg := "Вход с неизвестного IP адреса"

	auth := smtp.PlainAuth("", from, password, host)
	err := smtp.SendMail(host+":"+port, auth, from, []string{email}, []byte(msg))

	if err != nil {
		log.Println(err)
	}
}
