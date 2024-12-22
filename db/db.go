package db

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type User struct {
	IP      string
	UserID  string `gorm:"primaryKey"`
	Refresh string
}

var (
	db *gorm.DB
)

func init() {
	dsn := "host=localhost user=postgres password=postgres database=medods"

	var err error
	db, err = gorm.Open(postgres.Open(dsn))
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(User{})
}

func SaveRefreshToken(user User) error {
	hashed := sha256.Sum256([]byte(user.Refresh))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])

	user.Refresh = encoded
	fmt.Println(encoded)

	r := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"refresh", "ip"}),
	}).Create(&user)

	return r.Error
}

func GetRefresh(uid string) (string, error) {
	var res User
	r := db.Model(&User{}).Where(&User{UserID: uid}).Find(&res)

	if r.Error != nil {
		if errors.Is(r.Error, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", r.Error
	}

	return res.Refresh, r.Error
}
