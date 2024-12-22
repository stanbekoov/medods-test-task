package handlers

import (
	"log"
	"medods-test/auth"
	"medods-test/db"
	"medods-test/mail"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func GetTokens(c *gin.Context) {
	userID, exists := c.GetQuery("guid")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no user ID provided"})
		return
	}

	ip := c.ClientIP()

	sessionId := uuid.New().String()

	accessToken, refreshToken, err := auth.CreateTokenPair(userID, ip, sessionId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	err = db.SaveRefreshToken(db.User{UserID: userID, Refresh: refreshToken, IP: ip})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"access": accessToken, "refresh": refreshToken})
}

func RefreshTokens(c *gin.Context) {
	userID, exists := c.GetQuery("guid")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no user ID provided"})
		return
	}

	accessToken, err := c.Cookie("access")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	refreshToken, err := c.Cookie("refresh")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	ip := c.ClientIP()

	access, err := auth.ParseToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}
	if !access.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "malformed access token"})
	}

	oldIp := access.Claims.(*auth.Claims).IP
	if ip != oldIp {
		mail.Notify(userID)
	}

	if exp, _ := access.Claims.GetExpirationTime(); exp.After(time.Now()) {
		c.JSON(http.StatusOK, gin.H{"access": accessToken, "refresh": refreshToken})
		return
	}

	ok, err := auth.VerifyRefreshToken(refreshToken, userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad refresh token"})
		return
	}

	refresh, err := auth.ParseToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	if !refresh.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad refresh token"})
		return
	}

	accessToken, refreshToken, err = auth.RefreshTokenPair(access, refresh, userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"access": accessToken, "refresh": refreshToken})
}
