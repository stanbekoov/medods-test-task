package main

import (
	"medods-test/handlers"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load()
	// db.Init()
}

func main() {
	router := gin.Default()

	router.GET("/a", handlers.GetTokens)
	router.GET("/r", handlers.RefreshTokens)

	router.Run(":" + os.Getenv("PORT"))
}
