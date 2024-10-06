package main

import (
	"backend/internal/repository"
	"backend/internal/repository/dbrepo"
	"flag"
	"fmt"
	// "github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"time"
)

const port = 8080

// Create Application Struct to store configuration
type application struct {
	Domain       string
	DSN          string
	DB           repository.DatabaseRepo
	auth         Auth
	JWTSecret    string
	JWTIssuer    string
	JWTAudience  string
	CookieDomain string
	APIKey       string
}

// @title Movies API with Go and PostgreSQL
// @version 1.0
// @description This is a Movies API with GO and PostgreSQL
// @termOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://swagger.io/support
// @contact.email support@swaager.import
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// set application config
	var app application
	app.Domain = "example.com"

	// Load values from .env
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatal("Error loading .env file")
	// }
	// Read from command line argument

	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s timezone=%s connect_timeout=%s",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"), os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"), os.Getenv("DB_SSLMODE"),
		os.Getenv("DB_TIMEZONE"), os.Getenv("DB_CONNECT_TIMEOUT"),
	)
	app.DSN = dsn

	// Parse command line argument for JWT

	app.JWTSecret = os.Getenv("JWT_SECRET")
	app.JWTIssuer = os.Getenv("JWT_ISSUER")
	app.JWTAudience = os.Getenv("JWT_AUDIENCE")
	app.CookieDomain = os.Getenv("COOKIE_DOMAIN")
	app.Domain = os.Getenv("DOMAIN")
	app.APIKey = os.Getenv("API_KEY")

	flag.Parse()

	// Connect to database
	conn, err := app.connectToDB()

	if err != nil {
		log.Fatal(err)
	}
	app.DB = &dbrepo.PostgresDBRepo{
		DB: conn,
	}

	// Close the database before the main() function exists
	defer app.DB.Connection().Close()

	// Set Auth
	app.auth = Auth{
		Issuer:        app.JWTIssuer,
		Audience:      app.JWTAudience,
		Secret:        app.JWTSecret,
		TokenExpiry:   time.Minute * 15,
		RefreshExpiry: time.Hour * 24,
		CookiePath:    "/",
		CookieName:    "__Host-refresh_token",
		CookieDomain:  app.CookieDomain,
	}
	// Start server
	fmt.Printf("Domain name: %s\n", app.Domain)
	fmt.Printf("Link --> %s:%d\n", app.Domain, port)
	log.Printf("Starting server on port %d\n", port)

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), app.routes())
	if err != nil {
		log.Fatal(err)
	}
}
