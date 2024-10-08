package main

import (
	_ "backend/cmd/api/docs"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
)

func (app *application) routes() http.Handler {
	// Create Router mux
	mux := chi.NewRouter()

	// Add middleware
	mux.Use(middleware.Recoverer)
	mux.Use(app.enableCORS)

	// Register Swagger
	mux.Get("/swagger/*", httpSwagger.WrapHandler)

	// Register the API routes to "api/vi"
	mux.Route("/api/v1", func(r chi.Router) {

		//Adding routes

		// Public Route
		r.Get("/", app.Home)
		r.Get("/hello", app.Hello)
		r.Get("/about", app.About)

		// Authenticate route
		r.Post("/login", app.login)
		r.Get("/refresh", app.refreshToken)
		r.Get("/logout", app.logout)

		// Protected Route
		r.With(app.jwtMiddleware).Get("/admin/movies", app.MovieCatalog)
		r.With(app.jwtMiddleware).Get("/admin/movies/{id}", app.MovieForEdit)
		r.With(app.jwtMiddleware).Post("/admin/movies", app.InsertMovie)
		r.With(app.jwtMiddleware).Put("/admin/movies/{id}", app.UpdateMovie)
		r.With(app.jwtMiddleware).Delete("/admin/movies/{id}", app.DeleteMovie)

		r.Get("/movies", app.AllMovies)
		r.Get("/movies/{id}", app.GetMovie)
		r.Get("/genres", app.ALLGenres)

		// Admin Route
		r.Route("/admin", func(r chi.Router) {
			r.Use(app.authRequired)
			r.Get("/movies", app.MovieCatalog)
			r.Get("/movies/{id}", app.MovieForEdit)
			r.Post("/movies", app.InsertMovie)
			r.Put("/movies/{id}", app.UpdateMovie)
			r.Delete("/movies/{id}", app.DeleteMovie)

		})
	})
	return mux
}
