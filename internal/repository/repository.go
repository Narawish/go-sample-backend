package repository

import (
	"backend/internal/models"
	"database/sql"
)

type DatabaseRepo interface {
	Connection() *sql.DB // Connect to db

	GetUserByEmail(email string) (*models.User, error) // get user using email
	GetUserByID(id int) (*models.User, error)          // get user using id

	AllMovies() ([]*models.Movie, error) // Access all movies

	OneMovie(id int) (*models.Movie, error)
	OneMovieForEdit(id int) (*models.Movie, []*models.Genre, error)
	AllGenres() ([]*models.Genre, error)
	InsertMovie(movie models.Movie) (int, error)
	UpdateMovie(movie models.Movie) error
	UpdateMovieGenres(id int, genresID []int) error
	DeleteMovie(id int) error
}
