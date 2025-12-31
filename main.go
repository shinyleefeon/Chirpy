package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"strings"
	"database/sql"
	"os"
	"github.com/shinyleefeon/Chirpy.git/internal/database"
	"github.com/joho/godotenv"
	"github.com/google/uuid"
	"time"
	"github.com/shinyleefeon/Chirpy.git/internal/auth"
)

import _ "github.com/lib/pq"

type apiConfig struct {
	fileserverHits atomic.Int32
	database	  *database.Queries
	platform	  string
}

type User struct {
	ID    uuid.UUID  `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email string `json:"email"`
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func censorBody(body string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	censored := strings.Split(body, " ")
	for _, badWord := range badWords {
		for i, word := range censored {
			if strings.ToLower(word) == badWord {
				censored[i] = "****"
			}
		}
	}
	result := strings.Join(censored, " ")
	return result
}

func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(message + "\n"))
}

func respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error marshalling JSON")
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write(data)
}

func main() {
	apiCFG := &apiConfig{}
	godotenv.Load()
	apiCFG.platform = os.Getenv("PLATFORM")
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error connecting to database: %s", err)
	}
	defer db.Close()
	dbQueries := database.New(db)
	apiCFG.database = dbQueries
	const filepathRoot = "."
	
	mux := http.NewServeMux()
	mux.Handle("/app/", apiCFG.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type paramaters struct {
			Body string `json:"body"`
			UserID uuid.UUID `json:"user_id"`
		}
		params := paramaters{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(400)
			return
		}
		if len(params.Body) == 0 || len(params.Body) > 140 {
			w.WriteHeader(400)
			w.Write([]byte("Chirp must be between 1 and 140 characters\n"))
			return
		}
		type returnVals struct {
			ID          uuid.UUID `json:"id,omitempty"`
			CleanedBody string `json:"body,omitempty"`
			UserID      uuid.UUID `json:"user_id,omitempty"`
			CreatedAt   time.Time `json:"created_at,omitempty"`
			UpdatedAt   time.Time `json:"updated_at,omitempty"`
			
		}
		chirp, err := apiCFG.database.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   censorBody(params.Body),
			UserID: params.UserID,
		})
		if err != nil {
			log.Printf("Error creating chirp: %s", err)
			w.WriteHeader(500)
			return
		}
		data, err := json.Marshal(returnVals{CleanedBody: chirp.Body, UserID: chirp.UserID, ID: chirp.ID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(201)
		w.Write(data)
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := apiCFG.database.ListChirps(r.Context())
		if err != nil {
			log.Printf("Error listing chirps: %s", err)
			w.WriteHeader(500)
			return
		}
		type responseVal struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}
		responseChirps := make([]responseVal, len(chirps))
		for i, chirp := range chirps {
			responseChirps[i] = responseVal{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			}
		}
		respondWithJSON(w, 200, responseChirps)
	})

	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpIDStr := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
		chirpID, err := uuid.Parse(chirpIDStr)
		if err != nil {
			log.Printf("Error parsing chirp ID: %s", err)
			w.WriteHeader(400)
			return
		}
		chirp, err := apiCFG.database.GetChirpByID(r.Context(), chirpID)
		
		if chirp.ID == uuid.Nil || err == sql.ErrNoRows {
			w.WriteHeader(404)
			w.Write([]byte("Chirp not found\n"))
			return
		}
		if err != nil {
			log.Printf("Error getting chirp by ID: %s", err)
			w.WriteHeader(500)
			return
		}

		type responseVal struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}
		respondWithJSON(w, 200, responseVal{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
			Password string `json:"password"`
		}
		params := parameters{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}
		hashed, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			return
		}
		user, err := apiCFG.database.CreateUser(r.Context(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashed,
		})
		if err != nil {
			log.Printf("Error creating user: %s", err)
			w.WriteHeader(500)
			return
		}
		type responseVal struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
		}
		respondWithJSON(w, 201, responseVal{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		})
	})

	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, apiCFG.fileserverHits.Load())))
	})

	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		apiCFG.fileserverHits.Store(0)
		apiCFG.database.DeleteUsers(r.Context())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Metrics and users reset\n"))
	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		params := parameters{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}
		user, err := apiCFG.database.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error getting user by email: %s", err)
			w.WriteHeader(401)
			return
		}
		match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil || !match {
			log.Printf("Invalid password for user %s", params.Email)
			w.WriteHeader(401)
			return
		}
		type responseVal struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
		}
		respondWithJSON(w, 200, responseVal{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		})
	})

	Server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	fmt.Printf("Starting server at dir %s\n", filepathRoot)
	Server.ListenAndServe()
}