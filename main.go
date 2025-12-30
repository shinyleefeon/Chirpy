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
	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		type paramaters struct {
			Body string `json:"body"`
		}
		params := paramaters{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}
		if len(params.Body) == 0 || len(params.Body) > 140 {
			w.WriteHeader(400)
			w.Write([]byte("Chirp must be between 1 and 140 characters\n"))
			return
		}
		type returnVals struct {
			CleanedBody string `json:"cleaned_body,omitempty"`
		}
		data, err := json.Marshal(returnVals{CleanedBody: censorBody(params.Body)})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(200)
		w.Write(data)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
		}
		params := parameters{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}
		user, err := apiCFG.database.CreateUser(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error creating user: %s", err)
			w.WriteHeader(500)
			return
		}
		respondWithJSON(w, 201, user)
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
	
	Server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	fmt.Printf("Starting server at dir %s\n", filepathRoot)
	Server.ListenAndServe()
}