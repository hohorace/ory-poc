package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/hohorace/ory-poc/auth"
	kratos "github.com/ory/kratos-client-go"
)

func main() {
	kratosPublicUrl := os.Getenv("KRATOS_EXTERNAL_API_URL")
	ketoReadUrl := os.Getenv("KETO_API_READ_URL")
	port := os.Getenv("PORT")

	secureWrapper, loginHandler := auth.NewWebMiddleware(&auth.MiddlewareConfig{
		KratosPublicUrl: kratosPublicUrl,
		KetoReadUrl:     ketoReadUrl,
	})

	// all these routes are secure and will be checked for a validated session
	secureMux := mux.NewRouter()
	secureMux.Use(secureWrapper) // auth everything

	// api level handlers
	api := secureMux.PathPrefix("/api").Subrouter()
	api.HandleFunc("/session", sessionHandler)
	api.HandleFunc("/data", dataHandler)
	api.HandleFunc("/secret", secretHandler)

	// this router will aggregate all subrouters, including secure and public routes
	r := mux.NewRouter()
	r.PathPrefix("/api").Handler(secureMux)
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.PathPrefix("/").Handler(nocache(http.FileServer(http.Dir("static/"))))

	// create a server object
	s := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}

	fmt.Printf("starting server on :%s\n", port)
	panic(s.ListenAndServe())
}

type ProtectedData struct {
	Foo string `json:"foo"`
}

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*kratos.Session)

	data, err := json.Marshal(session)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	data := `{"foo": "bar"}`
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func secretHandler(w http.ResponseWriter, r *http.Request) {
	data := `{"secret": "secret"}`
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func nocache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}
