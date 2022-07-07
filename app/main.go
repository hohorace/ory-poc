package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/hohorace/ory-poc/app/auth"
)

func main() {
	LoginFlowUrl := os.Getenv("KRATOS_UI_URL")
	KratosPublicUrl := os.Getenv("KRATOS_EXTERNAL_API_URL")
	KetoReadUrl := os.Getenv("KETO_API_READ_URL")
	port := os.Getenv("PORT")

	// all these routes are secure and will be checked for a validated session
	secureMux := mux.NewRouter()
	secureWrapper := auth.NewSecureWrapper(&auth.SecureWrapperConfig{
		LoginFlowUrl:    LoginFlowUrl,
		KratosPublicUrl: KratosPublicUrl,
		KetoReadUrl:     KetoReadUrl,
	})
	secureMux.Use(secureWrapper) // auth everything

	// api level handlers
	api := secureMux.PathPrefix("/api").Subrouter()
	api.HandleFunc("/data", protectedData)

	// this router will aggregate all subrouters, including secure and public routes
	r := mux.NewRouter()
	r.PathPrefix("/api").Handler(secureMux)

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

func protectedData(w http.ResponseWriter, r *http.Request) {
	pd := &ProtectedData{
		Foo: "bar",
	}

	data, err := json.Marshal(pd)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
