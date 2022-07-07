package auth

import (
	"context"
	"fmt"
	"net/http"

	keto "github.com/ory/keto-client-go"
	kratos "github.com/ory/kratos-client-go"
)

type SecureWrapperConfig struct {
	LoginFlowUrl    string
	KratosPublicUrl string
	KetoReadUrl     string
}

func NewSecureWrapper(config *SecureWrapperConfig) func(handler http.Handler) http.Handler {
	kratosConfig := kratos.NewConfiguration()
	kratosConfig.Servers = []kratos.ServerConfiguration{{URL: config.KratosPublicUrl}}
	kratos := kratos.NewAPIClient(kratosConfig)

	ketoConfig := keto.NewConfiguration()
	ketoConfig.Servers = []keto.ServerConfiguration{{URL: config.KetoReadUrl}}
	keto := keto.NewAPIClient(ketoConfig)

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.Background()

			// Authentication
			cookie, err := r.Cookie("ory_kratos_session")
			if err != nil {
				http.Redirect(w, r, config.LoginFlowUrl, http.StatusTemporaryRedirect)
				return
			}

			session, resp, err := kratos.V0alpha2Api.ToSession(ctx).Cookie(fmt.Sprintf("ory_kratos_session=%s", cookie.Value)).Execute()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error when calling `V0alpha2Api.ToSession``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
				return
			}

			if !session.GetActive() {
				http.Error(w, "Identity not active", http.StatusUnauthorized)
				return
			}

			traits := session.Identity.GetTraits().(map[string]interface{})

			// Authoirsation
			namespace := "app"
			object := r.URL.Path
			relation := r.Method
			subjectId := traits["role"].(string)

			fmt.Printf("path: %s\n", object)

			check, resp, err := keto.ReadApi.GetCheck(ctx).Namespace(namespace).Object(object).Relation(relation).SubjectId(subjectId).Execute()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error when calling `ReadApi.GetCheck``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
				return
			}

			if !check.GetAllowed() {
				http.Error(w, "Access denied", http.StatusUnauthorized)
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}
