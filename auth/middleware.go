package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	keto "github.com/ory/keto-client-go"
	kratos "github.com/ory/kratos-client-go"
)

type MiddlewareConfig struct {
	KratosPublicUrl string
	KetoReadUrl     string
}

type Middleware struct {
	kratos *kratos.APIClient
	keto   *keto.APIClient
}

func NewWebMiddleware(config *MiddlewareConfig) (authingWrapper func(handler http.Handler) http.Handler, loginHandler http.HandlerFunc) {
	m := newMiddleware(config)

	loginHandler = m.formLogin
	authingWrapper = m.activeAuthingHandler

	return
}

func NewApiMiddleware(config *MiddlewareConfig) (authingWrapper func(handler http.Handler) http.Handler, loginHandler http.HandlerFunc) {
	m := newMiddleware(config)

	loginHandler = m.jsonLogin
	authingWrapper = m.passiveAuthingHandler

	return
}

func newMiddleware(config *MiddlewareConfig) *Middleware {
	kratosConfig := kratos.NewConfiguration()
	kratosConfig.Servers = []kratos.ServerConfiguration{{URL: config.KratosPublicUrl}}
	kratos := kratos.NewAPIClient(kratosConfig)

	ketoConfig := keto.NewConfiguration()
	ketoConfig.Servers = []keto.ServerConfiguration{{URL: config.KetoReadUrl}}
	keto := keto.NewAPIClient(ketoConfig)

	return &Middleware{
		kratos: kratos,
		keto:   keto,
	}
}

func (m *Middleware) formLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "error parsing form", http.StatusBadRequest)
		return
	}

	form := r.PostForm
	email := form.Get("email")
	password := form.Get("password")
	if email == "" || password == "" {
		http.Error(w, "invalid email/password", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(os.Stdout, fmt.Sprintf("%s/%s logging in\n", email, password))

	ctx := context.Background()

	// WARNING: this should be done when landed on login page
	flow, resp, err := m.kratos.V0alpha2Api.InitializeSelfServiceLoginFlowForBrowsers(ctx).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error when calling `V0alpha2Api.InitializeSelfServiceLoginFlowForBrowsers``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
		return
	}

	var csrfCookie string
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "csrf_token_") {
			csrfCookie = cookie.Name + "=" + cookie.Value
			break
		}
	}

	var csrfToken string
	for _, node := range flow.Ui.GetNodes() {
		if node.Attributes.UiNodeInputAttributes.GetName() == "csrf_token" {
			csrfToken = node.Attributes.UiNodeInputAttributes.GetValue().(string)
		}
	}

	if csrfToken == "" {
		http.Error(w, fmt.Sprintf("`V0alpha2Api.InitializeSelfServiceLoginFlowForBrowsers`` returns no CSRF token: %v\nFull HTTP response: %v\n", err, resp), http.StatusInternalServerError)
		return
	}

	submitLoginBody := kratos.SubmitSelfServiceLoginFlowBody{
		SubmitSelfServiceLoginFlowWithPasswordMethodBody: &kratos.SubmitSelfServiceLoginFlowWithPasswordMethodBody{
			CsrfToken:  &csrfToken,
			Identifier: email,
			Method:     "password",
			Password:   password,
		},
	}

	_, resp, err = m.kratos.V0alpha2Api.SubmitSelfServiceLoginFlow(ctx).Flow(flow.GetId()).Cookie(csrfCookie).SubmitSelfServiceLoginFlowBody(submitLoginBody).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("Error when calling `V0alpha2Api.SubmitSelfServiceLoginFlow``: %v\nFull HTTP response: %v\n", err, resp))
		http.Error(w, fmt.Sprintf("Error when calling `V0alpha2Api.SubmitSelfServiceLoginFlow``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
		return
	}

	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "ory_kratos_session" {
			sessionCookie = cookie
		}
	}

	http.SetCookie(w, sessionCookie)
	w.WriteHeader(http.StatusOK)
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expiresIn"` // seconds
}

type SubmitLoginFlowResponse struct {
	Session      *kratos.Session `json:"session"`
	SessionToken string          `json:"session_token"`
}

func (m *Middleware) jsonLogin(w http.ResponseWriter, r *http.Request) {
	req := &LoginRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(os.Stderr, fmt.Sprintf("Logging in %s/%s", req.Email, req.Password))

	if req.Email == "" || req.Password == "" {
		http.Error(w, "invalid email/password", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// AAL (AuthenticationMethod Assurance Level) is set to "aal1" for identity sign in using username+password
	flow, resp, err := m.kratos.V0alpha2Api.InitializeSelfServiceLoginFlowWithoutBrowser(ctx).Aal("aal1").Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error when calling `V0alpha2Api.InitializeSelfServiceLoginFlowWithoutBrowser``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
		return
	}

	submitLoginBody := kratos.SubmitSelfServiceLoginFlowBody{
		SubmitSelfServiceLoginFlowWithPasswordMethodBody: &kratos.SubmitSelfServiceLoginFlowWithPasswordMethodBody{
			Identifier: req.Email,
			Method:     "password",
			Password:   req.Password,
		},
	}

	_, resp, err = m.kratos.V0alpha2Api.SubmitSelfServiceLoginFlow(ctx).Flow(flow.Id).SubmitSelfServiceLoginFlowBody(submitLoginBody).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("Error when calling `V0alpha2Api.SubmitSelfServiceLoginFlow``: %v\nFull HTTP response: %v\n", err, resp))
		http.Error(w, fmt.Sprintf("Error when calling `V0alpha2Api.SubmitSelfServiceLoginFlow``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
		return
	}

	defer resp.Body.Close()

	submitLoginFlowResponse := &SubmitLoginFlowResponse{}

	if err := json.NewDecoder(resp.Body).Decode(submitLoginFlowResponse); err != nil {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("Error decoding `V0alpha2Api.SubmitSelfServiceLoginFlow` response`: %v\nFull HTTP response: %v\n", err, resp))
		http.Error(w, fmt.Sprintf("Error decoding `V0alpha2Api.SubmitSelfServiceLoginFlow` response`: %v\nFull HTTP response: %v\n", err, resp), http.StatusInternalServerError)
		return
	}

	loginResponse := &LoginResponse{
		Token:     submitLoginFlowResponse.SessionToken,
		ExpiresIn: int(submitLoginFlowResponse.Session.ExpiresAt.Sub(time.Now()).Seconds() * float64(time.Second)),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&loginResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating response`: %s", err), http.StatusInternalServerError)
	}
}

func (m *Middleware) activeAuthingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		// Authentication
		cookie, err := r.Cookie("ory_kratos_session")
		if err != nil {
			http.Error(w, "No token", http.StatusUnauthorized)
			return
		}

		session, resp, err := m.kratos.V0alpha2Api.ToSession(ctx).Cookie(fmt.Sprintf("ory_kratos_session=%s", cookie.Value)).Execute()
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

		roles := traits["roles"].([]interface{})
		
		fmt.Printf("path: %s\n", object)
		
		allowed := false
		for _, role := range roles {
			subjectId := role.(string)

			check, resp, err := m.keto.ReadApi.GetCheck(ctx).Namespace(namespace).Object(object).Relation(relation).SubjectId(subjectId).Execute()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error when calling `ReadApi.GetCheck``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
				return
			}

			if check.GetAllowed() {
				allowed = true
				break
			}
		}
		
		if !allowed {
			http.Error(w, "Access denied", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "session", session))

		h.ServeHTTP(w, r)
	})
}

func (m *Middleware) passiveAuthingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to extract Authorization parameter from the HTTP header
		authorization := r.Header.Get("Authorization")

		if authorization == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// extract Bearer token
		token := extractToken(authorization)

		if token == "" {
			http.Error(w, "Bearer Token missing", http.StatusUnauthorized)
			return
		}

		ctx := context.Background()

		// Authentication
		session, resp, err := m.kratos.V0alpha2Api.ToSession(ctx).XSessionToken(token).Execute()
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

		check, resp, err := m.keto.ReadApi.GetCheck(ctx).Namespace(namespace).Object(object).Relation(relation).SubjectId(subjectId).Execute()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error when calling `ReadApi.GetCheck``: %v\nFull HTTP response: %v\n", err, resp), http.StatusBadGateway)
			return
		}

		if !check.GetAllowed() {
			http.Error(w, "Access denied", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "session", session))

		h.ServeHTTP(w, r)
	})
}

func extractToken(authorization string) string {
	return strings.Replace(authorization, "Bearer ", "", 1)
}
