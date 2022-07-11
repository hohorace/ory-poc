# **Ory Stack**
Single-sign-on apps with Ory Kratos (authentication) and Ory Keto (authorisation).

Similar to Keyclaok, there are 2 login flows: cookie (browser) and bearer token (non-browser). 

## **Public Services URL**
Web App - http://localhost:5001 / http://localhost:5002

API App - http://localhost:5009

Ory Kratos Public (Selfservice) API - http://localhost:4433

Ory Keto Read API - http://localhost:4466

Ory Keto Write API - http://localhost:4467

## **Guide**
Spin-up the PoC by:
```
git clone https://github.com/hohorace/ory-poc.git
docker-compose up
```

### **Identities**
Initially you have 3 identities with different roles:
* `admin` - ric@longshotsystems.co.uk / ric@longshotsystems.co.uk
* `dev` - gary@longshotsystems.co.uk / gary@longshotsystems.co.uk
* `user` - jimmy@longshotsystems.co.uk / jimmy@longshotsystems.co.uk

which you could use for both login flows.

### **Login**
To use the browser login flow, open http://localhost:5001 or http://localhost:5002 in browser and submit the login form. A valid session should work in both server.

To use the non-browser login flow, obtain a session token with the following:
```
curl 'http://localhost:5009/login' -X POST -H 'Content-Type: application/json' -d '{"email": "email", "password": "password"}' | jq
```

### **Secured Endpoints**
`GET /api/session` - Kratos session info; accessible by all roles.

`GET /api/data` - dummy JSON; accessible by `dev`, `admin`.

`GET /api/secret` - dummy JSON; accessible by `admin`.

To access these endpoints via non-browser login flow, run:
```
curl 'http://localhost:5009/api/data' -H "Authorization: Bearer session_token"
```


### **Admin**
To manage identities via Ory Kratos CLI, run:
```
alias kratos="docker run -it --network=ory-poc_intranet -e KRATOS_ADMIN_URL=\"http://kratos:4434\" oryd/kratos:v0.10.1"
kratos help
```

To manage ACL via Ory Keto CLI, run:
```
alias keto="docker run -it --network=ory-poc_intranet -e KETO_READ_REMOTE=\"keto:4466\" -e KETO_WRITE_REMOTE=\"keto:4467\"  oryd/keto:v0.8.0-alpha.2"
keto help
```