This document is WIP

## Keycloak
Short Poc: https://github.com/rjmarques/auth-poc
I’ll add all this info (and maybe more related to the pros/cons) to the wiki.
Perhaps the more interesting part is in: https://github.com/rjmarques/auth-poc/tree/master/keycloak/auth
It has one middleware that does active checking of the session, and one that does passive checking. But both should look similar to our own [auth middleware](https://github.com/longshotsyndicate/auth/blob/master/postgresauth.go).
Steps to run the PoC:
```
git clone https://github.com/rjmarques/auth-poc.git
cd auth-poc/keycloack

# start up keycloak and the example apps
docker-compose up --build -d keycloak webapp1 webapp2

# create all the clients, users, roles on keycloak
./startup.sh
```

Keycloak’s admin console can be accessed on http://localhost:8080/ and using admin / admin
You also have 3 users (all with different groups and roles):

* ric / ric
* gary / gary
* jimmy / jimmy

You can login with these on either:
* http://localhost:8000/
* http://localhost:9000/

The apps have single-sign-on, even tho it’s a different server on each port, since the browser sends the cookies for that domain and each server then asks keycloak if it’s valid. So this  approach can be thought of “active validation” of sessions.
I’ve not implemented logout yet so it’s easier to use the browser’s incognito mode if you want to try and log in with different users.

There’s a secondary validation approach “passive validation” that I’ve also implemented on yet another app:
```
docker-compose up --build -d api
```

This one is uses port `:9999` but does not provide a webUI (it’s meant to behave a bit like STS) and is REST api only. To use you can do for example:
```
curl 'http://localhost:9999/login' -H 'content-type: application/json' --data-raw '{"username": "jimmy", "password": "jimmy"}'

# grab the token and do

curl 'http://localhost:9999/api/data' -H "Authorization: Bearer my_big_token"
```

Here the second request’s session is validated locally without interacting with keycloak.

TODO check if grafana can use keycloak
TODO check if apache and kong can too

## Ory stack
PoC: https://github.com/hohorace/ory-poc