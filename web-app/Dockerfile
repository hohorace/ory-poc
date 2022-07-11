FROM golang:1.17 AS base

WORKDIR /go/src/web-app

# copy go mod files and download depedencies
# do with as a seperate step to build to cache it
COPY go.mod go.sum ./
RUN go mod download

# copy the rest of the source files
COPY auth auth
COPY web-app web-app

RUN go build -v -o /go/bin/web-app ./web-app

# runnable container
FROM debian:bullseye-slim

WORKDIR /home/

# copy artefacts over
COPY --from=base /go/bin/web-app .
COPY --from=base /go/src/web-app/web-app/static ./static

# run service
CMD ["/bin/bash", "-c", "./web-app"]