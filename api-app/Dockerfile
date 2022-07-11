FROM golang:1.17 AS base

WORKDIR /go/src/api-app

# copy go mod files and download depedencies
# do with as a seperate step to build to cache it
COPY go.mod go.sum ./
RUN go mod download

# copy the rest of the source files
COPY auth auth
COPY api-app api-app

RUN go build -v -o /go/bin/api-app ./api-app

# runnable container
FROM debian:bullseye-slim

WORKDIR /home/

# copy artefacts over
COPY --from=base /go/bin/api-app .

# run service
CMD ["/bin/bash", "-c", "./api-app"]