FROM golang:1.17 AS base

WORKDIR /go/src/app

# copy go mod files and download depedencies
# do with as a seperate step to build to cache it
COPY go.mod go.sum ./
RUN go mod download

# copy the rest of the source files
COPY app app

RUN go build -v -o /go/bin/app ./app

# runnable container
FROM debian:bullseye-slim

WORKDIR /home/

# copy artefacts over
COPY --from=base /go/bin/app .

# run service
CMD ["/bin/bash", "-c", "./app"]