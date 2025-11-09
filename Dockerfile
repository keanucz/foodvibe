# syntax=docker/dockerfile:1

FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN mkdir -p template static
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o foodvibe ./src

FROM gcr.io/distroless/base-debian12:latest

WORKDIR /app
COPY --from=builder /app/foodvibe /usr/local/bin/foodvibe
COPY --from=builder /app/template ./template
COPY --from=builder /app/static ./static

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/usr/local/bin/foodvibe"]
