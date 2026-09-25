FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/guardian ./cmd/guardian

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardian /guardian
EXPOSE 8080
ENTRYPOINT ["/guardian"]
