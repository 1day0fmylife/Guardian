FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/guardian ./cmd/guardian

FROM scratch
COPY --from=build /out/guardian /guardian
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/guardian"]
