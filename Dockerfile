FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/upsilonauth ./cmd/upsilonauth

FROM alpine:3.21

RUN apk add --no-cache ca-certificates && addgroup -S upsilon && adduser -S -G upsilon upsilon
COPY --from=builder /out/upsilonauth /usr/local/bin/upsilonauth
USER upsilon
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/upsilonauth"]
