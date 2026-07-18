FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o tw .

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/tw .
COPY --from=builder /build/public ./public

EXPOSE 3000

CMD ["./tw"]
