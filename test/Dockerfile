FROM golang:bullseye

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -ldflags="-s -w" -v -o /usr/local/bin/ ./...

ENV VAULT_ADDR="http://localhost:8200"

ENTRYPOINT ["vault-shim"]
