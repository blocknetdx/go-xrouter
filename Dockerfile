# build backend
FROM golang:1.16.2
WORKDIR /go/src/github.com/blocknetdx/go-xrouter
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o go-xrouter main.go

CMD ["./go-xrouter"]

