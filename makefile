run:
	go run cmd/gocci/main.go

tidy:
	go mod tidy
	go mod vendor 