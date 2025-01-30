tidy:
	go mod tidy
	go mod vendor 

up:
	docker-compose up --build --scale gocci=3

down:
	docker-compose down