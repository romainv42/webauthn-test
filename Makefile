DB_ROOT=root
DB_PASSWORD=p4ssw0rd
DB_NAME=testdb
DB_SERVER=mymongo

build:
	DB_ROOT=${DB_ROOT} DB_PASSWORD=${DB_PASSWORD} DB_NAME=${DB_NAME} DB_SERVER=${DB_SERVER} docker-compose build

up:
	DB_ROOT=${DB_ROOT} DB_PASSWORD=${DB_PASSWORD} DB_NAME=${DB_NAME} DB_SERVER=${DB_SERVER} docker-compose up -d

start:
	DB_ROOT=${DB_ROOT} DB_PASSWORD=${DB_PASSWORD} DB_NAME=${DB_NAME} DB_SERVER=${DB_SERVER} docker-compose start

stop:
	docker-compose stop

down:
	docker-compose down
