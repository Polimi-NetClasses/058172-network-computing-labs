# Makefile for starting the docker container
SERVICE_NAME_LAB=nc-labs

# Detect the operating system
OS := $(shell uname -s)

# Default to the Linux docker-compose file
DOCKER_COMPOSE_FILE=./docker/docker-compose-linux.yml

# Specify a different file for MacOS
ifeq ($(OS),Darwin) # Darwin is the system name for MacOS
	DOCKER_COMPOSE_FILE=./docker/docker-compose-mac.yml
endif

start-docker:
	(. ./docker/setup-env.sh && docker compose -f $(DOCKER_COMPOSE_FILE) up -d)

stop-docker:
	(. ./docker/setup-env.sh && docker compose -f $(DOCKER_COMPOSE_FILE) down -v)
	sudo docker stop ${SERVICE_NAME_LAB}
	sudo docker rm ${SERVICE_NAME_LAB}

connect-docker: start-docker
	docker exec -it $(SERVICE_NAME_LAB) /bin/bash