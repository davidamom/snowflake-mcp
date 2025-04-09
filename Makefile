# Variables
SERVICE_NAME := snowflake-mcp

# Default target
.PHONY: all
all: build

# Build the Docker image
.PHONY: build
build:
	@echo "Building Docker image..."
	docker-compose build

# Run the Docker container
.PHONY: run
run:
	@echo "Running Docker container..."
	docker-compose up

# Run the Docker container in detached mode
.PHONY: run-detached
run-detached:
	@echo "Running Docker container in detached mode..."
	docker-compose up -d

# Stop the Docker container
.PHONY: stop
stop:
	@echo "Stopping Docker container..."
	docker-compose stop

# Remove the Docker container
.PHONY: rm
rm:
	@echo "Removing Docker container..."
	docker-compose down

# Stop and remove the Docker container
.PHONY: clean
clean:
	@echo "Stopping and removing Docker container..."
	docker-compose down
	@echo "Cleanup complete"

# Clean everything including the image
.PHONY: clean-all
clean-all:
	@echo "Removing Docker container and image..."
	docker-compose down --rmi all
	@echo "Full cleanup complete"

# View logs
.PHONY: logs
logs:
	@echo "Viewing logs..."
	docker-compose logs -f

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the Docker image"
	@echo "  run           - Run the Docker container (interactive mode)"
	@echo "  run-detached  - Run the Docker container in detached mode"
	@echo "  stop          - Stop the running Docker container"
	@echo "  rm            - Remove the Docker container"
	@echo "  clean         - Stop and remove the Docker container"
	@echo "  clean-all     - Clean everything including the Docker image"
	@echo "  logs          - View container logs"
	@echo "  help          - Show this help message" 