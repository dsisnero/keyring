.PHONY: help test build install clean
.PHONY: docker-build docker-test docker-test-linux docker-dev docker-clean
.PHONY: test-macos test-file test-all container-info

# Detect container runtime: Apple container > docker-compose > docker
CONTAINER := $(shell command -v container 2> /dev/null)
DOCKER_COMPOSE := $(shell command -v docker-compose 2> /dev/null)
DOCKER := $(shell command -v docker 2> /dev/null)

ifdef CONTAINER
    CONTAINER_ENGINE = container
    BUILD_CMD = container build --tag keyring-linux-test --file Dockerfile .
    RUN_CMD = container run --rm -v $(PWD):/workspace keyring-linux-test
    RUN_INTERACTIVE_CMD = container run --rm -it -v $(PWD):/workspace keyring-linux-test
    CLEAN_CMD = container image delete keyring-linux-test 2>/dev/null || true
else ifdef DOCKER_COMPOSE
    CONTAINER_ENGINE = docker-compose
    BUILD_CMD = docker-compose build
    RUN_CMD = docker-compose run --rm
    RUN_INTERACTIVE_CMD = docker-compose run --rm
    CLEAN_CMD = docker-compose down && docker rmi keyring-linux-test 2>/dev/null || true
else ifdef DOCKER
    CONTAINER_ENGINE = docker
    BUILD_CMD = docker build -t keyring-linux-test .
    RUN_CMD = docker run --rm -v $(PWD):/workspace keyring-linux-test
    RUN_INTERACTIVE_CMD = docker run --rm -it -v $(PWD):/workspace keyring-linux-test
    CLEAN_CMD = docker rmi keyring-linux-test 2>/dev/null || true
else
    CONTAINER_ENGINE = none
    BUILD_CMD = @echo "Error: No container runtime found. Install Docker, docker-compose, or Apple container."
    RUN_CMD = $(BUILD_CMD)
    RUN_INTERACTIVE_CMD = $(BUILD_CMD)
    CLEAN_CMD = @echo "No container runtime to clean."
endif

# Default target
help:
	@echo "Keyring Makefile"
	@echo ""
	@echo "Container Runtime: $(CONTAINER_ENGINE)"
	@echo ""
	@echo "Local Development:"
	@echo "  make install        - Install dependencies"
	@echo "  make build          - Build the project"
	@echo "  make test           - Run all tests"
	@echo "  make test-macos     - Test macOS backend"
	@echo "  make test-file      - Test file backend"
	@echo "  make lint           - Run code linting (ameba)"
	@echo "  make format         - Format code (crystal tool format)"
	@echo "  make format-check   - Check code formatting"
	@echo "  make pre-commit     - Run pre-commit checks (format + lint)"
	@echo ""
	@echo "Docker/Container (Linux Testing):"
	@echo "  make docker-build   - Build container image"
	@echo "  make docker-test    - Run all tests in container"
	@echo "  make test-linux     - Test Linux backend in container"
	@echo "  make docker-dev     - Interactive shell in container"
	@echo "  make docker-clean   - Remove container images"
	@echo "  make container-info - Show detected container runtime"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean          - Remove build artifacts"

# Display detected container runtime
container-info:
	@echo "Container runtime detection:"
	@echo "  Apple container: $(if $(CONTAINER),✓ found at $(CONTAINER),✗ not found)"
	@echo "  docker-compose:  $(if $(DOCKER_COMPOSE),✓ found at $(DOCKER_COMPOSE),✗ not found)"
	@echo "  docker:          $(if $(DOCKER),✓ found at $(DOCKER),✗ not found)"
	@echo ""
	@echo "Using: $(CONTAINER_ENGINE)"

# Local development
install:
	shards install

build:
	shards build

test:
	crystal spec

test-macos:
	crystal spec spec/keyring/macos_backend_spec.cr

test-file:
	crystal spec spec/keyring/file_backend_spec.cr

test-all: test

lint:
	@echo "Running Ameba linting..."
	shards build && crystal run lib/ameba/bin/ameba.cr -- --fail-level Error

format:
	@echo "Formatting code..."
	crystal tool format

format-check:
	@echo "Checking code formatting..."
	crystal tool format --check

pre-commit: format-check lint
	@echo "Pre-commit checks passed!"

clean:
	rm -rf bin/
	rm -rf lib/
	rm -rf .crystal/
	rm -rf .shards/
	find . -name "*.dwarf" -delete

# Container targets (work with Apple container, docker-compose, or docker)
docker-build:
	@echo "Building with $(CONTAINER_ENGINE)..."
ifdef CONTAINER
	@echo "Starting container system..."
	@container system start 2>/dev/null || true
endif
	$(BUILD_CMD)

docker-test:
ifdef CONTAINER
	$(RUN_CMD) with-keyring crystal spec
else ifdef DOCKER_COMPOSE
	$(RUN_CMD) test
else
	$(RUN_CMD) with-keyring crystal spec
endif

docker-test-linux:
ifdef CONTAINER
	$(RUN_CMD) with-keyring crystal spec spec/keyring/linux_backend_spec.cr
else ifdef DOCKER_COMPOSE
	$(RUN_CMD) test-linux
else
	$(RUN_CMD) with-keyring crystal spec spec/keyring/linux_backend_spec.cr
endif

docker-dev:
ifdef CONTAINER
	$(RUN_INTERACTIVE_CMD) bash
else ifdef DOCKER_COMPOSE
	$(RUN_CMD) dev
else
	$(RUN_INTERACTIVE_CMD) bash
endif

docker-clean:
	@echo "Cleaning with $(CONTAINER_ENGINE)..."
	$(CLEAN_CMD)
ifdef CONTAINER
	@echo "Stopping container system..."
	@container system stop 2>/dev/null || true
endif

# Convenience aliases
test-linux: docker-build docker-test-linux
dev-linux: docker-build docker-dev
