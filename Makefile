# Makefile for ezcaACMEAgent Docker management
# Run with: make <target>
# Note: If you're not using PowerShell as your default shell, you can run using: pwsh -Command "make <target>"

# Default values
IMAGE_NAME := thomasgeens/ezcaacmeagent
IMAGE_TAG := 2022
VERSION := 0.2.0
VCS_REF := $(shell git rev-parse --short HEAD 2>/dev/null || echo "test")
BUILD_DATE := $(shell pwsh -Command "(Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')")
ENV_FILE := env.list

# Environment variables with AA_ prefix will be automatically passed to Docker
# Example: AA_TenantId=new-value AA_FriendlyName=my-custom-name make run

# PHONY targets to avoid conflicts with files of the same name
.PHONY: build run run-shell clean help all version run-identity run-interactive run-devicecode run-spsecret run-spcert run-spcertbase64 generate-env-file

# Default target
all: build

# Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Git Ref: $(VCS_REF)"
	@echo "Build Date: $(BUILD_DATE)"

# Build the Docker image
build:
	$(eval DOCKER_BUILD_ARGS := --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg BUILD_VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF))
	$(foreach var,$(filter AA_%,$(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $(var))),$(eval DOCKER_BUILD_ARGS += --build-arg $(var)=$($(var)))) )
	docker build \
		$(DOCKER_BUILD_ARGS) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run the container normally
run:
	$(eval DOCKER_RUN_ARGS := --env-file $(ENV_FILE))
	$(foreach var,$(filter AA_%,$(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $(var))),$(eval DOCKER_RUN_ARGS += --env $(var)=$($(var)))) )
	docker run \
		$(DOCKER_RUN_ARGS) \
		-p 443:443/tcp \
		--rm -it \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Run the container with PowerShell entrypoint
run-shell:
	$(eval DOCKER_RUN_ARGS := --entrypoint powershell.exe --env-file $(ENV_FILE))
	$(foreach var,$(filter AA_%,$(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $(var))),$(eval DOCKER_RUN_ARGS += --env $(var)=$($(var)))) )
	docker run \
		$(DOCKER_RUN_ARGS) \
		-p 443:443/tcp \
		--rm -it \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Run with different authentication methods
run-identity:
	@echo "Running with Identity authentication method"
	ENV_FILE=env.identity.list make run

run-interactive:
	@echo "Running with Interactive authentication method"
	ENV_FILE=env.interactive.list make run

run-devicecode:
	@echo "Running with Device Code authentication method"
	ENV_FILE=env.devicecode.list make run

run-spsecret:
	@echo "Running with Service Principal Secret authentication method"
	ENV_FILE=env.spsecret.list make run

run-spcert:
	@echo "Running with Service Principal Certificate (thumbprint) authentication method"
	ENV_FILE=env.spcert.list make run

run-spcertbase64:
	@echo "Running with Service Principal Certificate (base64) authentication method"
	ENV_FILE=env.spcertbase64.list make run

# Remove Docker images
clean:
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) || true

# Generate a custom environment file from a base file plus overrides
# Usage: OUTPUT_ENV_FILE=custom.env.list ENV_FILE=env.spsecret.list AA_ClientId=new-id make generate-env-file
OUTPUT_ENV_FILE ?= custom.env.list
generate-env-file:
	@echo "Generating custom environment file $(OUTPUT_ENV_FILE) from $(ENV_FILE)"
	@pwsh -Command "Copy-Item -Path '$(ENV_FILE)' -Destination '$(OUTPUT_ENV_FILE)' -Force"
	@pwsh -Command "$(foreach var,$(filter AA_%,$(.VARIABLES)),\
		$(if $(filter-out environment% default automatic,$(origin $(var))),\
		if (Select-String -Path '$(OUTPUT_ENV_FILE)' -Pattern '^$(var)=') { \
			(Get-Content '$(OUTPUT_ENV_FILE)') -replace '^$(var)=.*', '$(var)=$($(var))' | Set-Content '$(OUTPUT_ENV_FILE)'; \
		} else { \
			Add-Content -Path '$(OUTPUT_ENV_FILE)' -Value '$(var)=$($(var))'; \
		}; \
		))"
	@echo "Generated $(OUTPUT_ENV_FILE) with overrides"

# Build with a specific version
build-version:
	@echo "Building version $(VERSION)"
	$(eval DOCKER_BUILD_ARGS := --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg BUILD_VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF))
	$(foreach var,$(filter AA_%,$(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $(var))),$(eval DOCKER_BUILD_ARGS += --build-arg $(var)=$($(var)))) )
	docker build \
		$(DOCKER_BUILD_ARGS) \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

# Show help information
help:
	@echo "ACME Agent Docker Makefile Help"
	@echo "=============================="
	@echo ""
	@echo "Basic Commands:"
	@echo "  make build                - Build the Docker image"
	@echo "  make run                  - Run with default configuration"
	@echo "  make clean                - Remove Docker images"
	@echo ""
	@echo "Authentication Methods:"
	@echo "  make run-identity         - Run with Managed Identity authentication"
	@echo "  make run-interactive      - Run with Interactive authentication"
	@echo "  make run-devicecode       - Run with Device Code authentication"
	@echo "  make run-spsecret         - Run with Service Principal Secret authentication"
	@echo "  make run-spcert           - Run with Service Principal Certificate (thumbprint)"
	@echo "  make run-spcertbase64     - Run with Service Principal Certificate (base64)"
	@echo ""
	@echo "Environment Variable Overrides:"
	@echo "  Set AA_ prefixed environment variables to override settings:"
	@echo "  Example: AA_CertificateSubjectName=custom.example.com make run"
	@echo ""
	@echo "Custom Environment Files:"
	@echo "  make ENV_FILE=custom.env.list run  - Run with a custom environment file"
	@echo "  make OUTPUT_ENV_FILE=my.list generate-env-file - Generate a custom env file"
	@echo ""
	@echo "For more details, see:"
	@echo "  - README.md               - General information"
	@echo "  - AUTH_METHODS.md         - Authentication methods details"
	@echo "  - ENV_VAR_OVERRIDES.md    - Environment variable override details"
	@echo "  - CHEATSHEET.md           - Quick reference of common commands"
