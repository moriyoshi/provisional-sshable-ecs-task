# tools
TERRAFORM := terraform
JQ := jq
DOCKER := docker
AWSCLI := aws
ECSPRESSO := ecspresso

TFSTATE_FILE := terraform.tfstate
ECS_CLUSTER = $(shell $(JQ) -r '.resources[] | select(.type == "aws_ecs_cluster") | .instances[0].attributes.name' $(TFSTATE_FILE))
PROVISIONAL_SSHABLE_CONTAINER_VERSION := latest
PROVISIONAL_SSHABLE_CONTAINER_REPOSITORY := $(shell $(JQ) -r '.resources[] | select(.type == "aws_ecr_repository") | .instances[0].attributes.repository_url' $(TFSTATE_FILE))
PROVISIONAL_SSHABLE_CONTAINER_ECSPRESSO_CONFIG_FILE := ecspresso.provisional-sshable-container.yaml

.PHONY: all
all: deploy

.PHONY: terraform
terraform: terraform-apply

.PHONY: terraform-apply
terraform-apply: .terraform
	$(TERRAFORM) apply -auto-approve

.PHONY: terraform-destroy
terraform-destroy: .terraform
	$(TERRAFORM) destroy

.terraform:
	$(TERRAFORM) init

.PHONY: build-image
build-image:
	$(DOCKER) build -t $(PROVISIONAL_SSHABLE_CONTAINER_REPOSITORY):$(PROVISIONAL_SSHABLE_CONTAINER_VERSION) docker/provisional-sshable-container

.PHONY: ecr-login
ecr-login:
	$(AWSCLI) ecr get-login-password | docker login --username AWS --password-stdin $(PROVISIONAL_SSHABLE_CONTAINER_REPOSITORY)

.PHONY: push-image
push-image: build-image ecr-login
	$(DOCKER) push $(PROVISIONAL_SSHABLE_CONTAINER_REPOSITORY):$(PROVISIONAL_SSHABLE_CONTAINER_VERSION)

.PHONY: deploy
deploy: push-image
	ECS_CLUSTER=$(ECS_CLUSTER) $(ECSPRESSO) run --config $(PROVISIONAL_SSHABLE_CONTAINER_ECSPRESSO_CONFIG_FILE) --wait-until="running"

.PHONY: bash
bash:
	ECS_CLUSTER=$(ECS_CLUSTER) $(ECSPRESSO) exec --config $(PROVISIONAL_SSHABLE_CONTAINER_ECSPRESSO_CONFIG_FILE) --container="default" --command="/bin/bash"

.PHONY: ssh
ssh:
	ECS_CLUSTER=$(ECS_CLUSTER) $(CURDIR)/ssh_helper.py '$(ECSPRESSO)' '$(PROVISIONAL_SSHABLE_CONTAINER_ECSPRESSO_CONFIG_FILE)'