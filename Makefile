# Update BUCKET_NAME for development or testing
BUCKET_NAME := lacework-alliances
KEY_PREFIX := lacework-control-tower-cfn
DATASET := lacework-alliances-prod

# Set to true from command line for Control Tower V4 support, e.g., make build V4=true
V4 ?= false

# Update VERSION with each v3 release
VERSION ?= 3.3.3

PROFILE ?= alliances-admin
REGION ?= us-west-2

BASE := $(shell pwd)
TEMPLATES_DIR := templates
LAMBDA_DIRS := $(wildcard lambda_functions/source/*/.)
LAMBDA_PACKAGES := $(wildcard lambda_functions/packages/*/*.zip)

ifeq ($(V4), true)
# Update VERSION with each v4 release
VERSION := 4.0.1
KEY_PREFIX := lacework-control-tower-cfn/v4
BASE := $(shell pwd)/v4
TEMPLATES_DIR := v4/templates
LAMBDA_DIRS := $(wildcard v4/lambda_functions/source/*/.)
LAMBDA_PACKAGES := $(wildcard v4/lambda_functions/packages/*/*.zip)
endif

TARGETS := all clean build
$(TARGETS): $(LAMBDA_DIRS)

$(LAMBDA_DIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS) $(ARGS) BASE="$(BASE)" VERSION="$(VERSION)" DATASET="${DATASET}"

upload:
	@$(MAKE) upload-templates
	@$(MAKE) upload-packages

upload-templates:
	$(info [+] Uploading templates to $(BUCKET_NAME) bucket)
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $(TEMPLATES_DIR) s3://$(BUCKET_NAME)/$(KEY_PREFIX)/templates/ --recursive --exclude "*" --include "*.yaml" --include "*.yml" --acl public-read

upload-packages: $(LAMBDA_PACKAGES)
	$(info [+] Uploading Lambda packages to $(BUCKET_NAME) bucket)
	@for zip in $(LAMBDA_PACKAGES); do \
		aws --profile $(PROFILE) --region $(REGION) s3 cp $$zip s3://$(BUCKET_NAME)/$(KEY_PREFIX)/lambda/ --acl public-read; \
	done

.PHONY: $(TARGETS) $(LAMBDA_DIRS) $(BUCKET_NAME) $(LAMBDA_PACKAGES)
