
BUCKET_PREFIX := lacework-alliances
KEY_PREFIX := lacework-control-tower-cfn
PACKAGES_PREFIX := lambda/
CFT_PREFIX := templates
CFT_DIR := templates
DATASET := lacework-alliances-prod

#PROFILE ?= alliances-admin
REGION ?= us-west-2

BUCKET_NAME ?= service_not_defined
BASE = $(shell /bin/pwd)

s3_buckets := $(BUCKET_PREFIX)

TOPTARGETS := all clean package build

SUBDIRS := $(wildcard lambda_functions/source/*/.)
ZIP_SUBDIRS := $(wildcard lambda_functions/packages/*/.)

ZIP_FILES := $(shell find $(ZIP_SUBDIRS) -type f -name '*.zip')

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS) $(ARGS) BASE="${BASE}" DATASET="${DATASET}"

upload: $(s3_buckets)

$(s3_buckets):
	$(info [+] Uploading artifacts to '$@' bucket)
	@$(MAKE) _upload BUCKET_NAME=$@
	@$(MAKE) _upload_zip BUCKET_NAME=$@

_upload:
	$(info [+] Uploading templates to $(BUCKET_NAME) bucket)
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $(CFT_DIR)/ s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(CFT_PREFIX) --recursive --exclude "*" --include "*.yaml" --include "*.yml" --acl public-read

_upload_zip: $(ZIP_SUBDIRS)

$(ZIP_SUBDIRS): $(ZIP_FILES)

$(ZIP_FILES):
	$(info [+] Uploading zip files to $(BUCKET_NAME) bucket)
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $@ s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(PACKAGES_PREFIX) --acl public-read

.PHONY: $(TOPTARGETS) $(SUBDIRS) $(s3_buckets) $(ZIP_FILES)
