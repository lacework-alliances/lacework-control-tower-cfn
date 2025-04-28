PROJECT = LaceworkCTSetup
DIR_NAME = setup
FUNCTION = $(PROJECT)3.3.3
DIST_DIR ?= "$(BASE)"/lambda_functions/packages/$(DIR_NAME)
HONEY_DATASET = $(DATASET)

all: build

.PHONY: clean build

clean:
	rm -rf build
	rm $(DIST_DIR)/$(FUNCTION).zip || true

build: clean
	mkdir -p build
	cp ../common/* build
	buildid=$$(git describe --all --long | cut -d "/" -f 2); \
	sed -e "s|\$$BUILD|$$buildid|g" -e "s|\$$DATASET|$(HONEY_DATASET)|g" -e "s|\$$HONEY_KEY|$(HONEY_KEY)|g" setup.py > build/setup.py
	pip3 install -r requirements.txt -t build
	cd build; zip -r $(DIST_DIR)/$(FUNCTION).zip . -x "*.DS_Store*" "*.git*" "build*" "Makefile"
	rm -rf build


