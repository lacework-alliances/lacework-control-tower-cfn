PROJECT = LaceworkCTAuth
DIR_NAME = auth
FUNCTION = $(PROJECT)
DIST_DIR ?= "$(BASE)"/functions/packages/$(DIR_NAME)

all: build

.PHONY: clean build

clean:
	rm -rf build

build: clean
	mkdir -p build
	zip -r $(DIST_DIR)/$(FUNCTION).zip . -x "*.DS_Store*" "*.git*" "build*" "Makefile" "requirements.txt"
	python3 -m venv build/$(FUNCTION)
	. build/$(FUNCTION)/bin/activate; \
	pip3 install  -r requirements.txt; \
	cp -r "$$VIRTUAL_ENV"/lib/ build/
	cd build/site-packages; zip -g -r $(DIST_DIR)/$(FUNCTION).zip . -x "*__pycache__*"
	rm -rf build
