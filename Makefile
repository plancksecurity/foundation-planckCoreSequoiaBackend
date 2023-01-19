DEBUG?=
PREFIX?=/usr/local
CARGO?=cargo

BUILD=./_build
LIB_DIR?=$(PREFIX)/lib

ifeq ($(strip $(DEBUG)),)
	CARGO_FLAGS+=--release
	BUILD_DIR=$(BUILD)/release
else
	BUILD_DIR=$(BUILD)/debug
endif

all: build

build: prepare
	CARGO_TARGET_DIR="$(BUILD)" "$(CARGO)" build $(CARGO_FLAGS)

.PHONY: prepare clean install

prepare:
	mkdir -p "$(BUILD)"

test:
	CARGO_TARGET_DIR="$(BUILD)" "$(CARGO)" test

install: build
	mkdir -p "$(LIB_DIR)"
	cp -f "$(BUILD_DIR)/libpep_engine_sequoia_backend.a" "$(LIB_DIR)"

uninstall:
	rm -f "$(LIB_DIR)/libpep_engine_sequoia_backend.a"

clean:
	rm -Rf "$(BUILD)"

