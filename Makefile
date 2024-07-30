# Copyleft 2023, pEp Foundation
# This file is part of pEpEngineSequoiaBackend
# This file may be used under the terms of the GNU General Public License version 3
# see COPYING

# Build config defaults
DEBUG?=debug
PREFIX?=/usr/local
CARGO?=cargo
BUILD?=_build
# Build config overrides
-include ./local.conf

ifeq ($(ARCH), arm64)
    ARCH_NAME=aarch64-apple-darwin
    CARGO_FLAGS+= --target $(ARCH_NAME)
    TARGET_DIR=$(ARCH_NAME)
else
    ifeq ($(ARCH), x64)
        ARCH_NAME=x86_64-apple-darwin
        CARGO_FLAGS+= --target $(ARCH_NAME)
        TARGET_DIR=$(ARCH_NAME)
    endif
endif

# Make sure CARGO_TARGET_DIR is not set by the user -- it would be ignored.
CARGO_TARGET_DIR?=
ifneq ($(CARGO_TARGET_DIR),)
    $(error "the user should not set 'CARGO_TARGET_DIR': 'BUILD' can be used \
             instead.")
endif

#export as env var to sub-shells
export CARGO_TARGET_DIR=$(BUILD)

# constants
LIB_NAME=libpep_engine_sequoia_backend

# determine library file extension
PLATFORM:=$(shell uname)
ifeq ($(PLATFORM),Linux)
    DYNLIB_EXT=so
else ifeq ($(PLATFORM),Darwin)
    DYNLIB_EXT=dylib
else
    $(error "Dont know how to build for '$(PLATFORM)'")
endif

# DEBUG can be defined as "release", "debug" or "maintainer".
ifeq ($(DEBUG),maintainer)  # For compatibility with other pEp repos.
    VARIANT_NAME=debug
    VARIANT_FLAGS=
else ifeq ($(DEBUG),debug)
    VARIANT_NAME=debug
    VARIANT_FLAGS=
else ifeq ($(DEBUG),release)
    VARIANT_NAME=release
    VARIANT_FLAGS=--release
else
    $(error "build option 'DEBUG' must be 'release', 'debug' or 'maintainer'")
endif

LIB_DYNAMIC_PATH=$(CARGO_TARGET_DIR)/$(ARCH_NAME)/$(VARIANT_NAME)/$(LIB_NAME).$(DYNLIB_EXT)
LIB_STATIC_PATH=$(CARGO_TARGET_DIR)/$(ARCH_NAME)/$(VARIANT_NAME)/$(LIB_NAME).a
PKGCONFIG_PATH=$(CARGO_TARGET_DIR)/$(VARIANT_NAME)/pep_engine_sequoia_backend.pc
LIB_DIR=$(PREFIX)/lib/
PKGCONFIG_DIR=$(PREFIX)/share/pkgconfig/

CARGO_FLAGS+=$(VARIANT_FLAGS)

INSTALL?=install

.PHONY: all build install uninstall test clean
all: build

# Assuming linking to Botan, the c++ standard library is needed,
# and for a full static build will need to resolve calls to it.
# Linking to it dynamically is the best choice on macOS.
ifeq ($(PLATFORM),Darwin)
    RUSTFLAGS+=-l dylib=c++
endif

build:
	$(CARGO) build $(CARGO_FLAGS)

install: build
	mkdir -p $(LIB_DIR) $(PKGCONFIG_DIR)
	if [ -f $(LIB_DYNAMIC_PATH) ]; then $(INSTALL) $(LIB_DYNAMIC_PATH) $(LIB_DIR); fi
	$(INSTALL) $(LIB_STATIC_PATH) $(LIB_DIR)
	$(INSTALL) $(PKGCONFIG_PATH) $(PKGCONFIG_DIR)

uninstall:
	rm -f $(LIB_DIR)/$(LIB_NAME).$(DYNLIB_EXT)
	rm -f $(LIB_DIR)/$(LIB_NAME).a
	rm -f $(PKGCONFIG_DIR)/pep_engine_sequoia_backend.pc

test:
	$(CARGO) test $(CARGO_FLAGS)

clean:
	$(CARGO) clean
