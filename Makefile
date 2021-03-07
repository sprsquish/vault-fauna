GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-fauna cmd/vault-fauna/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins -log-level=trace

enable:
	vault secrets enable -path=fauna vault-fauna

clean:
	rm -f ./vault/plugins/vault-fauna

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
