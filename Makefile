# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gdcrm bootnode clean

gdcrm:
	./gomod.sh
	go build -v -mod=vendor -o bin/cmd/bootnode ./cmd/bootnode/*.go
	go build -v -mod=vendor -o bin/cmd/gdcrm ./cmd/gdcrm/*.go
	@echo "Done building."

clean:
	rm -fr bin/cmd/* 
	rm -rf go.mod
	rm -rf go.sum
	rm -rf vendor
