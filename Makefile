# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gdcrm bootnode clean

gdcrm:
	./gomod.sh
	build/env.sh go run build/ci.go install ./cmd/bootnode
	build/env.sh go run build/ci.go install ./cmd/gdcrm
	@echo "Done building."

bootnode:
	build/env.sh go run build/ci.go install ./cmd/bootnode

all: gdcrm bootnode

clean:
	./build/clean_go_build_cache.sh
	rm -fr build/_workspace build/bin/*
	rm -rf go.mod
	rm -rf go.sum
	rm -rf vendor
