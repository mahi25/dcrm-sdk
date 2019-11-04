#!/bin/bash

set -eu

./gomod.sh
go build -v -mod=vendor -o bin/cmd/bootnode ./cmd/bootnode/*.go
go build -v -mod=vendor -o bin/cmd/gdcrm ./cmd/gdcrm/*.go

