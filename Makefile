.PHONY: test
STATICCHECK := $(shell command -v staticcheck)

vet:
	go vet ./...
ifndef STATICCHECK
	go get -u honnef.co/go/tools/cmd/staticcheck
endif
	staticcheck ./...

test: vet
	go test ./...

race-test: vet
	go test -race ./...
