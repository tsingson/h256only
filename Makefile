.PHONY: test
STATICCHECK := $(GOPATH)/bin/staticcheck

$(STATICCHECK):
	go get -u honnef.co/go/tools/cmd/staticcheck

vet: $(STATICCHECK)
	go vet ./...
	$(STATICCHECK) ./...

test: vet
	go test ./...

race-test:
	go test -race ./...
