all: format \
     build \
	 test  \
	 benchmark

format: 
	GOPATH=$(shell pwd) gofmt -w=true src/*

build: 
	GOPATH=$(shell pwd) go build github.com/twystd/tweetnacl

test:
	GOPATH=$(shell pwd) go test github.com/twystd/tweetnacl 

benchmark:
	GOPATH=$(shell pwd) go test -bench . github.com/twystd/tweetnacl 

clean:
	rm -rf pkg
	rm -rf bin

