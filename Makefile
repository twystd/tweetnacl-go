all: test      \
	 benchmark \
     coverage

format: 
	gofmt -w=true *.go
	gofmt -w=true *.go

build: format
	go build

test: build
	go test

benchmark: build
	go test -bench .

coverage: build
	go test -cover .

debug: build
	gofmt -w=true *.go
	go test -run TestCryptoHashBlocks

