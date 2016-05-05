SRC = .
TEST = ./test

all: test      \
	 benchmark \
     coverage

format: 
	gofmt -w=true ${SRC}/*.go
	gofmt -w=true ${TEST}/*.go

build: format
	go build ${SRC}

test: build
	go test ${TEST}

benchmark: build
	go test ${TEST} -bench .

coverage: build
	go test ${TEST} -cover .

debug: build
	gofmt -w=true ${SRC}
	go test ${TEST} -run TestCryptoHashBlocks

