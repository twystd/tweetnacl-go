all: format \
     build \
	 test  \
	 benchmark

format: 
	gofmt -w=true *.go

build: 
	go build 

test:
	go test

benchmark:
	go test -bench .

