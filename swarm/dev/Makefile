.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/auchain/auchain/cmd/swarm
	go build -o bin/geth     github.com/auchain/auchain/cmd/geth
	go build -o bin/bootnode github.com/auchain/auchain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/auchain/auchain/swarm/...
