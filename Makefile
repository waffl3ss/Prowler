BINARY    := prowler
VERSION   := 0.6
LDFLAGS   := -s -w
GOFLAGS   := -trimpath

.PHONY: all linux darwin windows clean

all: linux darwin windows

linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o build/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o build/$(BINARY)-linux-arm64 .

darwin:
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o build/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o build/$(BINARY)-darwin-arm64 .

windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o build/$(BINARY)-windows-amd64.exe .

clean:
	rm -rf build/
