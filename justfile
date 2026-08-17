set shell := ["zsh", "-cu"]

check: fmt test race lint tidy-check systemd-verify

fmt:
	test -z "$(gofmt -l $(find . -name '*.go' -not -path './vendor/*'))"

test:
	go test ./...

race:
	go test ./... -race -cover

cover:
	go test ./... -coverprofile=coverage.out

lint:
	go vet ./...

tidy-check:
	task_tmp=$(mktemp -d /private/tmp/certgot-tidy.XXXXXX); \
	trap 'rm -rf "$task_tmp"' EXIT; \
	cp go.mod "$task_tmp/go.mod"; \
	cp go.sum "$task_tmp/go.sum"; \
	task_status=0; \
	go mod tidy || task_status=$?; \
	diff -u "$task_tmp/go.mod" go.mod || task_status=1; \
	diff -u "$task_tmp/go.sum" go.sum || task_status=1; \
	if [ "$task_status" -ne 0 ]; then cp "$task_tmp/go.mod" go.mod; cp "$task_tmp/go.sum" go.sum; fi; \
	exit "$task_status"

build:
	go build .

systemd-verify:
	if command -v systemd-analyze >/dev/null 2>&1; then systemd-analyze verify .github/systemd/certgot.service .github/systemd/certgot.timer; else echo "systemd-analyze unavailable; run on Linux"; fi
