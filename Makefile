# Build

GO ?= go

all:
	$(GO) build -o raid ./main
	ln -sf raid raidd

.PHONY: all test bench clean install

test:
	$(GO) test -count=1 ./core/canonical ./core/policy ./core/decision ./core/store ./core/approval ./core/api ./core/jev ./core/nlpolicy ./core/tui ./core/cli ./pkg/raidclient

bench:
	$(GO) test -bench=Benchmark -benchmem -v ./core/bench

clean:
	rm -f raid raidd

install: all
	install -Dm755 raid /usr/local/bin/raid
	ln -sf raid /usr/local/bin/raidd
	install -d /usr/local/share/offense/raid/examples
	cp -r examples api docs /usr/local/share/offense/raid/

# Manage a local daemon (defaults match the demo):
#   make run-demo    builds and boots raidd with a temp data dir
run-demo: all
	mkdir -p /tmp/raid-demo
	rm -f /tmp/raid-demo/raid.sock /tmp/raid-demo/raid.db*
	./raidd --socket /tmp/raid-demo/raid.sock \
	        --db /tmp/raid-demo/raid.db \
	        --policy examples/policies/surge-default.yaml \
	        --key /tmp/raid-demo/ed25519.seed --uid 0 --uid $$(id -u) \
	        --approver $$(id -un):maintainers,admins