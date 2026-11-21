IMAGE ?= shopping-sessions:latest
CPUS  ?= 8
MEM   ?= 24g
# The scorer's platform. PLATFORM=linux/arm64 builds and runs natively on an Apple-silicon Mac, for fast local loops.
PLATFORM ?= linux/amd64
DEV   ?= dev
FIXTURES ?= fixtures
# Needs polars: pip install polars
PYTHON ?= python3
NATIVE = target/release/pipeline
export IMAGE CPUS MEM PLATFORM

.PHONY: build fixtures dev run-dev check-dev native native-fixtures native-fixtures-extra native-run-dev

## Build the image for the scorer's platform, linux/amd64 (emulated on Apple silicon)
build:
	docker buildx build --platform $(PLATFORM) --load -t $(IMAGE) .

## Run the image on all 36 edge-case fixtures and diff against the expected tables
fixtures: build
	$(PYTHON) scripts/run_fixtures.py $(FIXTURES) -- scripts/docker_run.sh

## Make the 1M-event dev set with the published generator (needs `generate` on PATH)
dev:
	generate --seed 1 --events 1000000 --clicks 250000 --output $(DEV)

## Run on the dev set with scorer flags and time it
run-dev: build
	rm -rf out && time scripts/docker_run.sh $(DEV) out

## Compare your dev output with the published dev answer (dev-answer.zip, unzipped): make check-dev ANSWER=dev-answer
ANSWER ?= dev-answer
check-dev:
	$(PYTHON) scripts/compare.py out $(ANSWER)

## Without Docker: build the binary for this machine
native:
	cargo build --release

## Without Docker: all fixtures against the native binary
native-fixtures: native
	$(PYTHON) scripts/run_fixtures.py $(FIXTURES) -- $(NATIVE)

## Without Docker: the extra hand-written cases in fixtures-extra/
native-fixtures-extra: native
	$(PYTHON) scripts/run_fixtures.py fixtures-extra -- $(NATIVE)

## Without Docker: the dev set through the native binary, timed (then `make check-dev`)
native-run-dev: native
	rm -rf out && time env DATA_DIR=$(DEV) OUTPUT_DIR=out $(NATIVE)
