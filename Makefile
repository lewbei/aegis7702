.PHONY: all test test-contracts test-engine test-benchmark build demo clean video

all: test-contracts test-engine build

test: test-contracts test-engine

test-contracts:
	cd contracts && forge test -v

test-engine:
	cd engine && npm test

test-benchmark:
	cd engine && npm run eval:usenix

test-comparison:
	cd engine && npm run eval:comparison

build:
	cd contracts && forge build
	cd app && npm run build

demo:
	@echo "Starting Aegis7702 Engine API Server and Vite Dashboard..."
	@trap 'kill 0' EXIT; \
	(cd engine && npm run server) & \
	(cd app && npm run dev)

video:
	@echo "Rendering Aegis7702 walkthrough video (1080p @ 30fps)..."
	python3 scripts/render_demo_video.py
