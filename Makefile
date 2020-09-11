APP_NAME=dnsproxy
LOCAL_PORT=53
HOST_PORT=5353
BUILD_ARGS=
EXTRA_VARS=

.PHONY: build
.PHONY: run

build:
	docker build -t $(APP_NAME) . --no-cache $(BUILD_ARGS)
run:
	docker run -t -e DNSP_LOCAL_PORT=$(LOCAL_PORT) $(EXTRA_VARS) \
        --name $(APP_NAME) \
        -p$(HOST_PORT):$(LOCAL_PORT) \
        $(APP_NAME)