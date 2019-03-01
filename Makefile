APP_NAME=dnsproxy
LOCAL_PORT=53
EXTRA_VARS=

.PHONY: build
.PHONY: run

build:
	docker build -t $(APP_NAME) .

run:
	docker run -ti -e LOCAL_PORT=$(LOCAL_PORT) $(EXTRA_VARS) \
        --name $(APP_NAME) \
        -p$(LOCAL_PORT):$(LOCAL_PORT) \
        -d $(APP_NAME)
