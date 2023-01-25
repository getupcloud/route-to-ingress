APP_NAME   ?= route-to-ingress
VERSION    ?= 0.2.2
IMAGE_HOST ?= ghcr.io
IMAGE_NAME ?= getupcloud/$(APP_NAME)
IMAGE      := $(IMAGE_HOST)/$(IMAGE_NAME)

CLUSTER_ISSUER     ?= letsencrypt-staging-http01
DRY_RUN            ?= false
INGRESS_CLASS_NAME ?= $(APP_NAME)
NAMESPACE          ?= getup

.ONESHELL:
.EXPORT_ALL_VARIABLES:

all: build help

help:
	@echo Targets:
	@echo '  build:    Create docker image.'
	@echo '  run:      Run dev.'
	@echo '  push:     Push image to repo $(IMAGE).'
	@echo '  release:  Build and push.'

KUBECONFIG ?= ~/.kube/config
run:
	docker run -it --rm --name $(APP_NAME) \
		-v $(PWD):/app \
		-v $(realpath $(KUBECONFIG)):/app/kubeconfig \
		-e CLUSTER_ISSUER=$(CLUSTER_ISSUER) \
		-e DRY_RUN=$(DRY_RUN) \
		-e INGRESS_CLASS_NAME=$(INGRESS_CLASS_NAME) \
		-e IGNORE_DANGEROUS_INGRESS_CLASS_NAME=$(IGNORE_DANGEROUS_INGRESS_CLASS_NAME) \
		-e KUBECONFIG=/app/kubeconfig \
		-e NAMESPACE=$(NAMESPACE) \
		$(IMAGE):$(VERSION)

build b:
	docker build . -t $(IMAGE):$(VERSION)
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest

push p:
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

.PHONY: manifests
manifests:
	sed -i -e 's|image: $(IMAGE):.*|image: $(IMAGE):$(VERSION)|' manifests/deployment.yaml

release r: build manifests push
