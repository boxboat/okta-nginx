REG     := 539779309746.dkr.ecr.us-west-2.amazonaws.com/nginx-okta-proxy
HASH    := $(shell git rev-parse --short HEAD)
BRANCH  := $(shell echo $(shell git symbolic-ref --short -q HEAD) | sed 's|/|\-|g' )
TAG     := ${BRANCH}-${HASH}
IMG     := ${REG}:${TAG}
LATEST  := ${REG}:latest

default: build push

build:
	# build the deployable container
	docker build -t ${IMG} .

push:
	docker push ${IMG}
# if develop also tag/push as latest
ifeq ($(BRANCH),develop)
	echo "Tag as ${LATEST}"
	docker tag ${IMG} ${LATEST}
	docker push ${LATEST}
else
	echo 'No develop or release, no additional docker tagging and pushing'
endif
