#!/bin/bash

cd $(dirname $0)

if [ -f "vars.env" ]; then
    set +a
    . ./vars.env
    set -a
fi

# Check if Dockerfile exists in the current directory
if [ ! -f "Dockerfile" ]; then
    echo "Error: Dockerfile not found in the current directory."
    exit 1
fi

# Build the Docker image with the full tag name
echo "Building Docker image..."
docker build --no-cache -t local/proxy:latest .

# Verify the image was built successfully
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Docker image."
    exit 1
fi

echo "Image built successfully. Starting container..."

# Run the Docker container using the local image
docker run \
    --platform linux/amd64 \
    --rm \
    --name "okta-nginx" \
    -e "APP_POST_LOGIN_URL=$APP_POST_LOGIN_URL" \
    -e "AUDIENCE=$AUDIENCE" \
    -e "CLIENT_ID=$CLIENT_ID" \
    -e "CLIENT_SECRET=$CLIENT_SECRET" \
    -e "COOKIE_DOMAIN=$COOKIE_DOMAIN" \
    -e "ISSUER=$ISSUER" \
    -e "LOGIN_REDIRECT_URL=$LOGIN_REDIRECT_URL" \
    -p "8080:80" \
    local/proxy:latest
