# Pinned base image — clean demo Dockerfile
FROM node:20.11.1-bookworm-slim

WORKDIR /app
COPY package.json package-lock.json ./
COPY src ./src

USER node
CMD ["node", "src/index.js"]
