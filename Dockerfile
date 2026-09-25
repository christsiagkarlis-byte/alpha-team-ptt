# Immutable multi-architecture base image digest (Node 22.13.0 Alpine 3.20).
FROM node:22.13.0-alpine3.20@sha256:db8dcb90326a0116375414e9a7c068a6b87a4422b7da37b5c6cd026f7c7835d3

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

WORKDIR /usr/src/app

# package-lock.json is mandatory; npm ci makes dependency installation reproducible.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --chown=node:node server.js database.sql ./
COPY --chown=node:node public ./public

USER node
EXPOSE 3000

CMD ["node", "server.js"]
