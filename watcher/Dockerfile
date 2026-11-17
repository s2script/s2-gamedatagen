FROM node:22.11.0-alpine3.20
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY lib.js watch.js ./
# The state volume must exist, owned by node, before VOLUME: a fresh named volume copies this
# directory's ownership, and the process runs as node.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
ENV STATE_FILE=/data/state.json HEALTH_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
CMD ["node", "watch.js"]
