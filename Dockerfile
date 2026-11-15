# Isolated D23 read-only audit broker. Do not attach this to the existing Commander Relay.
FROM oven/bun:1.2.23
WORKDIR /app
COPY rian-commander/d23-runner/broker.ts ./broker.ts
COPY rian-commander/d23-runner/broker-server.ts ./broker-server.ts
RUN mkdir -p /data && chown -R bun:bun /app /data
USER bun
ENV NODE_ENV=production
EXPOSE 3000
CMD ["bun", "run", "broker-server.ts"]
