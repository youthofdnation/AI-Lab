# Dedicated read-only D23 audit broker (not the main RIAN Commander Relay).
FROM oven/bun:1.2.23
WORKDIR /app
COPY rian-commander/d23-runner/broker.ts ./broker.ts
COPY rian-commander/d23-runner/broker-server.ts ./broker-server.ts
RUN mkdir -p /data && chown -R bun:bun /app
# Railway mounts /data at runtime (after build), with root ownership.
# Change only this dedicated volume's ownership, then drop privileges.
USER root
ENV NODE_ENV=production
EXPOSE 3000
CMD ["sh", "-c", "chown bun:bun /data && exec su -s /bin/sh bun -c 'exec bun run broker-server.ts'"]
