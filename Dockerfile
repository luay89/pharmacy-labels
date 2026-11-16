FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    DATA_DIR=/data \
    PORT=3000

WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node . .
RUN command -v setpriv && mkdir -p /data && chown node:node /data

# The entrypoint prepares only the mounted data files, then drops the app process to node.
ENTRYPOINT ["./docker-entrypoint.sh"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["setpriv", "--reuid=node", "--regid=node", "--init-groups", "node", "-e", "fetch('http://127.0.0.1:'+process.env.PORT+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
