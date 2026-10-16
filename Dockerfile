FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
COPY --chown=node:node sdk ./sdk
RUN mkdir /app/data && chown node:node /app/data
USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4408 DATA_DIR=/app/data
EXPOSE 4408
HEALTHCHECK --interval=20s --timeout=4s --start-period=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:4408/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "src/server.mjs"]
