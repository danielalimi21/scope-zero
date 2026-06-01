FROM node:24-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -S scopezero && adduser -S scopezero -G scopezero

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY index.html styles.css app.js openapi.yaml ./
COPY config ./config
COPY src ./src
COPY sdk ./sdk
COPY examples ./examples
COPY tools ./tools
COPY tests ./tests
COPY db ./db
COPY k8s ./k8s
COPY README.md PRODUCT_ARCHITECTURE.md SECURITY_REVIEW.md ACTION_AUTHORIZATION.md AATP.md CONTROL_MATRIX.md ./

RUN mkdir -p /app/data /app/logs && chown -R scopezero:scopezero /app

USER scopezero
EXPOSE 8788

CMD ["node", "server.js"]
