FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
RUN npm ci --omit=optional
COPY src ./src
COPY frontend ./frontend
COPY tsconfig.json vite.config.ts drizzle.config.ts ./
RUN npm run build
COPY docs ./docs
COPY .specs ./specs
RUN chmod +x src/cli.js
EXPOSE 3210
CMD ["node", "--import", "tsx", "src/server.ts"]
