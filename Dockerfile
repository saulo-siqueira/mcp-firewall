FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY docs ./docs
COPY .specs ./specs
RUN chmod +x src/cli.js
EXPOSE 3210
CMD ["node", "src/server.js"]
