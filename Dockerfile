FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY docs ./docs
COPY .specs ./specs
RUN chmod +x src/cli.js
EXPOSE 3210
CMD ["node", "--input-type=module", "-e", "import { Firewall, createApiServer } from './src/index.js'; const firewall = new Firewall(); createApiServer(firewall).listen(3210, '0.0.0.0', () => console.log('MCP Firewall dashboard running at http://localhost:3210/api/dashboard'));" ]
