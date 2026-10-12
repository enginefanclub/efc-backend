FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci socket.io cors

COPY . .

CMD ["node", "index.js"]