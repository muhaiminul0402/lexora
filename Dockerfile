FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_ENV=production DB_PATH=/data/lexora.db PORT=3000
EXPOSE 3000
CMD ["node","server.js"]
