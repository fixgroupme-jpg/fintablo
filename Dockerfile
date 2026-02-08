FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . ./
RUN mkdir -p /data
ENV PORT=3000
ENV DB_PATH=/data/fintablo.db
EXPOSE 3000
CMD ["node", "server.js"]
