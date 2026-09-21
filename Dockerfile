FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --only=production --no-audit --no-fund && npm cache clean --force

COPY . .

USER node
EXPOSE 3000

CMD ["npm", "start"]
