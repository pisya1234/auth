FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install --loglevel verbose
EXPOSE 5000
CMD ["npm", "start"]
