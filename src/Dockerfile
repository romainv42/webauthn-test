FROM node:jessie

WORKDIR /usr/src/app

COPY package.json .
RUN npm i

COPY index.js .
COPY private ./private
COPY public ./public
COPY routes ./routes
COPY utils ./utils

EXPOSE 3000

CMD ["node", "index.js"]
