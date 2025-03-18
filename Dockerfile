FROM node:20-alpine

WORKDIR /app

# Installation des dépendances
COPY package*.json ./
RUN npm install

# Copie du code source
COPY . .

# Exposition du port de développement
EXPOSE 5173

# Commande pour lancer le serveur de développement
CMD ["npm", "run", "dev", "--", "--host"] 