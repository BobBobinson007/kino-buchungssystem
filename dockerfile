FROM node:20-slim

# Installiere Build-Tools für native Pakete wie bcrypt
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Nur die package-Dateien kopieren
COPY package*.json ./

# Pakete im Container sauber für ARM neu installieren
RUN npm install --omit=dev

# Restlichen Code kopieren
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]