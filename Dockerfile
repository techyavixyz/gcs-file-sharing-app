# Use lightweight Node image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy only package files first (for caching)
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy app code
COPY . .

# Expose port
EXPOSE 3000

# Start app
CMD ["node", "app.js"]