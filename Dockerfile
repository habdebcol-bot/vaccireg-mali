FROM node:20-bookworm-slim
WORKDIR /app
COPY backend/package*.json ./backend/
RUN cd backend && npm install --omit=dev
COPY backend ./backend
COPY frontend ./frontend
WORKDIR /app/backend
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node","server.js"]
