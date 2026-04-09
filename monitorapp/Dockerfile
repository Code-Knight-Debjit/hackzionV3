# monitorapp/Dockerfile
# ─────────────────────────────────────────────────────────────────
# Stage 1 — Build the Expo web bundle
# ─────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests first (layer-cache friendly)
COPY monitorapp/package.json monitorapp/package-lock.json ./

# Install all deps (including devDeps needed for the build)
RUN npm ci --legacy-peer-deps

# Copy the rest of the app source
COPY monitorapp/ .
RUN npx expo install react-dom react-native-web @expo/metro-runtime
# Export static web build to /app/dist
RUN npx expo export --platform web --output-dir dist

# ─────────────────────────────────────────────────────────────────
# Stage 2 — Serve with nginx + proxy /api → api service
# ─────────────────────────────────────────────────────────────────
FROM nginx:1.25-alpine

# Remove default nginx site
RUN rm /etc/nginx/conf.d/default.conf

# Custom nginx config: serve SPA + proxy /api to backend
COPY monitorapp/nginx.conf /etc/nginx/conf.d/monitorapp.conf

# Copy the built web bundle from Stage 1
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]