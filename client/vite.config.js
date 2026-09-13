import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "SecureChat",
        short_name: "SecureChat",
        description: "End-to-end encrypted messaging and calls.",
        theme_color: "#0F1419",
        background_color: "#0F1419",
        display: "standalone",
        icons: []
      },
    }),
  ],
  server: {
    host: true,
    port: 5173,
  },
});
