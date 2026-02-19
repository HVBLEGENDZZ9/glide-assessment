import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // BUG-24: Externalize native modules for proper SSR handling
  serverExternalPackages: ["better-sqlite3"],
};

export default nextConfig;

