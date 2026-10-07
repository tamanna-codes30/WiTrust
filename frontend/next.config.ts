import type { NextConfig } from "next";

const backendOrigin = (process.env.WITRUST_API_URL ?? "http://127.0.0.1:8765").replace(/\/+$/, "");

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backendOrigin}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
