import type { NextConfig } from "next";

const backendUrl = process.env.EMFIRGE_BACKEND_URL ?? "http://localhost:3000";

const nextConfig: NextConfig = {
  async rewrites() {
    return {
      beforeFiles: [{ source: "/", destination: "/docs" }],
      afterFiles: [
        {
          source: "/api/:path*",
          destination: `${backendUrl}/:path*`,
        },
      ],
      fallback: [],
    };
  },
  async redirects() {
    return [{ source: "/docs", destination: "/", permanent: false }];
  },
};

export default nextConfig;
