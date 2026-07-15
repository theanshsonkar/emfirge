import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The published @emfirge/mcp defaults its backend to https://emfirge.cloud/api
  // (see emfirge-oss/mcp/src/client.ts). Since this docs site now owns the
  // emfirge.cloud apex, it must forward /api/* to the production backend
  // (aws-risk-agent on EC2) so the MCP keeps working.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://13.204.232.220/:path*",
      },
    ];
  },
};

export default nextConfig;
