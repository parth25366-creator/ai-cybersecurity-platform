export default {
  output: "standalone",
  experimental: { proxyTimeout: 120000 }, // agent calls can take 20-60s
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${process.env.BACKEND_URL ?? "http://backend:8000"}/:path*` }];
  },
};
