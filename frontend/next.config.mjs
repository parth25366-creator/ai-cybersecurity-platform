const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

// /api/* is proxied to the backend, so the browser never needs CORS.
export default {
  output: "standalone",
  poweredByHeader: false,
  experimental: { proxyTimeout: 120000 }, // agent calls can take 20-60s
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${process.env.BACKEND_URL ?? "http://backend:8000"}/:path*` }];
  },
};
