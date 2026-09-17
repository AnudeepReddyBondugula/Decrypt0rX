import type { NextConfig } from "next";

const config: NextConfig = {
  // Emits a minimal server bundle so the production image stays small.
  output: "standalone",
  reactStrictMode: true,
};

export default config;
