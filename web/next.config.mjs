import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // This web app is self-contained; pin the workspace root so Turbopack doesn't
  // pick up the monorepo lockfile one level up.
  turbopack: {
    root: here,
  },
};

export default nextConfig;
