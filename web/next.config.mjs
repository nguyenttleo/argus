import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

const nextConfig = {
  reactStrictMode: true,

  turbopack: {
    root: here,
  },
};

export default nextConfig;
