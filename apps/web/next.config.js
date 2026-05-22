const path = require('path')

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  eslint: {
    ignoreDuringBuilds: true,
  },
  images: {
    unoptimized: true,
  },
  experimental: {
    // Trace from monorepo root so standalone includes pnpm-hoisted deps
    outputFileTracingRoot: path.join(__dirname, '../../'),
  },
}

module.exports = nextConfig
