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
  async rewrites() {
    const apiUrl = process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    // Only proxy if API_URL is a full URL (not a relative path like /api)
    if (apiUrl.startsWith('http')) {
      return [
        {
          source: '/api/:path*',
          destination: `${apiUrl}/:path*`,
        },
      ]
    }
    return []
  },
}

module.exports = nextConfig
