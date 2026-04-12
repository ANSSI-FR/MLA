import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  output: 'server',
  adapter: cloudflare({ imageService: 'passthrough' }),
  integrations: [react(), tailwind({ applyBaseStyles: false })],
  vite: {
    optimizeDeps: {
      exclude: ['mla-wasm'],
    },
  },
});
