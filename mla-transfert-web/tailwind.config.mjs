/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Palette Kodetis DA
        kds: {
          navy:    '#24305e',
          blue:    '#005687',
          mist:    '#a8d0e6',
          gold:    '#f8e9a1',
          coral:   '#f76c6c',
        },
        // Alias cyber → Kodetis pour les composants existants
        cyber: {
          50:  '#f0f6fb',
          100: '#daeaf5',
          200: '#a8d0e6',
          300: '#7ab8d8',
          400: '#4d9ec9',
          500: '#005687',
          600: '#005080',
          700: '#24305e',
          800: '#1c2549',
          900: '#141a36',
          950: '#0d1124',
        },
      },
      boxShadow: {
        'card':    '0 2px 12px rgba(36,48,94,0.08), 0 1px 3px rgba(36,48,94,0.06)',
        'card-hover': '0 4px 20px rgba(36,48,94,0.12), 0 2px 6px rgba(36,48,94,0.08)',
        'glow-xs': '0 0 0 3px rgba(0,86,135,0.15)',
        'glow-sm': '0 0 16px rgba(0,86,135,0.25)',
        'glow':    '0 0 32px rgba(0,86,135,0.35)',
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        mono: ['ui-monospace', '"SFMono-Regular"', 'monospace'],
      },
      animation: {
        'slide-up':   'slide-up 0.35s cubic-bezier(0.16,1,0.3,1) both',
        'fade-in':    'fade-in 0.25s ease-out both',
        'pulse-soft': 'pulse-soft 2.5s ease-in-out infinite',
      },
      keyframes: {
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'pulse-soft': {
          '0%,100%': { opacity: '0.6' },
          '50%':     { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
