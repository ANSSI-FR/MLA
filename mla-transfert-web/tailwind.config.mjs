/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Palette officielle Kodetis
        kds: {
          primary:   '#24305e', // bleu marine foncé
          secondary: '#005687', // bleu moyen
          yellow:    '#f8e9a1', // complémentaire chaud
          red:       '#f76c6c', // complémentaire alerte
          blue:      '#a8d0e6', // complémentaire clair
        },
        // Alias cyber → mappage sur la palette Kodetis
        cyber: {
          50:  '#f0f6fb',
          100: '#daeaf5',
          200: '#a8d0e6', // kds.blue
          300: '#7ab8d8',
          400: '#4d9ec9',
          500: '#005687', // kds.secondary (accent principal)
          600: '#004d7a',
          700: '#24305e', // kds.primary (boutons, titres)
          800: '#1c2549',
          900: '#141a36',
          950: '#0d1124',
        },
      },
      boxShadow: {
        'glow-xs': '0 0 6px 0 rgba(0,86,135,0.30)',
        'glow-sm': '0 0 14px 0 rgba(0,86,135,0.40)',
        'glow':    '0 0 28px 0 rgba(0,86,135,0.50)',
        'glow-lg': '0 0 48px 0 rgba(36,48,94,0.60)',
        'card':    '0 4px 24px 0 rgba(0,0,0,0.50)',
      },
      animation: {
        'pulse-glow':  'pulse-glow 2.5s ease-in-out infinite',
        'slide-up':    'slide-up 0.3s ease-out both',
        'fade-in':     'fade-in 0.25s ease-out both',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 8px 0 rgba(0,86,135,0.25)' },
          '50%':       { boxShadow: '0 0 24px 0 rgba(0,86,135,0.55)' },
        },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
