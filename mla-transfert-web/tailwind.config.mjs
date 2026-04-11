/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          50:  '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
          950: '#083344',
        },
      },
      boxShadow: {
        'glow-xs': '0 0 6px 0 rgba(6,182,212,0.25)',
        'glow-sm': '0 0 12px 0 rgba(6,182,212,0.35)',
        'glow':    '0 0 24px 0 rgba(6,182,212,0.45)',
        'glow-lg': '0 0 40px 0 rgba(6,182,212,0.55)',
        'card':    '0 4px 24px 0 rgba(0,0,0,0.4)',
      },
      animation: {
        'pulse-glow':  'pulse-glow 2.5s ease-in-out infinite',
        'slide-up':    'slide-up 0.3s ease-out both',
        'fade-in':     'fade-in 0.25s ease-out both',
        'progress-in': 'progress-in 0.4s ease-out both',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 8px 0 rgba(6,182,212,0.2)' },
          '50%':       { boxShadow: '0 0 24px 0 rgba(6,182,212,0.5)' },
        },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'progress-in': {
          from: { width: '0%' },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
    },
  },
  plugins: [],
};
