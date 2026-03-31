/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        rex: {
          safe: '#22c55e',
          warn: '#eab308',
          threat: '#ef4444',
          accent: '#3b82f6',
          bg: '#1a1a2e',
          surface: '#16213e',
          card: '#0f3460',
          text: '#e2e8f0',
          muted: '#94a3b8',
        },
      },
      animation: {
        'breathe': 'breathe 4s ease-in-out infinite',
        'wag': 'wag 0.3s ease-in-out infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        breathe: {
          '0%, 100%': { transform: 'scale(1)' },
          '50%': { transform: 'scale(1.03)' },
        },
        wag: {
          '0%, 100%': { transform: 'rotate(-5deg)' },
          '50%': { transform: 'rotate(5deg)' },
        },
      },
    },
  },
  plugins: [],
};
