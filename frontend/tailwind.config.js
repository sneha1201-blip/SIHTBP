/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0f1d',
          card: '#0f172a',
          border: '#1e293b',
          muted: '#334155',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444',
        },
      },
      animation: {
        'pulse-radar': 'radar 2s cubic-bezier(0, 0, 0.2, 1) infinite',
        'glow-pulse': 'glow 3s ease-in-out infinite alternate',
      },
      keyframes: {
        radar: {
          '0%': { transform: 'scale(0.95)', opacity: '0.8' },
          '70%': { transform: 'scale(2.2)', opacity: '0' },
          '100%': { transform: 'scale(2.4)', opacity: '0' },
        },
        glow: {
          '0%': { filter: 'drop-shadow(0 0 4px rgba(6, 182, 212, 0.4))' },
          '100%': { filter: 'drop-shadow(0 0 12px rgba(6, 182, 212, 0.8))' },
        },
      },
    },
  },
  plugins: [],
};

