import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        danger: { DEFAULT: '#ef4444', light: '#fee2e2', dark: '#b91c1c' },
        warning: { DEFAULT: '#f59e0b', light: '#fef3c7', dark: '#b45309' },
        success: { DEFAULT: '#22c55e', light: '#dcfce7', dark: '#15803d' },
      },
    },
  },
  plugins: [],
}

export default config
