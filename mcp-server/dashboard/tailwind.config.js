/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Deep dark navy (darker than infracorp)
        app:     '#080e17',
        surface: '#0d1520',
        raised:  '#121d2b',
        overlay: '#080e1790',
        border:  '#1e3a52',
        // Text hierarchy
        't-primary':    '#f6f8f9',
        't-secondary':  '#94a8b8',
        't-tertiary':   '#6b8399',
        't-quaternary': '#3f627d',
        // Intent colors
        brand:   '#6366f1',
        success: '#10b981',
        warning: '#f59e0b',
        danger:  '#ef4444',
        info:    '#06b6d4',
        // Risk gradient
        'risk-critical': '#ef4444',
        'risk-high':     '#f97316',
        'risk-medium':   '#eab308',
        'risk-low':      '#10b981',
        // Accent
        accent: {
          indigo: '#6366f1',
          violet: '#8b5cf6',
          cyan:   '#22d3ee',
          teal:   '#2dd4bf',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"SF Mono"', '"Fira Code"', 'monospace'],
      },
      fontSize: {
        micro: '9px',
        xxs: '10px',
        xs: '11px',
        sm: '12px',
        md: '13px',
        lg: '15px',
        xl: '18px',
        '2xl': '22px',
        '3xl': '28px',
      },
      borderRadius: {
        'xl': '12px',
        '2xl': '16px',
        '3xl': '20px',
      },
    },
  },
  plugins: [],
}
