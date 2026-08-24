/** @type {import('tailwindcss').Config} */
//
// Color tokens are defined as CSS custom properties in src/index.css and
// exposed here through `rgb(var(--token) / <alpha-value>)` so opacity
// modifiers (e.g. `bg-primary/10`) keep working. The palette mirrors the
// existing wemarketplus-site exactly — dark only by design.
//
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: 'rgb(var(--color-ink) / <alpha-value>)',
        bg: 'rgb(var(--color-bg) / <alpha-value>)',
        surface: {
          DEFAULT: 'rgb(var(--color-surface) / <alpha-value>)',
          elevated: 'rgb(var(--color-surface-elevated) / <alpha-value>)',
          raised: 'rgb(var(--color-surface-raised) / <alpha-value>)',
        },
        foreground: 'rgb(var(--color-foreground) / <alpha-value>)',
        muted: {
          DEFAULT: 'rgb(var(--color-muted) / <alpha-value>)',
          soft: 'rgb(var(--color-muted-soft) / <alpha-value>)',
        },
        faint: 'rgb(var(--color-faint) / <alpha-value>)',
        border: {
          DEFAULT: 'rgb(var(--color-border) / <alpha-value>)',
          strong: 'rgb(var(--color-border-strong) / <alpha-value>)',
        },
        primary: {
          DEFAULT: 'rgb(var(--color-primary) / <alpha-value>)',
          hover: 'rgb(var(--color-primary-hover) / <alpha-value>)',
          foreground: 'rgb(var(--color-primary-foreground) / <alpha-value>)',
        },
        azure: 'rgb(var(--color-azure) / <alpha-value>)',
        gold: 'rgb(var(--color-gold) / <alpha-value>)',
        amber: 'rgb(var(--color-amber) / <alpha-value>)',
        sage: 'rgb(var(--color-sage) / <alpha-value>)',
        lime: 'rgb(var(--color-lime) / <alpha-value>)',
        success: 'rgb(var(--color-success) / <alpha-value>)',
        warning: 'rgb(var(--color-warning) / <alpha-value>)',
        destructive: {
          DEFAULT: 'rgb(var(--color-destructive) / <alpha-value>)',
          foreground: 'rgb(var(--color-destructive-foreground) / <alpha-value>)',
        },
      },
      borderRadius: {
        sm: 'var(--radius-sm)',
        DEFAULT: 'var(--radius)',
        md: 'var(--radius)',
        lg: 'var(--radius-lg)',
        // The card/panel/modal surface. See --radius-card in index.css.
        card: 'var(--radius-card)',
        xl: 'var(--radius-xl)',
        pill: 'var(--radius-pill)',
      },
      fontFamily: {
        // The site uses the system stack, not a webfont. `display` is an
        // alias so existing `font-display` headings keep rendering.
        sans: ['"Segoe UI"', 'system-ui', '-apple-system', 'Arial', 'sans-serif'],
        display: ['"Segoe UI"', 'system-ui', '-apple-system', 'Arial', 'sans-serif'],
      },
      letterSpacing: {
        // The ONE tracking for uppercase eyebrows, kickers and table column
        // headers. Fourteen different values (0.02em … 0.16em) were in use for
        // that single visual role, which is why two labels on adjacent cards
        // never quite looked like the same style. 0.08em was the most common of
        // the fourteen, so this is the majority value promoted to a token
        // rather than a new number. See shared/ui/core/typography.ts (OVERLINE).
        label: '0.08em',
      },
      borderColor: {
        // Default border uses semi-transparent white per site convention.
        DEFAULT: 'rgb(var(--color-border) / 0.09)',
      },
      keyframes: {
        breathe: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.3' },
        },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(22px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        // Cinematic hero reveal — longer, eased, GPU-only (opacity + translateY).
        reveal: {
          from: { opacity: '0', transform: 'translateY(24px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        breathe: 'breathe 2s ease infinite',
        'slide-up': 'slide-up 0.22s ease both',
        'fade-in': 'fade-in 0.18s ease both',
        reveal: 'reveal 0.8s cubic-bezier(0.22, 1, 0.36, 1) both',
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 12px 32px -16px rgba(0,0,0,0.5)',
        glow: '0 0 0 1px rgb(var(--color-primary) / 0.4), 0 12px 40px -10px rgb(var(--color-primary) / 0.25)',
      },
    },
  },
  plugins: [],
};
