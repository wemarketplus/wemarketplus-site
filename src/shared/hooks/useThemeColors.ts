import { useTheme } from '@/shared/contexts/ThemeContext';

// Most theming should happen via Tailwind utilities backed by CSS variables
// (see src/index.css). This hook is reserved for the rare case where you
// need the active mode inside JS — e.g. third-party chart libraries.
export function useThemeColors() {
  const { resolved, isDark } = useTheme();
  return { mode: resolved, isDark };
}
