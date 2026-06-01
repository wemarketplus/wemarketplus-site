import { createContext, useContext, useEffect, type ReactNode } from 'react';

// The app is intentionally dark-only — the brand palette (mirrored from
// wemarketplus-site) is designed exclusively for a near-black canvas. This
// provider exists so the rest of the app (ThemeProvider in providers.tsx,
// hooks/useThemeColors) keeps a stable contract; light/system modes are
// deliberately not supported today.
//
// If a future product decision adds light mode, restore the prior
// localStorage + matchMedia logic here; the consumers won't need to change.

interface ThemeContextValue {
  readonly mode: 'dark';
  readonly resolved: 'dark';
  readonly isDark: true;
}

const VALUE: ThemeContextValue = {
  mode: 'dark',
  resolved: 'dark',
  isDark: true,
};

const ThemeContext = createContext<ThemeContextValue>(VALUE);

export function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    // Ensure the `.dark` class is on <html> even if index.html was edited.
    document.documentElement.classList.add('dark');
  }, []);

  return <ThemeContext.Provider value={VALUE}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}
