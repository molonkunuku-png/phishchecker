import { createContext, useContext } from 'react';

export type Theme = 'dark' | 'light';

type ThemeContextValue = {
  theme: Theme;
  setTheme: (t: Theme) => void;
};

export const ThemeContext = createContext<ThemeContextValue>({ theme: 'dark', setTheme: () => {} });

export function useTheme() {
  return useContext(ThemeContext);
}
