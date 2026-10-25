import { useCallback, useEffect, useState } from "react";

type Theme = "dark" | "light";
// Display preference. The spoken-summary switch is the other one.
const KEY = "pai-theme";

function initial(): Theme {
  try {
    return window.localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(initial);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next = current === "dark" ? "light" : "dark";

      try {
        window.localStorage.setItem(KEY, next);
      } catch {
        // Preference simply is not persisted.
      }

      return next;
    });
  }, []);

  return { theme, toggle };
}
