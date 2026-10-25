import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry) && !path.includes("/test/") ? [path] : [];
  });
}

const files = sources(SRC).map((path) => ({ path, text: readFileSync(path, "utf8") }));

describe("client hygiene", () => {
  it("scans a meaningful number of files", () => {
    expect(files.length).toBeGreaterThan(30);
  });

  it("never references credentials, build-time env secrets or the API-key header", () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(/X-API-Key/i);
      expect(text, path).not.toMatch(/PRIVATE_AI_API_KEY/);
      expect(text, path).not.toMatch(/import\.meta\.env\.VITE_/);
    }
  });

  it("uses browser storage only for display preferences", () => {
    const users = files.filter(({ text }) => /\b(localStorage|sessionStorage|indexedDB)\b/.test(text));
    const paths = users.map(({ path }) => path.replace(SRC, "")).sort();

    expect(paths).toEqual(["/features/speech/preference.ts", "/hooks/useTheme.ts"]);

    for (const file of users) {
      expect(file.text, file.path).not.toMatch(/csrf|api[_-]?key|token/i);
    }

    expect(users.find((file) => file.path.endsWith("useTheme.ts"))?.text).toContain('"pai-theme"');
    expect(users.find((file) => file.path.endsWith("preference.ts"))?.text).toContain('"pai-spoken"');
  });

  it("never injects HTML or evaluates strings", () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(/dangerouslySetInnerHTML/);
      expect(text, path).not.toMatch(/\binnerHTML\b/);
      expect(text, path).not.toMatch(/\beval\(|new Function\(/);
    }
  });

  it("only talks to same-origin /api paths", () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
    }
  });
});
