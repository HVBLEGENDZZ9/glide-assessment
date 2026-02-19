// BUG-24 fix: Node.js 25 exposes an experimental localStorage that doesn't
// implement getItem/setItem properly. The `debug` npm package detects it
// and crashes. This polyfill ensures the global localStorage has working methods.
if (typeof globalThis.localStorage !== "undefined") {
  const ls = globalThis.localStorage as Record<string, unknown>;
  if (typeof ls.getItem !== "function") {
    const store: Record<string, string> = {};
    globalThis.localStorage = {
      getItem: (key: string) => store[key] ?? null,
      setItem: (key: string, value: string) => { store[key] = String(value); },
      removeItem: (key: string) => { delete store[key]; },
      clear: () => { Object.keys(store).forEach((k) => delete store[k]); },
      get length() { return Object.keys(store).length; },
      key: (index: number) => Object.keys(store)[index] ?? null,
    } as unknown as Storage;
  }
}

export async function register() {
  // Instrumentation hook for Next.js — runs once on server startup
}
