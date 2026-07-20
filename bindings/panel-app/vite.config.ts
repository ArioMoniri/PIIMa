// `vitest/config` rather than `vite`, because the `test` block below is a
// vitest key: `vite`'s own defineConfig does not type it and rejects it.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// THE BUILD IS CONFIGURED AROUND ONE CONSTRAINT: the output must run under
//
//   default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'
//
// which is the policy the vanilla panel enforces. Vite's DEFAULTS violate that
// policy in three separate places, and every override below exists to close one
// of them. None of these is a preference.
//
//   1. `modulePreload.polyfill` injects an INLINE <script> into index.html.
//      `script-src 'self'` refuses it. The refusal is silent in the sense that
//      the app still boots -- so this would have shipped as a permanent console
//      error nobody read, on a page whose entire pitch is that you can check it.
//   2. `assetsInlineLimit` turns small assets into `data:` URLs. `default-src
//      'none'` has no `data:` source, so an inlined asset is a resource the page
//      requests and the policy denies. Zero means every asset is a real file.
//   3. `cssCodeSplit` off keeps the CSS in ONE stylesheet loaded by <link>,
//      rather than letting a lazily-loaded chunk inject a <style> element at
//      runtime -- which `style-src 'self'` blocks, and which would land as an
//      unstyled component rather than as an error.
//
// `scripts/check-csp.mjs` VERIFIES the result rather than trusting this file.
// The settings say what we asked for; the checker says what we got, and the
// second one is the one worth having, because a Vite upgrade can change a
// default without changing this file.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Relative, because the built app is served from a directory whose path is
  // not known at build time: from `dist/` under `just serve-panel-app`, and
  // from `panel-app/` inside an extracted release bundle. An absolute "/"
  // base 404s in the second case.
  base: "./",
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "./src") },
  },
  build: {
    target: "es2022",
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    // One JS chunk. Not for size -- for auditability: the claim this app makes
    // is about what it loads, and a reviewer counting <script> tags against the
    // network panel should not have to reason about which chunks are lazy.
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        entryFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
