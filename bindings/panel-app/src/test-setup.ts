// jsdom does not implement `matchMedia`, and `useReducedMotion` calls it on
// every render. Without this every component test throws before it asserts
// anything, which would make the reduced-motion tests pass for the wrong
// reason. The default is "no preference"; the tests that care override it.
if (!globalThis.matchMedia) {
  Object.defineProperty(globalThis, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
