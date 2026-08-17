/**
 * Vitest setup.
 *
 * jsdom has no matchMedia and no clipboard, and several components reach for
 * both. Stubbing them here rather than in each test keeps a component test
 * about the component.
 */

import '@testing-library/jest-dom/vitest';

if (!window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}
