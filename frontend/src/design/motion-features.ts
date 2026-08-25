/**
 * The `motion` feature bundle, loaded on its own chunk.
 *
 * ⚠ THIS FILE EXISTS SO THE 20-ODD KB OF ANIMATION FEATURES STAY OFF THE
 * CRITICAL PATH. `<LazyMotion features={() => import('./motion-features')}>`
 * puts everything below in a chunk fetched after first paint; importing
 * `domAnimation` directly from a component would pull it into the entry.
 *
 * ⚠ AND DO NOT NAME `motion` IN vite.config.ts's manualChunks. Listing it
 * there forces it into a chunk fetched with the entry and quietly defeats the
 * dynamic import this file is for.
 *
 * `domAnimation` — not `domMax` — is deliberate: it covers transforms, opacity
 * and exit animations, which is everything this product animates. `domMax`
 * adds layout projection and drag for another ~10 KB we would not use.
 */
import { domAnimation } from 'motion/react';

export default domAnimation;
