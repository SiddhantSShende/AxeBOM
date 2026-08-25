/**
 * The ambient wash the whole product sits on.
 *
 * ⚠ IT IS DECORATION, AND IT SAYS SO. `aria-hidden` plus `pointer-events:
 * none` — it carries no information, must never be announced, and must never
 * intercept a click meant for the page.
 *
 * Three elements rather than one pseudo-element, because three blobs drift
 * independently and a pseudo-element can carry exactly one animation. They are
 * plain radial gradients with NO `filter: blur()` — a `closest-side` gradient
 * is already soft, and blurring a 70vmax element is a per-frame GPU cost
 * proportional to its area, forever. That single decision is what makes a
 * permanently-running background acceptable on an integrated GPU.
 *
 * Sits OUTSIDE `.app`, not inside it: a `z-index: -1` child would paint behind
 * its own parent's background and disappear.
 */
export function Ambient() {
  return (
    <div className="ambient" aria-hidden="true">
      <span className="ambient-blob" data-blob="1" />
      <span className="ambient-blob" data-blob="2" />
      <span className="ambient-blob" data-blob="3" />
    </div>
  );
}
