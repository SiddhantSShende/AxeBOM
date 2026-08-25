/**
 * The modal surface: a drawer or a dialog.
 *
 * ⚠ FOCUS-TRAPPED, ESCAPE-CLOSES, FOCUS-RESTORED. `ComponentDrawer` and
 * `ShareDialog` each hand-rolled a partial version of this — Escape and an
 * initial `.focus()`, nothing else — which is a WCAG 2.2 modal-dialog defect:
 * a keyboard user could Tab straight out of either into the table or the
 * report behind it, which is still there and still scrollable. This traps
 * Tab within the panel and returns focus to whatever opened it on close.
 *
 * ⚠ PORTALED TO `document.body`, DELIBERATELY. Rendered inline under the
 * glass grid shell, an ancestor's `backdrop-filter` or `transform` — the
 * route-enter animation on `.route` is exactly this — becomes the scrim's
 * containing block and silently breaks its `position: fixed`. Escaping the
 * tree avoids auditing every ancestor for that bug rather than risking it.
 *
 * ⚠ THE EXIT ANIMATION IS THE CALLER'S RESPONSIBILITY TO ENABLE. This
 * component supplies `exit` variants for `motion`, but React unmounts a
 * conditionally-rendered element the instant its condition goes false —
 * nothing plays an exit animation unless something upstream is holding the
 * element open for it. Wrap the conditional in `<AnimatePresence>` at the
 * call site:
 *
 *   <AnimatePresence>
 *     {selected && <Overlay variant="drawer" onClose={...}>…</Overlay>}
 *   </AnimatePresence>
 */

import { useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { m } from 'motion/react';

interface OverlayProps {
  variant: 'drawer' | 'dialog';
  onClose: () => void;
  children: ReactNode;
  'aria-label'?: string | undefined;
  'aria-labelledby'?: string | undefined;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), ' +
  'input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

const VARIANTS = {
  drawer: {
    initial: { x: 28, opacity: 0 },
    animate: { x: 0, opacity: 1 },
    exit: { x: 28, opacity: 0 },
  },
  dialog: {
    initial: { y: 10, opacity: 0, scale: 0.98 },
    animate: { y: 0, opacity: 1, scale: 1 },
    exit: { y: 10, opacity: 0, scale: 0.98 },
  },
} as const;

export function Overlay({ variant, onClose, children, ...aria }: OverlayProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const returnFocusTo = useRef<Element | null>(null);

  useEffect(() => {
    returnFocusTo.current = document.activeElement;
    // ⚠ THE REST OF THE APP GOES `inert`, NOT JUST VISUALLY DIMMED. A scrim
    // is a hint for sighted users; `inert` is what actually stops a screen
    // reader's virtual cursor and Tab from reaching content behind the modal.
    const root = document.getElementById('root');
    root?.setAttribute('inert', '');

    panelRef.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const panel = panelRef.current;
      if (!panel) return;
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);

    return () => {
      document.removeEventListener('keydown', onKey);
      root?.removeAttribute('inert');
      // The trigger may have unmounted along with whatever list produced it
      // (a row removed by the same action that closed the drawer); a focus()
      // on a detached element is a silent no-op, not an error, so this is
      // safe without an extra existence check.
      if (returnFocusTo.current instanceof HTMLElement) {
        returnFocusTo.current.focus();
      }
    };
  }, [onClose]);

  const Panel = variant === 'drawer' ? m.aside : m.div;

  return createPortal(
    <m.div
      className="drawer-scrim"
      onClick={onClose}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
    >
      <Panel
        className={variant}
        role="dialog"
        aria-modal="true"
        {...aria}
        tabIndex={-1}
        ref={panelRef}
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
        {...VARIANTS[variant]}
        transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
      >
        {children}
      </Panel>
    </m.div>,
    document.body,
  );
}
