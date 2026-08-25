/**
 * Shell state: the sidebar.
 *
 * ⚠ ONE OF THE FEW THINGS ZUSTAND MAY HOLD, for the same reason the theme is —
 * it never round-trips to a server. Server data lives in TanStack Query and
 * nowhere else (docs/07-FRONTEND-SPEC.md §1).
 *
 * Two pieces of state that look similar and are not:
 *
 *   `collapsed`  a persistent PREFERENCE. Survives reloads, and is written to
 *                the document before first paint by the bootstrap script in
 *                index.html — see applySidebar.
 *   `navOpen`    a transient mobile OVERLAY. Deliberately NOT persisted: an
 *                app that reopens a modal navigation drawer on every load
 *                because you left it open once is broken, not helpful.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type SidebarState = 'expanded' | 'collapsed';

interface ShellState {
  collapsed: boolean;
  toggleCollapsed: () => void;
  navOpen: boolean;
  setNavOpen: (open: boolean) => void;
}

export const useShell = create<ShellState>()(
  persist(
    (set) => ({
      collapsed: false,
      toggleCollapsed: () =>
        set((s) => {
          const collapsed = !s.collapsed;
          applySidebar(collapsed);
          return { collapsed };
        }),

      navOpen: false,
      setNavOpen: (navOpen) => {
        set({ navOpen });
        document.documentElement.toggleAttribute('data-nav-open', navOpen);
      },
    }),
    {
      name: 'axebom.shell',
      // ⚠ COLLAPSED ONLY. Persisting navOpen would restore a modal overlay on
      // load, over a page the user has not asked for yet.
      partialize: (s) => ({ collapsed: s.collapsed }),
      onRehydrateStorage: () => (state) => {
        if (state) applySidebar(state.collapsed);
      },
    },
  ),
);

/**
 * applySidebar writes the preference to the document element.
 *
 * ⚠ ON documentElement, NOT ON .app — and that is the whole point. The
 * blocking script in index.html runs before React exists and can only reach
 * <html>. Without it the sidebar rehydrates after mount and every cold load
 * shows a visible 15rem → 4rem jump, which is the same class of bug the theme
 * bootstrap exists to prevent.
 *
 * The attribute is REMOVED rather than set to "expanded", so the default lives
 * in exactly one place: --sidebar-w on :root.
 */
export function applySidebar(collapsed: boolean): void {
  const root = document.documentElement;
  if (collapsed) {
    root.setAttribute('data-sidebar', 'collapsed');
  } else {
    root.removeAttribute('data-sidebar');
  }
}
