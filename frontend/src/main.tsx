import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from './App';
import './design/tokens.css';
import './design/app.css';

// Server state lives here and ONLY here (docs/07-FRONTEND-SPEC.md §1).
// Zustand holds theme, sidebar and the generate-wizard draft — nothing that
// round-trips. Duplicating API responses into a client store is how two
// sources of truth start disagreeing.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: (failureCount, error) => {
        // Never retry a 4xx: the request is wrong, and retrying just makes
        // the user wait longer for the same answer.
        const status = (error as { status?: number })?.status;
        if (status && status >= 400 && status < 500) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
    },
  },
});

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root not found');

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
