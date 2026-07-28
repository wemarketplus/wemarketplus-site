import type { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { BrowserRouter } from 'react-router-dom';
import { Toaster } from 'sonner';
import { ProfileSync } from '@/modules/auth';
import { ThemeProvider } from '@/shared/contexts';
import { persistor, store } from './store';

interface ProvidersProps {
  children: ReactNode;
}

function PersistLoadingFallback() {
  return (
    <div className="flex h-screen w-full items-center justify-center bg-bg">
      <div className="text-sm text-muted">Loading…</div>
    </div>
  );
}

export function Providers({ children }: ProvidersProps) {
  return (
    <Provider store={store}>
      <PersistGate loading={<PersistLoadingFallback />} persistor={persistor}>
        <ThemeProvider>
          <ProfileSync />
          <BrowserRouter>{children}</BrowserRouter>
          <Toaster position="top-right" richColors closeButton />
        </ThemeProvider>
      </PersistGate>
    </Provider>
  );
}
