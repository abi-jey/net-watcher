import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/app.css';
import { App } from './App.tsx';

// After a deploy, an open tab still references the previous build's page
// chunks, which no longer exist: load the new build once instead of failing.
// A second failure within 10 s is left to the page's error message.
// The import still fails (the page's error boundary shows it) until the reload
// replaces the page; suppressing it would hand the page wrapper no module.
window.addEventListener('vite:preloadError', () => {
  const last = Number(sessionStorage.getItem('nw-chunk-reload') ?? 0);
  if (Date.now() - last < 10_000) return;
  sessionStorage.setItem('nw-chunk-reload', String(Date.now()));
  location.reload();
});

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
