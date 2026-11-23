import { lazy, Suspense } from 'react';
import { useResource, useRoute } from './lib/hooks.ts';
import type { HealthResponse } from './lib/api.ts';
import { Spinner } from './components/ui.tsx';
import { Icon } from './components/icons.tsx';
import { Overview } from './pages/Overview.tsx';

const Events = lazy(() => import('./pages/Events.tsx').then(module => ({ default: module.Events })));
const Pods = lazy(() => import('./pages/Pods.tsx').then(module => ({ default: module.Pods })));
const PodInspector = lazy(() => import('./pages/PodInspector.tsx').then(module => ({ default: module.PodInspector })));
const Collectors = lazy(() => import('./pages/Collectors.tsx').then(module => ({ default: module.Collectors })));
const NetworkMap = lazy(() => import('./pages/NetworkMap.tsx').then(module => ({ default: module.NetworkMap })));

const nav = [
  { id: '', label: 'Overview', icon: 'overview' },
  { id: 'events', label: 'Events', icon: 'events' },
  { id: 'pods', label: 'Pods', icon: 'pods' },
  { id: 'map', label: 'Network map', icon: 'map' },
  { id: 'collectors', label: 'Collectors', icon: 'collectors' },
];

export function App() {
  const route = useRoute();
  const [section = '', ...rest] = route.path;
  // One light poll drives the health dot in the sidebar.
  const health = useResource<HealthResponse>('/api/collectors', 60_000);
  const unhealthy = (health.data?.collectors ?? []).filter(collector => collector.state !== 'ok');
  const severe = unhealthy.some(collector => collector.state === 'failing' || collector.state === 'stale');
  const healthTitle = unhealthy.length
    ? unhealthy.map(collector => `${collector.CollectorID}: ${collector.state}`).join(', ') + ' (see Collectors)'
    : 'All collectors healthy';
  const version = useResource<{ version: string }>('/api/version');

  let page;
  switch (section) {
    case 'events': page = <Events query={route.query} />; break;
    case 'pods': page = rest.length ? <PodInspector path={rest} query={route.query} /> : <Pods query={route.query} />; break;
    case 'map': page = <NetworkMap />; break;
    case 'collectors': page = <Collectors />; break;
    default: page = <Overview />;
  }

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Sections">
        <div className="brand"><img src="./favicon.svg" alt="" /><span>Net Watcher<small>network audit</small></span></div>
        {nav.map(item => (
          <a key={item.id} href={`#/${item.id}`} className={`nav-link ${section === item.id ? 'active' : ''}`} aria-current={section === item.id ? 'page' : undefined}>
            <Icon name={item.icon} />{item.label}
            {item.id === 'collectors' && health.data && <span className={`dot ${severe ? 'danger' : unhealthy.length ? 'warn' : 'ok'}`} title={healthTitle} role="img" aria-label={healthTitle} />}
          </a>
        ))}
        <div className="sidebar-foot">{version.data?.version ? `v${version.data.version.replace(/^v/, '')}` : ''}</div>
      </nav>
      <main className="main">
        <Suspense fallback={<Spinner />}>{page}</Suspense>
      </main>
    </div>
  );
}
