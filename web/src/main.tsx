import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
} from '@tanstack/react-router'
import axios from 'axios'
import './styles.css'

const api = axios.create({ baseURL: '/api/v1', timeout: 10_000 })
const queryClient = new QueryClient()

const navigation = [
  ['dashboard', 'Dashboard'],
  ['devices', 'Devices'],
  ['qr_code_2', 'Enrollments'],
  ['vpn_key', 'VPN Profiles'],
  ['lan', 'Address Pools'],
  ['terminal', 'Commands'],
  ['group', 'Users'],
  ['admin_panel_settings', 'Roles'],
  ['history', 'Audit'],
  ['settings', 'Settings'],
] as const

function Shell() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="material-symbols-rounded">shield</span>
          <span>Guardian</span>
        </div>
        <nav>
          {navigation.map(([icon, label], index) => (
            <button className={index === 0 ? 'nav-item active' : 'nav-item'} key={label} type="button">
              <span className="material-symbols-rounded">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">WireGuard control plane</div>
      </aside>
      <main className="content">
        <header className="topbar">
          <div>
            <div className="eyebrow">Secure access management</div>
            <h1>Dashboard</h1>
          </div>
          <button className="icon-button" aria-label="Toggle theme" type="button">
            <span className="material-symbols-rounded">dark_mode</span>
          </button>
        </header>
        <Outlet />
      </main>
    </div>
  )
}

function Dashboard() {
  const cards = [
    ['devices', 'Managed devices', '0'],
    ['shield_lock', 'Connected', '0'],
    ['key', 'Active peers', '0'],
    ['warning', 'Needs attention', '0'],
  ]

  return (
    <section>
      <div className="cards">
        {cards.map(([icon, label, value]) => (
          <article className="card" key={label}>
            <div className="card-icon material-symbols-rounded">{icon}</div>
            <div className="metric">{value}</div>
            <div className="metric-label">{label}</div>
          </article>
        ))}
      </div>
      <article className="panel">
        <div>
          <div className="eyebrow">Bootstrap</div>
          <h2>Guardian control plane is ready for implementation</h2>
          <p>The next slice adds persistence, RBAC, device enrollment, WireGuard peer lifecycle and live device state.</p>
        </div>
        <span className="status">Phase 0</span>
      </article>
    </section>
  )
}

const rootRoute = createRootRoute({ component: Shell })
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: Dashboard,
})
const routeTree = rootRoute.addChildren([indexRoute])
const router = createRouter({ routeTree })

void api.get('').catch(() => undefined)

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
)
