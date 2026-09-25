import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Link,
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
  useRouterState,
} from '@tanstack/react-router'
import { AuthGate } from './auth'
import { clearSession, getMe, listDevices, logout } from './api'
import { AuditPage, CommandsPage, RolesPage, SettingsPage, UsersPage } from './admin'
import { DeviceDetailPage, DevicesPage } from './devices'
import { EnrollmentsPage } from './enrollments'
import { AddressPoolsPage, VPNProfilesPage } from './network-config'
import './styles.css'
import './enrollments.css'
import './commands.css'
import './network-config.css'
import './admin.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5_000, retry: 1 },
  },
})

const navigation = [
  { icon: 'dashboard', label: 'Dashboard', to: '/', permission: '' },
  { icon: 'devices', label: 'Devices', to: '/devices', permission: 'devices.read' },
  { icon: 'qr_code_2', label: 'Enrollments', to: '/enrollments', permission: 'enrollment.read' },
  { icon: 'vpn_key', label: 'VPN Profiles', to: '/vpn-profiles', permission: 'profiles.read' },
  { icon: 'lan', label: 'Address Pools', to: '/address-pools', permission: 'pools.read' },
  { icon: 'terminal', label: 'Commands', to: '/commands', permission: 'commands.read' },
  { icon: 'group', label: 'Users', to: '/users', permission: 'users.read' },
  { icon: 'admin_panel_settings', label: 'Roles', to: '/roles', permission: 'roles.read' },
  { icon: 'history', label: 'Audit', to: '/audit', permission: 'audit.read' },
  { icon: 'settings', label: 'Settings', to: '/settings', permission: 'settings.read' },
] as const

function Root() {
  return <AuthGate><Shell /></AuthGate>
}

function pageTitle(pathname: string) {
  if (pathname.startsWith('/devices')) return 'Devices'
  if (pathname.startsWith('/enrollments')) return 'Enrollments'
  if (pathname.startsWith('/vpn-profiles')) return 'VPN Profiles'
  if (pathname.startsWith('/address-pools')) return 'Address Pools'
  if (pathname.startsWith('/commands')) return 'Commands'
  if (pathname.startsWith('/users')) return 'Users'
  if (pathname.startsWith('/roles')) return 'Roles'
  if (pathname.startsWith('/audit')) return 'Audit'
  if (pathname.startsWith('/settings')) return 'Settings'
  return 'Dashboard'
}

function Shell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const [dark, setDark] = React.useState(() => {
    const saved = localStorage.getItem('guardian.theme')
    return saved ? saved === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches
  })
  React.useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
    localStorage.setItem('guardian.theme', dark ? 'dark' : 'light')
  }, [dark])

  const signOut = useMutation({
    mutationFn: logout,
    onSettled: () => {
      clearSession()
      queryClient.clear()
      window.location.assign('/')
    },
  })
  const permissions = new Set(principal.data?.permissions ?? [])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="material-symbols-rounded">shield</span>
          <span>Guardian</span>
        </div>
        <nav>
          {navigation.filter((item) => !item.permission || permissions.has(item.permission)).map((item) => {
            const active = item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)
            return <Link className={active ? 'nav-item active' : 'nav-item'} key={item.label} to={item.to}><span className="material-symbols-rounded">{item.icon}</span><span>{item.label}</span></Link>
          })}
        </nav>
        <div className="sidebar-footer">WireGuard control plane</div>
      </aside>
      <main className="content">
        <header className="topbar">
          <div>
            <div className="eyebrow">Secure access management</div>
            <h1>{pageTitle(pathname)}</h1>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" aria-label="Toggle theme" type="button" onClick={() => setDark((value) => !value)}><span className="material-symbols-rounded">{dark ? 'light_mode' : 'dark_mode'}</span></button>
            <button className="icon-button" aria-label="Sign out" disabled={signOut.isPending} type="button" onClick={() => signOut.mutate()}><span className="material-symbols-rounded">logout</span></button>
          </div>
        </header>
        <Outlet />
      </main>
    </div>
  )
}

function Dashboard() {
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const canReadDevices = Boolean(principal.data?.permissions.includes('devices.read'))
  const query = useQuery({ queryKey: ['devices'], queryFn: () => listDevices(100, 0), refetchInterval: 15_000, enabled: canReadDevices })
  if (principal.isPending) return <article className="panel loading-panel">Loading…</article>
  if (!canReadDevices) return <article className="panel dashboard-panel"><div><h2>Guardian administration</h2><p>Your account is authenticated, but it does not have permission to read managed devices. Use the navigation items available to your role.</p></div></article>
  if (query.isPending) return <article className="panel loading-panel">Loading…</article>
  if (query.isError) return <article className="alert danger">Unable to load device inventory.</article>

  const devices = query.data.items
  const active = devices.filter((device) => device.status === 'active' && !device.suspended).length
  const suspended = devices.filter((device) => device.suspended).length
  const recentlySeen = devices.filter((device) => {
    if (!device.last_seen_at) return false
    const timestamp = new Date(device.last_seen_at).getTime()
    return Number.isFinite(timestamp) && Date.now() - timestamp < 5 * 60 * 1000
  }).length
  const cards = [
    ['devices', 'Managed devices', query.data.total],
    ['shield_lock', 'Active', active],
    ['wifi_tethering', 'Seen in 5 min', recentlySeen],
    ['pause_circle', 'Suspended', suspended],
  ] as const

  return (
    <section>
      <div className="cards">
        {cards.map(([icon, label, value]) => <article className="card" key={label}><div className="card-icon material-symbols-rounded">{icon}</div><div className="metric">{value}</div><div className="metric-label">{label}</div></article>)}
      </div>
      <article className="panel dashboard-panel">
        <div><div className="eyebrow">Device observability</div><h2>Guardian is receiving managed-device state</h2><p>Open Devices to inspect enrollment state and the latest WireGuard handshake, traffic counters, endpoint and tunnel uptime reported by ArlanPhone.</p></div>
        <Link className="secondary-button link-button" to="/devices">Open devices</Link>
      </article>
    </section>
  )
}

function DeviceDetailRoute() {
  const { deviceId } = deviceRoute.useParams()
  return <DeviceDetailPage deviceId={deviceId} />
}

const rootRoute = createRootRoute({ component: Root })
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: Dashboard })
const devicesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/devices', component: DevicesPage })
const deviceRoute = createRoute({ getParentRoute: () => rootRoute, path: '/devices/$deviceId', component: DeviceDetailRoute })
const enrollmentsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/enrollments', component: EnrollmentsPage })
const vpnProfilesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/vpn-profiles', component: VPNProfilesPage })
const addressPoolsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/address-pools', component: AddressPoolsPage })
const commandsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/commands', component: CommandsPage })
const usersRoute = createRoute({ getParentRoute: () => rootRoute, path: '/users', component: UsersPage })
const rolesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/roles', component: RolesPage })
const auditRoute = createRoute({ getParentRoute: () => rootRoute, path: '/audit', component: AuditPage })
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/settings', component: SettingsPage })
const routeTree = rootRoute.addChildren([indexRoute, devicesRoute, deviceRoute, enrollmentsRoute, vpnProfilesRoute, addressPoolsRoute, commandsRoute, usersRoute, rolesRoute, auditRoute, settingsRoute])
const router = createRouter({ routeTree })

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
)
