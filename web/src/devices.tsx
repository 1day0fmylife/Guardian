import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import axios from 'axios'
import {
  createDeviceCommand,
  getDevice,
  getLatestTelemetry,
  getMe,
  listDeviceCommands,
  listDevices,
  resumeDevice,
  suspendDevice,
  type Device,
  type DeviceCommand,
  type DeviceCommandType,
  type DeviceTelemetry,
} from './api'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : 'Request failed'
}

export function DevicesPage() {
  const query = useQuery({
    queryKey: ['devices'],
    queryFn: () => listDevices(100, 0),
    refetchInterval: 15_000,
  })
  const columns = React.useMemo<ColumnDef<Device>[]>(() => [
    {
      accessorKey: 'name',
      header: 'Device',
      cell: ({ row }) => <div className="device-name"><Link to="/devices/$deviceId" params={{ deviceId: row.original.id }}>{row.original.name}</Link><span>{row.original.device_uuid}</span></div>,
    },
    { accessorKey: 'status', header: 'Status', cell: ({ row }) => <StatusBadge state={row.original.status} suspended={row.original.suspended} /> },
    { accessorKey: 'primary_mac', header: 'MAC', cell: ({ getValue }) => <span className="mono">{String(getValue() || '—')}</span> },
    { accessorKey: 'last_seen_at', header: 'Last seen', cell: ({ getValue }) => formatRelative(String(getValue() || '')) },
    { accessorKey: 'updated_at', header: 'Updated', cell: ({ getValue }) => formatDate(String(getValue() || '')) },
  ], [])
  const table = useReactTable({ data: query.data?.items ?? [], columns, getCoreRowModel: getCoreRowModel() })

  if (query.isPending) return <LoadingPanel />
  if (query.isError) return <ErrorPanel error={query.error} retry={() => query.refetch()} />

  return (
    <section className="page-stack">
      <div className="section-heading">
        <div><div className="eyebrow">Inventory</div><h2>Managed devices</h2><p>ArlanPhone endpoints enrolled in Guardian.</p></div>
        <span className="count-chip">{query.data.total} total</span>
      </div>
      <article className="table-panel">
        <div className="table-scroll">
          <table className="data-table">
            <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}>{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead>
            <tbody>
              {table.getRowModel().rows.map((row) => <tr key={row.id}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
              {table.getRowModel().rows.length === 0 && <tr><td className="empty-cell" colSpan={columns.length}>No devices enrolled yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </article>
    </section>
  )
}

export function DeviceDetailPage({ deviceId }: { deviceId: string }) {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const query = useQuery({
    queryKey: ['device-detail', deviceId],
    queryFn: async () => {
      const [device, telemetry] = await Promise.all([getDevice(deviceId), getLatestTelemetry(deviceId)])
      return { device, telemetry }
    },
    refetchInterval: 10_000,
  })
  const canReadCommands = Boolean(principal.data?.permissions.includes('commands.read'))
  const commands = useQuery({
    queryKey: ['device-commands', deviceId],
    queryFn: () => listDeviceCommands(deviceId, 50, 0),
    enabled: canReadCommands,
    refetchInterval: 5_000,
  })
  const [actionMessage, setActionMessage] = React.useState('')

  const commandMutation = useMutation({
    mutationFn: (type: DeviceCommandType) => createDeviceCommand(deviceId, type),
    onSuccess: async (command) => {
      setActionMessage(`${humanCommandType(command.type)} queued.`)
      await queryClient.invalidateQueries({ queryKey: ['device-commands', deviceId] })
    },
  })
  const lifecycleMutation = useMutation({
    mutationFn: (operation: 'suspend' | 'resume') => operation === 'suspend' ? suspendDevice(deviceId) : resumeDevice(deviceId),
    onSuccess: async (_, operation) => {
      setActionMessage(operation === 'suspend' ? 'Suspension requested; disconnect queued.' : 'Resume requested; connect queued.')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['device-detail', deviceId] }),
        queryClient.invalidateQueries({ queryKey: ['device-commands', deviceId] }),
        queryClient.invalidateQueries({ queryKey: ['devices'] }),
      ])
    },
  })

  if (query.isPending) return <LoadingPanel />
  if (query.isError) return <ErrorPanel error={query.error} retry={() => query.refetch()} />
  const { device, telemetry } = query.data
  const permissions = new Set(principal.data?.permissions ?? [])
  const canCreateCommand = permissions.has('commands.create')
  const unavailableForActiveCommand = device.suspended || device.status === 'revoking'
  const mutationError = commandMutation.error || lifecycleMutation.error

  const commandActions: Array<{ type: DeviceCommandType; label: string; icon: string; permission: string; confirm?: string; disabledWhenSuspended?: boolean }> = [
    { type: 'connect', label: 'Connect', icon: 'play_arrow', permission: 'devices.connect', disabledWhenSuspended: true },
    { type: 'disconnect', label: 'Disconnect', icon: 'stop_circle', permission: 'devices.disconnect', confirm: 'Queue a disconnect command for this device?' },
    { type: 'apply-config', label: 'Apply config', icon: 'sync', permission: 'devices.reconfigure', disabledWhenSuspended: true },
    { type: 'rotate-key', label: 'Rotate key', icon: 'key', permission: 'devices.rotate_key', confirm: 'Rotate this device WireGuard key? The device must stay reachable during reconciliation.', disabledWhenSuspended: true },
  ]

  function queueCommand(action: (typeof commandActions)[number]) {
    if (action.confirm && !window.confirm(action.confirm)) return
    setActionMessage('')
    commandMutation.mutate(action.type)
  }

  function changeLifecycle(operation: 'suspend' | 'resume') {
    const message = operation === 'suspend'
      ? 'Suspend this device? Guardian will keep the management channel available only to deliver disconnect and receive status.'
      : 'Resume this device and queue a connect command?'
    if (!window.confirm(message)) return
    setActionMessage('')
    lifecycleMutation.mutate(operation)
  }

  return (
    <section className="page-stack">
      <div className="detail-heading">
        <div><Link className="back-link" to="/devices">← Devices</Link><h2>{device.name}</h2><p className="mono">{device.device_uuid}</p></div>
        <StatusBadge state={device.status} suspended={device.suspended} />
      </div>

      {(canCreateCommand || permissions.has('devices.update')) && (
        <article className="panel device-actions-panel">
          <div className="device-actions-heading">
            <div><div className="eyebrow">Remote management</div><h2>Device actions</h2><p>Commands are durable in Guardian. WebSocket wakes the phone immediately when available; HTTP polling remains the fallback.</p></div>
            {(commandMutation.isPending || lifecycleMutation.isPending) && <span className="status">Queuing…</span>}
          </div>
          <div className="device-actions">
            {commandActions.map((action) => {
              const allowed = canCreateCommand && permissions.has(action.permission)
              if (!allowed) return null
              const disabled = commandMutation.isPending || lifecycleMutation.isPending || (Boolean(action.disabledWhenSuspended) && unavailableForActiveCommand)
              return <button className="secondary-button action-button" disabled={disabled} key={action.type} type="button" onClick={() => queueCommand(action)}><span className="material-symbols-rounded">{action.icon}</span>{action.label}</button>
            })}
            {permissions.has('devices.update') && (device.suspended
              ? <button className="primary-button action-button" disabled={commandMutation.isPending || lifecycleMutation.isPending} type="button" onClick={() => changeLifecycle('resume')}><span className="material-symbols-rounded">resume</span>Resume</button>
              : <button className="secondary-button action-button danger-outline" disabled={commandMutation.isPending || lifecycleMutation.isPending} type="button" onClick={() => changeLifecycle('suspend')}><span className="material-symbols-rounded">pause_circle</span>Suspend</button>)}
          </div>
          {actionMessage && <div className="alert success compact-alert">{actionMessage}</div>}
          {mutationError && <div className="alert danger compact-alert">{errorMessage(mutationError)}</div>}
        </article>
      )}

      <div className="detail-grid">
        <InfoCard title="Device identity" icon="devices">
          <InfoRow label="Serial" value={device.serial_number || '—'} mono />
          <InfoRow label="Primary MAC" value={device.primary_mac || '—'} mono />
          <InfoRow label="Last seen" value={device.last_seen_at ? `${formatRelative(device.last_seen_at)} · ${formatDate(device.last_seen_at)}` : 'Never'} />
          <InfoRow label="Created" value={formatDate(device.created_at)} />
        </InfoCard>
        <InfoCard title="Tunnel" icon="shield_lock">
          <InfoRow label="State" value={telemetry ? humanState(telemetry.tunnel_state) : 'No telemetry'} />
          <InfoRow label="VPN address" value={telemetry?.assigned_address || '—'} mono />
          <InfoRow label="Observed endpoint" value={telemetry?.endpoint || '—'} mono />
          <InfoRow label="Config revision" value={telemetry ? `revision ${telemetry.config_revision}` : '—'} />
        </InfoCard>
      </div>
      <RuntimeTelemetry telemetry={telemetry} />
      {telemetry?.error_code && <article className="alert danger runtime-error"><strong>{telemetry.error_code}</strong><span>{telemetry.error_message || 'Device reported a runtime error.'}</span></article>}
      {canReadCommands && <CommandHistory query={commands} />}
    </section>
  )
}

function CommandHistory({ query }: { query: ReturnType<typeof useQuery<{ items: DeviceCommand[]; total: number; limit: number; offset: number }>> }) {
  return (
    <article className="panel command-history-panel">
      <div className="telemetry-header"><div><div className="eyebrow">Control plane</div><h2>Command history</h2></div>{query.data && <span className="status">{query.data.total} commands</span>}</div>
      {query.isPending && <div className="inline-loading">Loading command history…</div>}
      {query.isError && <div className="alert danger compact-alert">{errorMessage(query.error)}</div>}
      {query.data && (
        <div className="table-scroll">
          <table className="data-table command-table">
            <thead><tr><th>Command</th><th>Status</th><th>Created</th><th>Finished</th><th>Result</th></tr></thead>
            <tbody>
              {query.data.items.map((command) => <CommandRow command={command} key={command.id} />)}
              {query.data.items.length === 0 && <tr><td className="empty-cell" colSpan={5}>No commands have been issued for this device.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </article>
  )
}

function CommandRow({ command }: { command: DeviceCommand }) {
  const terminal = ['succeeded', 'failed', 'expired'].includes(command.status)
  const result = command.error_message || (terminal && command.result && Object.keys(command.result).length > 0 ? JSON.stringify(command.result) : '—')
  return <tr><td><div className="command-name"><span className="material-symbols-rounded">{commandIcon(command.type)}</span><span>{humanCommandType(command.type)}</span></div></td><td><CommandStatusBadge status={command.status} /></td><td>{formatDate(command.created_at)}</td><td>{command.finished_at ? formatDate(command.finished_at) : '—'}</td><td className={command.error_message ? 'command-error' : 'mono command-result'}>{result}</td></tr>
}

function CommandStatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase()
  const tone = normalized === 'succeeded' ? 'ok' : normalized === 'failed' || normalized === 'expired' ? 'danger' : normalized === 'running' || normalized === 'delivered' ? 'warn' : 'neutral'
  return <span className={`badge ${tone}`}><span className="dot" />{humanState(normalized)}</span>
}

function commandIcon(type: DeviceCommandType) {
  switch (type) {
    case 'connect': return 'play_arrow'
    case 'disconnect': return 'stop_circle'
    case 'apply-config': return 'sync'
    case 'rotate-key': return 'key'
  }
}

function humanCommandType(type: DeviceCommandType) {
  switch (type) {
    case 'connect': return 'Connect'
    case 'disconnect': return 'Disconnect'
    case 'apply-config': return 'Apply config'
    case 'rotate-key': return 'Rotate key'
  }
}

function RuntimeTelemetry({ telemetry }: { telemetry: DeviceTelemetry | null }) {
  if (!telemetry) return <article className="panel telemetry-empty"><div><div className="eyebrow">Runtime telemetry</div><h2>No telemetry yet</h2><p>The device has not reported runtime state to Guardian.</p></div></article>
  return (
    <article className="panel telemetry-panel">
      <div className="telemetry-header"><div><div className="eyebrow">Runtime telemetry</div><h2>WireGuard observed state</h2></div><span className="status">Observed {formatRelative(telemetry.observed_at)}</span></div>
      <div className="metric-grid">
        <Metric label="Latest handshake" value={telemetry.latest_handshake_at ? formatRelative(telemetry.latest_handshake_at) : 'Never'} detail={telemetry.latest_handshake_at ? formatDate(telemetry.latest_handshake_at) : undefined} />
        <Metric label="Received" value={formatBytes(telemetry.rx_bytes)} />
        <Metric label="Transmitted" value={formatBytes(telemetry.tx_bytes)} />
        <Metric label="Tunnel uptime" value={formatDuration(telemetry.tunnel_uptime_seconds)} />
      </div>
      <div className="runtime-meta">
        <InfoRow label="ArlanPhone" value={telemetry.arlanphone_version || '—'} mono />
        <InfoRow label="Guardian agent" value={telemetry.agent_version || '—'} mono />
        <InfoRow label="WireGuard" value={telemetry.wireguard_version || '—'} mono />
        <InfoRow label="Latency" value={telemetry.latency_ms == null ? '—' : `${telemetry.latency_ms} ms`} />
      </div>
    </article>
  )
}

function InfoCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return <article className="panel info-card"><div className="card-title"><span className="material-symbols-rounded">{icon}</span><h2>{title}</h2></div>{children}</article>
}

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="info-row"><span>{label}</span><strong className={mono ? 'mono' : undefined}>{value}</strong></div>
}

function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return <div className="runtime-metric"><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div>
}

function StatusBadge({ state, suspended }: { state: string; suspended: boolean }) {
  const normalized = suspended ? 'suspended' : state.toLowerCase()
  const tone = normalized === 'active' ? 'ok' : normalized === 'suspended' || normalized === 'revoking' ? 'warn' : normalized === 'error' ? 'danger' : 'neutral'
  return <span className={`badge ${tone}`}><span className="dot" />{humanState(normalized)}</span>
}

function humanState(value: string) {
  return value ? value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()) : 'Unknown'
}

function formatDate(value: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function formatRelative(value: string) {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const delta = Math.round((date.getTime() - Date.now()) / 1000)
  const abs = Math.abs(delta)
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  if (abs < 60) return formatter.format(delta, 'second')
  if (abs < 3600) return formatter.format(Math.round(delta / 60), 'minute')
  if (abs < 86400) return formatter.format(Math.round(delta / 3600), 'hour')
  return formatter.format(Math.round(delta / 86400), 'day')
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  const number = value / 1024 ** index
  return `${number >= 10 || index === 0 ? number.toFixed(0) : number.toFixed(1)} ${units[index]}`
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${Math.floor(seconds % 60)}s`
  return `${Math.floor(seconds)}s`
}

function LoadingPanel() {
  return <article className="panel loading-panel">Loading…</article>
}

function ErrorPanel({ error, retry }: { error: unknown; retry: () => void }) {
  return <article className="alert danger"><span>{errorMessage(error)}</span><button className="secondary-button" type="button" onClick={retry}>Retry</button></article>
}
