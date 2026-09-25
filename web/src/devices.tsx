import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import axios from 'axios'
import {
  getDevice,
  getLatestTelemetry,
  listDevices,
  type Device,
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
  const query = useQuery({
    queryKey: ['device-detail', deviceId],
    queryFn: async () => {
      const [device, telemetry] = await Promise.all([getDevice(deviceId), getLatestTelemetry(deviceId)])
      return { device, telemetry }
    },
    refetchInterval: 10_000,
  })

  if (query.isPending) return <LoadingPanel />
  if (query.isError) return <ErrorPanel error={query.error} retry={() => query.refetch()} />
  const { device, telemetry } = query.data

  return (
    <section className="page-stack">
      <div className="detail-heading">
        <div><Link className="back-link" to="/devices">← Devices</Link><h2>{device.name}</h2><p className="mono">{device.device_uuid}</p></div>
        <StatusBadge state={device.status} suspended={device.suspended} />
      </div>
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
    </section>
  )
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
