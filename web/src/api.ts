import axios from 'axios'

export const sessionTokenKey = 'guardian.session'

export type SetupStatus = {
  bootstrap_required: boolean
}

export type Principal = {
  user_id: string
  username: string
  display_name: string
  roles: string[]
  permissions: string[]
}

export type Device = {
  id: string
  name: string
  device_uuid: string
  serial_number?: string
  primary_mac?: string
  status: string
  suspended: boolean
  created_at: string
  updated_at: string
  last_seen_at?: string
}

export type DeviceTelemetry = {
  id: string
  device_id: string
  observed_at: string
  tunnel_state: string
  latest_handshake_at?: string
  endpoint?: string
  assigned_address?: string
  rx_bytes: number
  tx_bytes: number
  tunnel_uptime_seconds: number
  latency_ms?: number
  config_revision: number
  arlanphone_version?: string
  agent_version?: string
  wireguard_version?: string
  error_code?: string
  error_message?: string
}

export type DeviceList = {
  items: Device[]
  total: number
  limit: number
  offset: number
}

export const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10_000,
})

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem(sessionTokenKey)
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export function saveSession(token: string) {
  sessionStorage.setItem(sessionTokenKey, token)
}

export function clearSession() {
  sessionStorage.removeItem(sessionTokenKey)
}

export function hasSession() {
  return Boolean(sessionStorage.getItem(sessionTokenKey))
}

export async function getSetupStatus() {
  const { data } = await api.get<SetupStatus>('/setup/status')
  return data
}

export async function getMe() {
  const { data } = await api.get<Principal>('/me')
  return data
}

export async function login(username: string, password: string) {
  const { data } = await api.post<{ token: string; expires_at: string }>('/auth/login', { username, password })
  return data
}

export async function bootstrap(username: string, displayName: string, password: string) {
  const { data } = await api.post<{ token: string; expires_at: string }>('/auth/bootstrap', {
    username,
    display_name: displayName,
    password,
  })
  return data
}

export async function logout() {
  await api.post('/auth/logout')
}

export async function listDevices(limit = 100, offset = 0) {
  const { data } = await api.get<DeviceList>('/devices', { params: { limit, offset } })
  return data
}

export async function getDevice(deviceId: string) {
  const { data } = await api.get<Device>(`/devices/${encodeURIComponent(deviceId)}`)
  return data
}

export async function getLatestTelemetry(deviceId: string): Promise<DeviceTelemetry | null> {
  try {
    const { data } = await api.get<DeviceTelemetry>(`/devices/${encodeURIComponent(deviceId)}/telemetry/latest`)
    return data
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null
    throw error
  }
}
