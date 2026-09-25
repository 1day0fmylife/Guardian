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

export type DeviceCommandType = 'connect' | 'disconnect' | 'apply-config' | 'rotate-key'

export type DeviceCommand = {
  id: string
  device_id: string
  type: DeviceCommandType
  status: string
  idempotency_key: string
  payload: Record<string, unknown>
  result?: Record<string, unknown>
  error_message?: string
  created_at: string
  delivered_at?: string
  acknowledged_at?: string
  finished_at?: string
  expires_at: string
}

export type DeviceCommandList = {
  items: DeviceCommand[]
  total: number
  limit: number
  offset: number
}

export type VPNProfile = {
  id: string
  name: string
  server_public_key: string
  endpoint: string
  allowed_ips: string[]
  dns_servers?: string[]
  persistent_keepalive: number
  address_pool_id: string
  created_at: string
  updated_at: string
}

export type Enrollment = {
  id: string
  name?: string
  profile_id: string
  bound_device_uuid?: string
  bound_serial_number?: string
  bound_mac?: string
  expires_at: string
  consumed_at?: string
  revoked_at?: string
  created_at: string
}

export type EnrollmentList = {
  items: Enrollment[]
  total: number
  limit: number
  offset: number
}

export type IssuedEnrollment = {
  enrollment: Enrollment
  token: string
  provisioning_uri: string
  claim_url: string
}

export type EnrollmentCreate = {
  name: string
  profile_id: string
  bound_device_uuid: string
  bound_serial_number: string
  bound_mac: string
  ttl_seconds: number
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

export async function listDeviceCommands(deviceId: string, limit = 50, offset = 0) {
  const { data } = await api.get<DeviceCommandList>(`/devices/${encodeURIComponent(deviceId)}/commands`, { params: { limit, offset } })
  return data
}

export async function createDeviceCommand(deviceId: string, type: DeviceCommandType) {
  const { data } = await api.post<DeviceCommand>(`/devices/${encodeURIComponent(deviceId)}/commands`, {
    type,
    idempotency_key: '',
    payload: {},
    ttl_seconds: 300,
  })
  return data
}

export async function suspendDevice(deviceId: string) {
  await api.post(`/devices/${encodeURIComponent(deviceId)}/suspend`)
}

export async function resumeDevice(deviceId: string) {
  await api.post(`/devices/${encodeURIComponent(deviceId)}/resume`)
}

export async function listVPNProfiles() {
  const { data } = await api.get<{ items: VPNProfile[] }>('/vpn-profiles')
  return data.items
}

export async function listEnrollments(limit = 100, offset = 0) {
  const { data } = await api.get<EnrollmentList>('/enrollments', { params: { limit, offset } })
  return data
}

export async function createEnrollment(input: EnrollmentCreate) {
  const { data } = await api.post<IssuedEnrollment>('/enrollments', input)
  return data
}

export async function revokeEnrollment(enrollmentId: string) {
  await api.post(`/enrollments/${encodeURIComponent(enrollmentId)}/revoke`)
}
