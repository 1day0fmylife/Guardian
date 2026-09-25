import axios from 'axios'

export const sessionTokenKey = 'guardian.session'

export type SetupStatus = { bootstrap_required: boolean }
export type Principal = { user_id: string; username: string; display_name: string; roles: string[]; permissions: string[] }
export type Device = { id: string; name: string; device_uuid: string; serial_number?: string; primary_mac?: string; status: string; suspended: boolean; created_at: string; updated_at: string; last_seen_at?: string }
export type DeviceTelemetry = { id: string; device_id: string; observed_at: string; tunnel_state: string; latest_handshake_at?: string; endpoint?: string; assigned_address?: string; rx_bytes: number; tx_bytes: number; tunnel_uptime_seconds: number; latency_ms?: number; config_revision: number; arlanphone_version?: string; agent_version?: string; wireguard_version?: string; error_code?: string; error_message?: string }
export type DeviceList = { items: Device[]; total: number; limit: number; offset: number }
export type VPNProfile = { id: string; name: string; server_public_key: string; endpoint: string; allowed_ips: string[]; dns_servers?: string[]; persistent_keepalive: number; address_pool_id: string; created_at: string; updated_at: string }
export type AddressPool = { id: string; name: string; cidr: string; gateway?: string; dns_servers?: string[]; created_at: string; updated_at: string }
export type Enrollment = { id: string; name?: string; profile_id: string; bound_device_uuid?: string; bound_serial_number?: string; bound_mac?: string; expires_at: string; consumed_at?: string; revoked_at?: string; created_at: string }
export type EnrollmentList = { items: Enrollment[]; total: number; limit: number; offset: number }
export type IssuedEnrollment = { enrollment: Enrollment; token: string; provisioning_uri: string; claim_url: string }
export type EnrollmentCreate = { name: string; profile_id: string; bound_device_uuid: string; bound_serial_number: string; bound_mac: string; ttl_seconds: number }
export type DeviceCommand = { id: string; device_id: string; device_name?: string; device_uuid?: string; type: string; status: string; idempotency_key: string; payload: Record<string, unknown>; result?: Record<string, unknown>; error_message?: string; created_at: string; delivered_at?: string; acknowledged_at?: string; finished_at?: string; expires_at: string }
export type User = { id: string; username: string; display_name: string; disabled: boolean; roles: string[]; created_at: string; updated_at: string }
export type Role = { id: string; name: string; description: string; system: boolean; permissions: string[] }
export type AuditEvent = { id: string; actor_user_id?: string; action: string; resource_type: string; resource_id?: string; source_ip?: string; request_id?: string; details?: string; created_at: string }
export type SystemSettings = { values: Record<string, string>; public_url: string; editable: string[] }

export const api = axios.create({ baseURL: '/api/v1', timeout: 10_000 })
api.interceptors.request.use((config) => { const token = sessionStorage.getItem(sessionTokenKey); if (token) config.headers.Authorization = `Bearer ${token}`; return config })

export function saveSession(token: string) { sessionStorage.setItem(sessionTokenKey, token) }
export function clearSession() { sessionStorage.removeItem(sessionTokenKey) }
export function hasSession() { return Boolean(sessionStorage.getItem(sessionTokenKey)) }
export async function getSetupStatus() { const { data } = await api.get<SetupStatus>('/setup/status'); return data }
export async function getMe() { const { data } = await api.get<Principal>('/me'); return data }
export async function login(username: string, password: string) { const { data } = await api.post<{ token: string; expires_at: string }>('/auth/login', { username, password }); return data }
export async function bootstrap(username: string, displayName: string, password: string) { const { data } = await api.post<{ token: string; expires_at: string }>('/auth/bootstrap', { username, display_name: displayName, password }); return data }
export async function logout() { await api.post('/auth/logout') }
export async function listDevices(limit = 100, offset = 0) { const { data } = await api.get<DeviceList>('/devices', { params: { limit, offset } }); return data }
export async function getDevice(deviceId: string) { const { data } = await api.get<Device>(`/devices/${encodeURIComponent(deviceId)}`); return data }
export async function getLatestTelemetry(deviceId: string): Promise<DeviceTelemetry | null> { try { const { data } = await api.get<DeviceTelemetry>(`/devices/${encodeURIComponent(deviceId)}/telemetry/latest`); return data } catch (error) { if (axios.isAxiosError(error) && error.response?.status === 404) return null; throw error } }
export async function listVPNProfiles() { const { data } = await api.get<{ items: VPNProfile[] }>('/vpn-profiles'); return data.items }
export async function createVPNProfile(input: { name: string; server_public_key: string; endpoint: string; allowed_ips: string[]; dns_servers: string[]; persistent_keepalive: number; address_pool_id: string }) { const { data } = await api.post<VPNProfile>('/vpn-profiles', input); return data }
export async function listAddressPools() { const { data } = await api.get<{ items: AddressPool[] }>('/address-pools'); return data.items }
export async function createAddressPool(input: { name: string; cidr: string; gateway: string; dns_servers: string[] }) { const { data } = await api.post<AddressPool>('/address-pools', input); return data }
export async function listEnrollments(limit = 100, offset = 0) { const { data } = await api.get<EnrollmentList>('/enrollments', { params: { limit, offset } }); return data }
export async function createEnrollment(input: EnrollmentCreate) { const { data } = await api.post<IssuedEnrollment>('/enrollments', input); return data }
export async function revokeEnrollment(enrollmentId: string) { await api.post(`/enrollments/${encodeURIComponent(enrollmentId)}/revoke`) }
export async function listDeviceCommands(deviceId: string) { const { data } = await api.get<{ items: DeviceCommand[]; total: number }>(`/devices/${encodeURIComponent(deviceId)}/commands`, { params: { limit: 50, offset: 0 } }); return data }
export async function createDeviceCommand(deviceId: string, type: string) { const { data } = await api.post<DeviceCommand>(`/devices/${encodeURIComponent(deviceId)}/commands`, { type, idempotency_key: `${type}-${crypto.randomUUID()}`, payload: {}, ttl_seconds: 300 }); return data }
export async function suspendDevice(deviceId: string) { const { data } = await api.post(`/devices/${encodeURIComponent(deviceId)}/suspend`); return data }
export async function resumeDevice(deviceId: string) { const { data } = await api.post(`/devices/${encodeURIComponent(deviceId)}/resume`); return data }
export async function listUsers() { const { data } = await api.get<{ items: User[] }>('/users'); return data.items }
export async function createUser(input: { username: string; display_name: string; password: string; roles: string[] }) { const { data } = await api.post<User>('/users', input); return data }
export async function updateUser(id: string, input: { display_name: string; disabled: boolean; roles: string[] }) { const { data } = await api.patch<User>(`/users/${encodeURIComponent(id)}`, input); return data }
export async function resetUserPassword(id: string, password: string) { await api.post(`/users/${encodeURIComponent(id)}/password`, { password }) }
export async function listRoles() { const { data } = await api.get<{ items: Role[] }>('/roles'); return data.items }
export async function listPermissions() { const { data } = await api.get<{ items: string[] }>('/permissions'); return data.items }
export async function createRole(input: { name: string; description: string; permissions: string[] }) { const { data } = await api.post<Role>('/roles', input); return data }
export async function updateRole(id: string, input: { description: string; permissions: string[] }) { const { data } = await api.patch<Role>(`/roles/${encodeURIComponent(id)}`, input); return data }
export async function listAudit(limit = 100, offset = 0) { const { data } = await api.get<{ items: AuditEvent[]; total: number; limit: number; offset: number }>('/audit', { params: { limit, offset } }); return data }
export async function listCommands(limit = 100, offset = 0) { const { data } = await api.get<{ items: DeviceCommand[]; total: number; limit: number; offset: number }>('/commands', { params: { limit, offset } }); return data }
export async function getSettings() { const { data } = await api.get<SystemSettings>('/settings'); return data }
export async function updateSettings(values: Record<string, string>) { const { data } = await api.patch<SystemSettings>('/settings', { values }); return data }
