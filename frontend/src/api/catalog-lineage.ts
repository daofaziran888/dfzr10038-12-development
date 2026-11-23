import { request } from './client'
import type {
  Attestation,
  Binding,
  CatalogPackage,
  IndexResult,
  PackageReport,
} from '@/data/catalog-lineage'

type ApiError = { code?: string; message?: string }

async function read<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const error = payload as ApiError
    throw new Error(error.message || `接口返回 ${response.status}`)
  }
  return payload as T
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request(path, { method: 'POST', body: JSON.stringify(body) }).then(read<T>)
}

export function loadIndex(params: { role: string; domain?: string }): Promise<IndexResult> {
  const query = new URLSearchParams({ role: params.role })
  if (params.domain) query.set('domain', params.domain)
  return request(`/api/catalog-lineage/index?${query}`).then(read<IndexResult>)
}

export function loadAttestations(): Promise<{ items: Attestation[] }> {
  return request('/api/catalog-lineage/attestations').then(read<{ items: Attestation[] }>)
}

export function openReport(version: string): Promise<PackageReport> {
  return request(`/api/catalog-lineage/packages/${version}/report`).then(
    read<PackageReport>,
  )
}

export function listPackages(): Promise<{ items: CatalogPackage[] }> {
  return request('/api/catalog-lineage/packages').then(read<{ items: CatalogPackage[] }>)
}

export function getPackage(version: string): Promise<CatalogPackage> {
  return request(`/api/catalog-lineage/packages/${version}`).then(read<CatalogPackage>)
}

export function listBindings(version?: string): Promise<{ items: Binding[] }> {
  const query = version ? `?version_no=${encodeURIComponent(version)}` : ''
  return request(`/api/catalog-lineage/bindings${query}`).then(read<{ items: Binding[] }>)
}

export function publishPackage(body: {
  version_no: string
  operator: string
  issued_to: string[]
  withdraw: string[]
  reason?: string
}): Promise<{ package: CatalogPackage; idempotent: boolean }> {
  return post('/api/catalog-lineage/packages', body)
}

export function signAttestation(body: {
  source_no: string
  outputs: string[]
  audit_batch: string
  signer: string
  operator: string
  valid_from?: string
  valid_until?: string
}): Promise<Attestation> {
  return post('/api/catalog-lineage/attestations', body)
}

export function bindOutput(body: {
  version_no: string
  output: string
  consumer_domain: string
  operator: string
}): Promise<Binding> {
  return post('/api/catalog-lineage/bindings', body)
}
