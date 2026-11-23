/** 目录血缘：消费域索引、来源核查、目录包与关联记录的类型。 */

export type IndexedOutput = {
  edge_no: string
  output_id: string
  output_name: string
  consumer_domain: string
  source_group: string
  owner_domain: string
  mapping_digest: string
  status: string
  scope_version: number
  domain_scope: string[]
  coverage_status: string
  coverage_label: string
  attestation: AttestationRef | null
}

export type AttestationRef = {
  attestation_no: string
  audit_batch: string
  signer: string
  signed_at: string
  valid_from: string
  valid_until: string
  status: string
}

export type SourceGroup = {
  source_group: string
  owner_domain: string
  outputs: {
    output_id: string
    output_name: string
    edge_no: string
    consumer_domain: string
    mapping_digest: string
    status: string
    coverage_status: string
  }[]
  consumer_domains: string[]
  output_count: number
  shared_across_domains: boolean
}

export type IndexResult = {
  view: 'consumer' | 'governance'
  role: string
  domain: string | null
  as_of: string
  items: IndexedOutput[]
  total: number
  groups: SourceGroup[]
  same_source_rule: string
  masked_fields: string[]
}

export type PackageEntry = {
  edge_no: string
  output_id: string
  output_name: string
  consumer_domain: string
  source_group: string
  mapping_digest: string
  subject_digest: string
  attestation_no: string
  audit_batch: string
  signer: string
  valid_from: string
  valid_until: string
  basis: string
  scope_version: number
  bindable_now?: boolean
  current_status?: string
  current_reason?: string | null
  current_attestation?: AttestationRef | null
  current_basis?: string
}

export type PackageSummary = {
  version_no: string
  package_no: string
  status: string
  generated_by: string
  generated_at: string
  issued_by: string | null
  issued_at: string | null
  issued_to: string[]
  scope_version: number
  entries: PackageEntry[]
  entry_count: number
  withdrawn_count: number
}

export type CatalogPackage = PackageSummary

export type PackageReport = Omit<PackageSummary, 'entry_count' | 'entries'> & {
  as_of: string
  entries: PackageEntry[]
  issued_scope: {
    output_ids: string[]
    output_count: number
    domains: string[]
    audit_batches: string[]
    attestation_nos: string[]
    source_groups: string[]
    valid_from: string | null
    valid_until: string | null
  }
  bindings: Binding[]
  checks: {
    entry_count: number
    bindable_count: number
    signatures_verified: boolean
    no_revoked_evidence: boolean
  }
}

export type Binding = {
  binding_no: string
  version_no: string
  package_no: string
  output_id: string
  output_name: string
  edge_no: string
  consumer_domain: string
  source_group: string
  attestation_no: string
  audit_batch: string
  basis: string
  valid_from: string
  valid_until: string
  bound_at: string
  operator: string
  package_attestation_no: string
}

export type Attestation = {
  attestation_no: string
  source_no: string
  source_group: string
  coverages: { edge_no: string; output_id: string; subject_digest: string }[]
  audit_batch: string
  signer: string
  signed_at: string
  valid_from: string
  valid_until: string
  status: string
  valid_now: boolean
  validity_note: string
  signature_verified: boolean
}
