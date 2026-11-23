<template>
  <section class="page cow-page">
    <header class="page-head">
      <div>
        <h2>目录血缘</h2>
        <p class="page-desc">
          把跨域血缘边按访问权限转换成目录索引：消费域看不到源表名和映射值，
          仍能凭同源组认出来自同一来源的输出。
        </p>
      </div>
      <div class="page-actions">
        <label class="role-picker">
          <span>当前身份</span>
          <select v-model="role" data-testid="role-select" @change="onRoleChange">
            <option value="maintainer">目录维护员</option>
            <option value="consumer">消费域</option>
          </select>
        </label>
        <label v-if="role === 'consumer'" class="role-picker">
          <span>消费域</span>
          <select v-model="domain" data-testid="domain-select" @change="reloadIndex">
            <option v-for="item in domains" :key="item" :value="item">{{ item }}</option>
          </select>
        </label>
      </div>
    </header>

    <nav class="cow-tabs">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        class="cow-tab"
        :class="{ active: activeTab === tab.key }"
        :data-testid="`tab-${tab.key}`"
        type="button"
        @click="activeTab = tab.key"
      >
        {{ tab.label }}
      </button>
    </nav>

    <p v-if="errorMessage" class="error-text cow-error" data-testid="error">{{ errorMessage }}</p>
    <p v-if="notice" class="cow-notice" data-testid="notice">{{ notice }}</p>

    <!-- ============================ 索引 ============================ -->
    <template v-if="activeTab === 'index'">
      <p class="cow-hint" data-testid="index-hint">
        {{ index?.same_source_rule }} 当前视图已隐藏：{{ (index?.masked_fields ?? []).join('、') }}。
      </p>
      <div class="stat-row">
        <article class="stat-card">
          <span class="stat-label">可见输出</span>
          <strong class="stat-value" data-testid="index-total">{{ index?.total ?? 0 }}</strong>
        </article>
        <article class="stat-card">
          <span class="stat-label">同源组</span>
          <strong class="stat-value" data-testid="group-total">{{ index?.groups.length ?? 0 }}</strong>
        </article>
        <article class="stat-card">
          <span class="stat-label">跨域共享来源</span>
          <strong class="stat-value">
            {{ index?.groups.filter((group) => group.shared_across_domains).length ?? 0 }}
          </strong>
        </article>
      </div>

      <div v-for="group in index?.groups ?? []" :key="group.source_group" class="cow-group">
        <header class="cow-group-head">
          <div>
            <strong class="cow-group-id" :data-testid="`group-${group.source_group}`">
              同源组 {{ group.source_group }}
            </strong>
            <span class="cow-muted">归属域：{{ group.owner_domain }}</span>
            <span v-if="group.shared_across_domains" class="cow-chip">跨域共享</span>
          </div>
          <span class="cow-muted">{{ group.output_count }} 个输出</span>
        </header>
        <table class="data-table">
          <thead>
            <tr>
              <th>输出</th>
              <th>名称</th>
              <th>消费域</th>
              <th>映射摘要</th>
              <th>核查状态</th>
              <th>核查批次</th>
              <th>有效期</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="output in group.outputs" :key="output.edge_no">
              <td>{{ output.output_id }}</td>
              <td>{{ output.output_name }}</td>
              <td>{{ output.consumer_domain }}</td>
              <td class="cow-mono">{{ output.mapping_digest }}</td>
              <td>
                <span :class="['cow-status', statusClass(output.coverage_status)]">
                  {{ coverageLabel(output.coverage_status) }}
                </span>
              </td>
              <td>{{ findAttestation(output.edge_no)?.audit_batch ?? '—' }}</td>
              <td>{{ validityText(output.edge_no) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="!index?.groups.length" class="empty-state">
        当前{{ role === 'consumer' ? `消费域 ${domain}` : '身份' }}没有可见的目录血缘索引。
      </p>
    </template>

    <!-- ============================ 来源核查 ============================ -->
    <template v-else-if="activeTab === 'attestation'">
      <p v-if="role === 'consumer'" class="cow-hint" data-testid="attestation-readonly">
        来源核查由目录维护员提交；消费域只读，不能补签或撤销核查。
      </p>
      <form
        v-else
        class="cow-form"
        data-testid="attestation-form"
        @submit.prevent="submitAttestation"
      >
        <label>
          <span>来源编号</span>
          <select v-model="attestationForm.source_no" data-testid="att-source">
            <option v-for="source in sources" :key="source.source_no" :value="source.source_no">
              {{ source.source_no }} · {{ source.owner_domain }}
            </option>
          </select>
        </label>
        <label>
          <span>核查输出（一次可核查同一来源的多个输出）</span>
          <input
            v-model="attestationForm.outputs"
            data-testid="att-outputs"
            placeholder="如 OUT-JIA,OUT-YI"
          />
        </label>
        <label>
          <span>审计批次</span>
          <input v-model="attestationForm.audit_batch" data-testid="att-batch" placeholder="AUD-2026-11-23-B9" />
        </label>
        <label>
          <span>签字人</span>
          <input v-model="attestationForm.signer" data-testid="att-signer" placeholder="陈目录" />
        </label>
        <label>
          <span>生效日期</span>
          <input v-model="attestationForm.valid_from" data-testid="att-from" placeholder="2026-11-23" />
        </label>
        <label>
          <span>失效日期</span>
          <input v-model="attestationForm.valid_until" data-testid="att-until" placeholder="2027-06-30" />
        </label>
        <button class="btn primary" data-testid="att-submit" type="submit" :disabled="busy">
          提交来源核查
        </button>
      </form>

      <table class="data-table">
        <thead>
          <tr>
            <th>核查编号</th>
            <th>来源</th>
            <th>覆盖输出</th>
            <th>审计批次</th>
            <th>签字人</th>
            <th>有效期</th>
            <th>签字</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in attestations"
            :key="item.attestation_no"
            :data-testid="`att-row-${item.attestation_no}`"
          >
            <td>{{ item.attestation_no }}</td>
            <td class="cow-mono">{{ item.source_group }}</td>
            <td>{{ item.coverages.map((coverage) => coverage.output_id).join('、') }}</td>
            <td>{{ item.audit_batch }}</td>
            <td>{{ item.signer }}</td>
            <td>{{ item.valid_from }} ~ {{ item.valid_until }}</td>
            <td>
              <span :class="['cow-status', item.signature_verified ? 'ok' : 'bad']">
                {{ item.signature_verified ? '校验通过' : '校验失败' }}
              </span>
            </td>
            <td>{{ item.status === 'revoked' ? '已撤销' : item.validity_note }}</td>
          </tr>
        </tbody>
      </table>
    </template>

    <!-- ============================ 目录包 ============================ -->
    <template v-else-if="activeTab === 'package'">
      <p v-if="role === 'consumer'" class="cow-hint">
        目录包由目录维护员发布；消费域只能打开已签发的目录包，用它关联输出。
      </p>
      <form
        v-else
        class="cow-form"
        data-testid="package-form"
        @submit.prevent="submitPublish"
      >
        <label>
          <span>版本号</span>
          <input v-model="packageForm.version_no" data-testid="pkg-version" placeholder="v2" />
        </label>
        <label>
          <span>签发对象（逗号分隔）</span>
          <input v-model="packageForm.issued_to" data-testid="pkg-domains" placeholder="推荐域,营销域" />
        </label>
        <label>
          <span>撤下的边（逗号分隔，可留空）</span>
          <input v-model="packageForm.withdraw" data-testid="pkg-withdraw" placeholder="OUT-YI" />
        </label>
        <label>
          <span>操作人</span>
          <input v-model="packageForm.operator" data-testid="pkg-operator" placeholder="陈目录" />
        </label>
        <button class="btn primary" data-testid="pkg-submit" type="submit" :disabled="busy">
          发布目录包
        </button>
      </form>

      <p v-if="role === 'consumer'" class="cow-hint">
        消费域可以直接打开已签发目录包，核对原签发范围和审计批次。
      </p>

      <table class="data-table">
        <thead>
          <tr>
            <th>版本</th>
            <th>目录包</th>
            <th>状态</th>
            <th>签发对象</th>
            <th>输出数</th>
            <th>撤下边数</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in packages" :key="item.version_no" :data-testid="`pkg-row-${item.version_no}`">
            <td>{{ item.version_no }}</td>
            <td class="cow-mono">{{ item.package_no }}</td>
            <td>{{ item.status === 'issued' ? '已签发' : '草稿' }}</td>
            <td>{{ item.issued_to.join('、') }}</td>
            <td>{{ item.entry_count }}</td>
            <td>{{ item.withdrawn_count }}</td>
            <td>
              <button
                v-if="role !== 'consumer'"
                class="link"
                data-testid="open-report"
                type="button"
                @click="openPackageReport(item.version_no)"
              >
                打开报告
              </button>
              <button
                v-else
                class="link"
                data-testid="open-package"
                type="button"
                @click="openIssuedPackage(item.version_no)"
              >
                查看已签发目录包
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <section v-if="issuedPackage" class="cow-report" data-testid="issued-package">
        <header class="cow-group-head">
          <strong>已签发目录包 {{ issuedPackage.version_no }} · {{ issuedPackage.package_no }}</strong>
          <span class="cow-muted">签发给 {{ issuedPackage.issued_to.join('、') }}</span>
        </header>
        <table class="data-table">
          <thead>
            <tr>
              <th>输出</th>
              <th>同源组</th>
              <th>消费域</th>
              <th>核查编号</th>
              <th>审计批次</th>
              <th>签字依据</th>
              <th>有效期</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in issuedPackage.entries" :key="entry.edge_no">
              <td>{{ entry.output_id }} · {{ entry.output_name }}</td>
              <td class="cow-mono">{{ entry.source_group }}</td>
              <td>{{ entry.consumer_domain }}</td>
              <td>{{ entry.attestation_no }}</td>
              <td>{{ entry.audit_batch }}</td>
              <td>{{ basisLabel(entry.basis) }}</td>
              <td>{{ entry.valid_from }} ~ {{ entry.valid_until }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section v-if="report" class="cow-report" data-testid="package-report">
        <header class="cow-group-head">
          <strong>目录包 {{ report.version_no }} · {{ report.package_no }}</strong>
          <span class="cow-muted">核对日期 {{ report.as_of }}</span>
        </header>
        <dl class="cow-scope">
          <div>
            <dt>原签发范围</dt>
            <dd data-testid="report-scope">{{ report.issued_scope.output_ids.join('、') }}</dd>
          </div>
          <div>
            <dt>签发对象</dt>
            <dd>{{ report.issued_scope.domains.join('、') }}</dd>
          </div>
          <div>
            <dt>审计批次</dt>
            <dd data-testid="report-batches">{{ report.issued_scope.audit_batches.join('、') }}</dd>
          </div>
          <div>
            <dt>核查编号</dt>
            <dd>{{ report.issued_scope.attestation_nos.join('、') }}</dd>
          </div>
          <div>
            <dt>签发有效期</dt>
            <dd>{{ report.issued_scope.valid_from }} ~ {{ report.issued_scope.valid_until }}</dd>
          </div>
          <div>
            <dt>当前可办理</dt>
            <dd data-testid="report-bindable">
              {{ report.checks.bindable_count }} / {{ report.checks.entry_count }}
            </dd>
          </div>
        </dl>
        <table class="data-table">
          <thead>
            <tr>
              <th>输出</th>
              <th>签发包内的核查</th>
              <th>审计批次</th>
              <th>签字依据</th>
              <th>当前依据</th>
              <th>当前有效期</th>
              <th>当前可关联</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in report.entries" :key="entry.edge_no">
              <td>{{ entry.output_id }} · {{ entry.output_name }}</td>
              <td>{{ entry.attestation_no }}</td>
              <td>{{ entry.audit_batch }}</td>
              <td>{{ basisLabel(entry.basis) }}</td>
              <td>{{ entry.current_attestation?.attestation_no ?? '—' }}</td>
              <td>
                <template v-if="entry.current_attestation">
                  {{ entry.current_attestation.valid_from }} ~ {{ entry.current_attestation.valid_until }}
                </template>
                <template v-else>—</template>
              </td>
              <td>
                <span :class="['cow-status', entry.bindable_now ? 'ok' : 'bad']">
                  {{ entry.bindable_now ? '可关联' : entry.current_status }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </template>

    <!-- ============================ 关联 ============================ -->
    <template v-else>
      <form class="cow-form" data-testid="bind-form" @submit.prevent="submitBind">
        <label>
          <span>目录包版本</span>
          <input v-model="bindForm.version_no" data-testid="bind-version" placeholder="v2" />
        </label>
        <label>
          <span>输出</span>
          <input v-model="bindForm.output" data-testid="bind-output" placeholder="OUT-JIA" />
        </label>
        <label>
          <span>消费域</span>
          <input v-model="bindForm.consumer_domain" data-testid="bind-domain" placeholder="推荐域" />
        </label>
        <label>
          <span>操作人</span>
          <input v-model="bindForm.operator" data-testid="bind-operator" placeholder="推荐域值班" />
        </label>
        <button class="btn primary" data-testid="bind-submit" type="submit" :disabled="busy">
          关联输出
        </button>
      </form>

      <article v-if="lastBinding" class="cow-binding" data-testid="last-binding">
        <strong>本次关联 {{ lastBinding.binding_no }}：{{ lastBinding.output_id }}</strong>
        <p>
          来源组 <span class="cow-mono">{{ lastBinding.source_group }}</span> ·
          依据 {{ basisLabel(lastBinding.basis) }} ·
          核查 {{ lastBinding.attestation_no }} ·
          审计批次 {{ lastBinding.audit_batch }}
        </p>
        <p>有效期 {{ lastBinding.valid_from }} ~ {{ lastBinding.valid_until }}</p>
      </article>

      <table class="data-table">
        <thead>
          <tr>
            <th>关联编号</th>
            <th>版本</th>
            <th>输出</th>
            <th>消费域</th>
            <th>核查</th>
            <th>审计批次</th>
            <th>依据</th>
            <th>有效期</th>
            <th>关联时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in bindings" :key="item.binding_no" :data-testid="`bind-row-${item.binding_no}`">
            <td>{{ item.binding_no }}</td>
            <td>{{ item.version_no }}</td>
            <td>{{ item.output_id }}</td>
            <td>{{ item.consumer_domain }}</td>
            <td>{{ item.attestation_no }}</td>
            <td>{{ item.audit_batch }}</td>
            <td>{{ basisLabel(item.basis) }}</td>
            <td>{{ item.valid_from }} ~ {{ item.valid_until }}</td>
            <td>{{ item.bound_at }}</td>
          </tr>
          <tr v-if="!bindings.length">
            <td colspan="9" class="empty-state">还没有消费域关联记录。</td>
          </tr>
        </tbody>
      </table>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  bindOutput,
  getPackage,
  listBindings,
  listPackages,
  loadAttestations,
  loadIndex,
  openReport,
  publishPackage,
  signAttestation,
} from '@/api/catalog-lineage'
import type {
  Attestation,
  Binding,
  CatalogPackage,
  IndexResult,
  PackageReport,
} from '@/data/catalog-lineage'

type Role = 'maintainer' | 'consumer'
type TabKey = 'index' | 'attestation' | 'package' | 'bind'

const tabs: { key: TabKey; label: string }[] = [
  { key: 'index', label: '目录血缘索引' },
  { key: 'attestation', label: '来源核查' },
  { key: 'package', label: '目录包与报告' },
  { key: 'bind', label: '消费域关联' },
]

const sources = [
  { source_no: 'SRC-USER-AGE', owner_domain: '用户域' },
  { source_no: 'SRC-MEMBER-AGE', owner_domain: '会员域' },
  { source_no: 'SRC-ORDER-AMT', owner_domain: '交易域' },
]
const domains = ['推荐域', '营销域', '会员运营域', '风控域']

const role = ref<Role>('maintainer')
const domain = ref('推荐域')
const activeTab = ref<TabKey>('index')
const index = ref<IndexResult | null>(null)
const attestations = ref<Attestation[]>([])
const packages = ref<CatalogPackage[]>([])
const report = ref<PackageReport | null>(null)
const issuedPackage = ref<CatalogPackage | null>(null)
const bindings = ref<Binding[]>([])
const lastBinding = ref<Binding | null>(null)
const busy = ref(false)
const errorMessage = ref('')
const notice = ref('')

const attestationForm = ref({
  source_no: 'SRC-USER-AGE',
  outputs: 'OUT-JIA',
  audit_batch: '',
  signer: '陈目录',
  valid_from: '',
  valid_until: '',
})
const packageForm = ref({
  version_no: '',
  issued_to: '推荐域,营销域',
  withdraw: '',
  operator: '陈目录',
})
const bindForm = ref({
  version_no: 'v2',
  output: 'OUT-JIA',
  consumer_domain: '推荐域',
  operator: '推荐域值班',
})

const attestationByEdge = computed(() => {
  const map = new Map<string, Attestation>()
  for (const item of attestations.value) {
    for (const coverage of item.coverages) {
      map.set(coverage.edge_no, item)
    }
  }
  return map
})

function findAttestation(edgeNo: string): Attestation | undefined {
  return attestationByEdge.value.get(edgeNo)
}

function validityText(edgeNo: string): string {
  const item = findAttestation(edgeNo)
  return item ? `${item.valid_from} ~ ${item.valid_until}` : '—'
}

function coverageLabel(status: string): string {
  return {
    VALID: '核查有效',
    ATTESTATION_EXPIRED: '核查已过期',
    ATTESTATION_NOT_YET_VALID: '核查未生效',
    ATTESTATION_REVOKED: '核查已撤销',
    SIGNATURE_INVALID: '签字校验失败',
    SUBJECT_CHANGED: '来源或授权已变化',
    EDGE_REVOKED: '边已撤下',
    NO_VALID_ATTESTATION: '无有效核查',
  }[status] ?? status
}

function statusClass(status: string): string {
  return status === 'VALID' ? 'ok' : 'bad'
}

function basisLabel(basis: string): string {
  return {
    carried_over: '沿用未变部分签字',
    new_signature: '本次补签',
    direct: '首次核查',
  }[basis] ?? basis
}

function splitList(value: string): string[] {
  return value
    .split(/[,，\s]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function reportError(error: unknown, fallback: string) {
  errorMessage.value = error instanceof Error ? error.message : fallback
}

async function reloadIndex() {
  errorMessage.value = ''
  try {
    index.value = await loadIndex({
      role: role.value,
      domain: role.value === 'consumer' ? domain.value : undefined,
    })
  } catch (error) {
    reportError(error, '目录血缘索引读取失败')
  }
}

async function reloadAttestations() {
  try {
    attestations.value = (await loadAttestations()).items
  } catch (error) {
    reportError(error, '来源核查读取失败')
  }
}

async function reloadPackages() {
  try {
    packages.value = (await listPackages()).items
  } catch (error) {
    reportError(error, '目录包读取失败')
  }
}

async function reloadBindings(version = bindForm.value.version_no) {
  try {
    bindings.value = (await listBindings(version)).items
  } catch (error) {
    reportError(error, '关联记录读取失败')
  }
}

async function onRoleChange() {
  notice.value = ''
  await reloadIndex()
}

async function submitAttestation() {
  busy.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    const attestation = await signAttestation({
      source_no: attestationForm.value.source_no,
      outputs: splitList(attestationForm.value.outputs),
      audit_batch: attestationForm.value.audit_batch,
      signer: attestationForm.value.signer,
      operator: attestationForm.value.signer,
      valid_from: attestationForm.value.valid_from || undefined,
      valid_until: attestationForm.value.valid_until || undefined,
    })
    notice.value = `来源核查 ${attestation.attestation_no} 已签字，覆盖 ${
      attestation.coverages.map((coverage) => coverage.output_id).join('、')
    }。`
    await reloadAttestations()
    await reloadIndex()
  } catch (error) {
    reportError(error, '来源核查提交失败')
  } finally {
    busy.value = false
  }
}

async function submitPublish() {
  busy.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await publishPackage({
      version_no: packageForm.value.version_no,
      operator: packageForm.value.operator,
      issued_to: splitList(packageForm.value.issued_to),
      withdraw: splitList(packageForm.value.withdraw),
    })
    notice.value = `目录包 ${result.package.version_no} 已签发，包含 ${
      result.package.entry_count
    } 个输出，沿用签字 ${result.package.entries.filter((entry) => entry.basis === 'carried_over').length} 个。`
    await reloadPackages()
    await openPackageReport(result.package.version_no)
    await reloadIndex()
  } catch (error) {
    reportError(error, '目录包发布失败')
  } finally {
    busy.value = false
  }
}

async function openPackageReport(version: string) {
  errorMessage.value = ''
  issuedPackage.value = null
  try {
    report.value = await openReport(version)
  } catch (error) {
    reportError(error, '目录包报告读取失败')
  }
}

async function openIssuedPackage(version: string) {
  errorMessage.value = ''
  report.value = null
  try {
    issuedPackage.value = await getPackage(version)
  } catch (error) {
    reportError(error, '已签发目录包读取失败')
  }
}

async function submitBind() {
  busy.value = true
  errorMessage.value = ''
  notice.value = ''
  lastBinding.value = null
  try {
    const binding = await bindOutput({
      version_no: bindForm.value.version_no,
      output: bindForm.value.output,
      consumer_domain: bindForm.value.consumer_domain,
      operator: bindForm.value.operator,
    })
    lastBinding.value = binding
    notice.value = `输出 ${binding.output_id} 已关联，依据 ${basisLabel(binding.basis)}。`
    await reloadBindings(binding.version_no)
    await reloadIndex()
  } catch (error) {
    reportError(error, '消费域关联失败')
  } finally {
    busy.value = false
  }
}

onMounted(async () => {
  await Promise.all([reloadIndex(), reloadAttestations(), reloadPackages()])
})
</script>

<style scoped>
.cow-page { padding-bottom: 24px; }
.cow-tabs { display: flex; gap: 6px; margin: 12px 0; }
.cow-tab { border: 1px solid var(--border); background: #fff; border-radius: 999px; padding: 6px 14px; cursor: pointer; font-size: 13px; }
.cow-tab.active { background: var(--brand); border-color: var(--brand); color: #fff; }
.cow-hint { background: #eef4ff; border: 1px solid #c7d7fe; border-radius: 8px; padding: 8px 12px; font-size: 13px; }
.cow-error { display: block; margin: 8px 0; }
.cow-notice { background: #ecfdf3; border: 1px solid #abefc6; border-radius: 8px; padding: 8px 12px; font-size: 13px; color: #067647; }
.cow-group { background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-bottom: 14px; }
.cow-group-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }
.cow-group-id { font-family: ui-monospace, monospace; }
.cow-muted { color: var(--muted); font-size: 12px; margin-left: 8px; }
.cow-mono { font-family: ui-monospace, monospace; font-size: 12px; }
.cow-chip { margin-left: 8px; background: #e0e7ff; color: #3730a3; border-radius: 999px; padding: 1px 8px; font-size: 12px; }
.cow-status.ok { color: #067647; }
.cow-status.bad { color: #b42318; }
.cow-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-bottom: 12px; }
.cow-form label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--muted); }
.cow-form input, .cow-form select { border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 13px; min-width: 160px; }
.role-picker { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--muted); }
.role-picker select { border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; font-size: 13px; }
.cow-report { background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-top: 14px; }
.cow-scope { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin: 10px 0; }
.cow-scope dt { font-size: 12px; color: var(--muted); }
.cow-scope dd { margin: 2px 0 0; font-size: 13px; }
.cow-binding { background: #f0f9ff; border: 1px solid #b9e6fe; border-radius: 10px; padding: 12px; margin: 12px 0; font-size: 13px; }
.cow-binding p { margin: 6px 0 0; }
</style>
