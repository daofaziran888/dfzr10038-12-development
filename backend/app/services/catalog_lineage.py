"""目录血缘索引：把跨域血缘边按访问权限转换成消费域可用的同源识别视图。

与普通 CRUD 模块不同，这里承载的是四条领域规则：

1. 权限转换：消费域看不到源表名和映射值时，仍能通过不可逆的「同源组」指纹
   认出两个输出来自同一来源；指纹包含归属域与归属方，所以异域同名来源不会
   被合并身份，也不会互相顶替核查。
2. 来源核查：目录维护员可以一次核查同一来源的多个输出；核查记录为每个输出
   保存签字时的主题摘要（来源身份 + 输出 + 映射 + 共享范围），并带审计批次。
3. 签字沿用：新版撤下部分边时，主题摘要未变化的输出可以沿用旧签字；主题
   摘要变化（来源或授权范围变更）、核查过期或已撤权的输出不能沿用，已撤权
   的证据也不会进入新版目录包和报告。
4. 签发与消费：只有已经签发、且仍处于有效核查范围内的输出才能被消费域关联。
   同一个版本号只允许生成一个目录包；发布与共享范围变更共用一把锁。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
from typing import Any

# 指纹盐只在本进程内有效：进程重启后账本本身也会重置，指纹不会指向旧身份。
# 生产部署可以用 CATALOG_LINEAGE_SECRET 固定下来，让多个副本算出同一组指纹。
SALT = os.environ.get("CATALOG_LINEAGE_SECRET") or secrets.token_hex(16)

ROLE_MAINTAINER = "catalog_maintainer"
ROLE_AUDITOR = "auditor"
ROLE_CONSUMER = "consumer"

BASIS_LABELS = {
    "direct": "首次核查",
    "carried_over": "沿用未变部分签字",
    "new_signature": "本次补签",
}

REASON_LABELS = {
    "NO_VALID_ATTESTATION": "没有覆盖当前主题的有效来源核查",
    "ATTESTATION_EXPIRED": "来源核查已过有效期",
    "ATTESTATION_NOT_YET_VALID": "来源核查尚未生效",
    "ATTESTATION_REVOKED": "来源核查已撤销",
    "SIGNATURE_INVALID": "来源核查签字校验失败",
    "EDGE_REVOKED": "该来源映射已撤下",
    "SUBJECT_CHANGED": "来源或授权范围已变化，不能沿用原签字",
    "SOURCE_NOT_AUTHORIZED": "消费域不在该来源的共享范围内",
    "NOT_IN_ISSUANCE_SCOPE": "该输出不在本次签发范围",
    "PACKAGE_NOT_ISSUED": "目录包尚未签发",
    "NOT_ISSUED_TO_DOMAIN": "目录包未签发给该消费域",
    "VERSION_EXISTS": "该版本已生成目录包，不能重复生成",
    "VERSION_NOT_FOUND": "目录包版本不存在",
    "OUTPUT_NOT_FOUND": "未找到对应的输出",
    "DOMAIN_REQUIRED": "需要提供消费域",
    "SIGNATURE_INVALID": "来源核查签字校验失败",
    "OPERATOR_REQUIRED": "需要登记操作人",
    "SIGNER_REQUIRED": "来源核查需要签字人",
    "AUDIT_BATCH_REQUIRED": "来源核查需要审计批次",
    "INVALID_DATE": "日期格式不正确",
    "INVALID_VALIDITY": "有效期不合法",
    "SOURCE_NOT_FOUND": "来源不存在",
    "OUTPUTS_NOT_IN_SOURCE": "核查输出不属于同一来源",
    "ROLE_FORBIDDEN": "当前角色无权执行该操作",
    "REVOCATION_REASON_REQUIRED": "撤权需要登记原因",
    "SCOPE_EMPTY": "共享范围不能为空",
    "NO_EFFECTIVE_SCOPE": "没有可签发且核查有效的输出",
    "EMPTY_WITHDRAW": "没有指定要撤下的边",
    "UNKNOWN_FIELD": "请求字段不合法",
    "AMBIGUOUS_OUTPUT": "输出标识不唯一，请同时给出消费域",
}


class CatalogLineageError(Exception):
    """目录血缘领域错误：code 给接口机和测试用，message 直接给人看。"""

    def __init__(self, code: str, message: str | None = None, status_code: int = 409) -> None:
        self.code = code
        self.message = message or REASON_LABELS.get(code, code)
        self.status_code = status_code
        super().__init__(self.message)


# ---------------------------------------------------------------------------
# 指纹与签字：所有对外身份都从哈希派生，避免把源表名、映射值带出去
# ---------------------------------------------------------------------------


def _canon(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: Any) -> str:
    return hashlib.sha256((SALT + "|" + _canon(value)).encode("utf-8")).hexdigest()


def _parse_date(value: str | None, field: str, default: dt.date | None = None) -> dt.date:
    if value is None or not str(value).strip():
        if default is None:
            raise CatalogLineageError("INVALID_DATE", f"{field}不能为空")
        return default
    text = str(value).strip()
    try:
        return dt.date.fromisoformat(text[:10])
    except ValueError as exc:
        raise CatalogLineageError("INVALID_DATE", f"{field}需要 YYYY-MM-DD 格式") from exc


def _now() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat()


def source_fingerprint(source: dict[str, Any]) -> str:
    """同源组：同名但归属域/归属方不同的来源会得到不同指纹。"""
    return "SG-" + _hash([
        "source",
        source["owner_domain"],
        source["owner"],
        source["table"],
        source["column"],
    ])[:16]


def subject_digest(edge: dict[str, Any], source: dict[str, Any]) -> str:
    """单个输出的主题摘要：来源身份、输出、映射和共享范围任一变化都会变。"""
    return _hash([
        "subject",
        source_fingerprint(source),
        edge["output_id"],
        edge["output_name"],
        edge["mapping"],
        sorted(edge["authorized_domains"]),
        edge["scope_version"],
    ])


def mapping_digest(edge: dict[str, Any]) -> str:
    return "MD-" + _hash(["mapping", edge["mapping"]])[:16]


def attestation_signature(attestation: dict[str, Any]) -> str:
    core = {
        "attestation_no": attestation["attestation_no"],
        "source_no": attestation["source_no"],
        "source_fingerprint": attestation["source_fingerprint"],
        "audit_batch": attestation["audit_batch"],
        "signer": attestation["signer"],
        "signed_at": attestation["signed_at"],
        "valid_from": attestation["valid_from"],
        "valid_until": attestation["valid_until"],
        "outputs": sorted(c["output_id"] for c in attestation["coverages"]),
        "digests": sorted(c["subject_digest"] for c in attestation["coverages"]),
    }
    return "SIG-" + _hash(["attestation", core])[:40]


def _signature_ok(attestation: dict[str, Any]) -> bool:
    return attestation.get("signature") == attestation_signature(attestation)


# ---------------------------------------------------------------------------
# 示例账本：V1 已由维护员共同核查甲、乙并签发；异域同名来源另有独立核查
# ---------------------------------------------------------------------------


def _make_source(
    source_no: str, owner_domain: str, owner: str, table: str, column: str, description: str
) -> dict[str, Any]:
    source = {
        "source_no": source_no,
        "owner_domain": owner_domain,
        "owner": owner,
        "table": table,
        "column": column,
        "description": description,
    }
    source["fingerprint"] = source_fingerprint(source)
    return source


def _make_edge(
    edge_no: str,
    source_no: str,
    output_id: str,
    output_name: str,
    consumer_domain: str,
    mapping: str,
    authorized_domains: list[str],
    scope_version: int = 1,
) -> dict[str, Any]:
    return {
        "edge_no": edge_no,
        "source_no": source_no,
        "output_id": output_id,
        "output_name": output_name,
        "consumer_domain": consumer_domain,
        "mapping": mapping,
        "authorized_domains": list(authorized_domains),
        "scope_version": scope_version,
        "status": "active",
        "created_at": "2026-10-25T10:00:00",
        "revoked_at": None,
        "revoked_version": None,
        "revoked_reason": None,
    }


def _seed_state() -> dict[str, Any]:
    sources = {
        s["source_no"]: s
        for s in [
            _make_source(
                "SRC-USER-AGE", "用户域", "用户画像组", "dwd_user_profile", "age",
                "用户基础属性，供推荐域与营销域共用",
            ),
            _make_source(
                "SRC-MEMBER-AGE", "会员域", "会员数据组", "dwd_user_profile", "age",
                "与用户域同名同列，但归属不同，身份必须独立",
            ),
            _make_source(
                "SRC-ORDER-AMT", "交易域", "交易数据组", "dwd_order_detail", "amount",
                "订单金额，核查已过有效期",
            ),
        ]
    }

    edges = {
        e["edge_no"]: e
        for e in [
            _make_edge(
                "EDGE-USER-AGE-BUCKET", "SRC-USER-AGE", "OUT-JIA", "user_age_bucket_7d",
                "推荐域", "dwd_user_profile.age -> age_bucket_5x", ["推荐域", "营销域"],
            ),
            _make_edge(
                "EDGE-USER-AGE-BAND", "SRC-USER-AGE", "OUT-YI", "user_age_band_30d",
                "营销域", "dwd_user_profile.age -> age_band_10y", ["营销域"],
            ),
            _make_edge(
                "EDGE-MEMBER-AGE-BAND", "SRC-MEMBER-AGE", "OUT-MEMBER-AGE",
                "member_age_bucket_30d", "会员运营域",
                "dwd_user_profile.age -> member_age_band_30d", ["会员运营域"],
            ),
            _make_edge(
                "EDGE-ORDER-AMT-RISK", "SRC-ORDER-AMT", "OUT-ORDER-AMT",
                "order_amount_30d", "风控域",
                "dwd_order_detail.amount -> order_amount_sum_30d", ["风控域"],
            ),
        ]
    }

    def coverage(edge_no: str) -> dict[str, Any]:
        edge = edges[edge_no]
        return {
            "edge_no": edge_no,
            "output_id": edge["output_id"],
            "subject_digest": subject_digest(edge, sources[edge["source_no"]]),
            "mapping_digest": mapping_digest(edge),
        }

    attestations: dict[str, dict[str, Any]] = {}

    def add_attestation(
        attestation_no: str,
        source_no: str,
        edge_nos: list[str],
        audit_batch: str,
        signer: str,
        signed_at: str,
        valid_from: str,
        valid_until: str,
        status: str = "active",
    ) -> None:
        attestation = {
            "attestation_no": attestation_no,
            "source_no": source_no,
            "source_fingerprint": sources[source_no]["fingerprint"],
            "coverages": [coverage(e) for e in edge_nos],
            "audit_batch": audit_batch,
            "signer": signer,
            "signed_at": signed_at,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "status": status,
            "supersedes": None,
            "revoked_at": None,
            "revoke_reason": None,
        }
        attestation["signature"] = attestation_signature(attestation)
        attestations[attestation_no] = attestation

    add_attestation(
        "ATT-2026-11-01-01", "SRC-USER-AGE",
        ["EDGE-USER-AGE-BUCKET", "EDGE-USER-AGE-BAND"],
        "AUD-2026-11-01-B1", "陈目录", "2026-11-01", "2026-11-01", "2027-05-31",
    )
    add_attestation(
        "ATT-2026-10-20-07", "SRC-MEMBER-AGE", ["EDGE-MEMBER-AGE-BAND"],
        "AUD-2026-10-20-B7", "李核", "2026-10-20", "2026-10-20", "2027-03-31",
    )
    add_attestation(
        "ATT-2026-08-01-03", "SRC-ORDER-AMT", ["EDGE-ORDER-AMT-RISK"],
        "AUD-2026-08-01-B3", "陈目录", "2026-08-01", "2026-08-01", "2026-10-31",
    )

    def snapshot(edge_no: str, attestation_no: str, basis: str) -> dict[str, Any]:
        edge = edges[edge_no]
        attestation = attestations[attestation_no]
        cov = next(
            c for c in attestation["coverages"] if c["edge_no"] == edge_no
        )
        return {
            "edge_no": edge_no,
            "output_id": edge["output_id"],
            "output_name": edge["output_name"],
            "consumer_domain": edge["consumer_domain"],
            "source_no": edge["source_no"],
            "source_group": sources[edge["source_no"]]["fingerprint"],
            "subject_digest": cov["subject_digest"],
            "mapping_digest": cov["mapping_digest"],
            "attestation_no": attestation_no,
            "audit_batch": attestation["audit_batch"],
            "signer": attestation["signer"],
            "valid_from": attestation["valid_from"],
            "valid_until": attestation["valid_until"],
            "basis": basis,
            "scope_version": edge["scope_version"],
        }

    packages: dict[str, dict[str, Any]] = {
        "v1": {
            "version_no": "v1",
            "package_no": "PKG-v1-20261102",
            "status": "issued",
            "generated_by": "陈目录",
            "generated_at": "2026-11-02T09:30:00",
            "issued_by": "陈目录",
            "issued_at": "2026-11-02T09:35:00",
            "issued_to": ["推荐域", "营销域"],
            "scope_version": 1,
            "request_id": "seed-v1",
            "entries": [
                snapshot("EDGE-USER-AGE-BUCKET", "ATT-2026-11-01-01", "direct"),
                snapshot("EDGE-USER-AGE-BAND", "ATT-2026-11-01-01", "direct"),
            ],
        }
    }

    return {
        "sources": sources,
        "edges": edges,
        "attestations": attestations,
        "packages": packages,
        "bindings": [],
        "events": [],
        "scope_changes": [],
        "sequence": 1,
    }
