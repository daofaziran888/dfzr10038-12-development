"""目录血缘索引的业务操作：核查、撤权、共享范围变更、目录包签发与消费域关联。

所有写操作在同一把可重入锁内完成。发布目录包和共享范围变更因此互斥，
同一个版本号只会落下一份目录包；请求号相同的重复提交按幂等处理。
"""
from __future__ import annotations

import copy
import datetime as dt
import threading
from typing import Any, Iterable

from app.services.catalog_lineage import (
    BASIS_LABELS,
    REASON_LABELS,
    ROLE_AUDITOR,
    ROLE_CONSUMER,
    ROLE_MAINTAINER,
    CatalogLineageError,
    _hash,
    _now,
    _parse_date,
    _seed_state,
    _signature_ok,
    attestation_signature,
    mapping_digest,
    subject_digest,
)

# 账本：示例数据给 V1 一份已签发的共同核查，异域同名来源单独核查。
_STATE: dict[str, Any] = _seed_state()
_LOCK = threading.RLock()

_ROLE_ALIASES = {
    "catalog_maintainer": ROLE_MAINTAINER,
    "maintainer": ROLE_MAINTAINER,
    "维护员": ROLE_MAINTAINER,
    "目录维护员": ROLE_MAINTAINER,
    "auditor": ROLE_AUDITOR,
    "审计": ROLE_AUDITOR,
    "consumer": ROLE_CONSUMER,
    "消费域": ROLE_CONSUMER,
    "consumer_domain": ROLE_CONSUMER,
}


def reset_state() -> dict[str, Any]:
    """把账本恢复到示例初始状态，主要给测试和演示重置用。"""
    global _STATE
    with _LOCK:
        _STATE = _seed_state()
        return _state_summary()


def _state_summary() -> dict[str, Any]:
    packages = sorted(_STATE["packages"])
    current = packages[-1] if packages else None
    return {
        "sources": len(_STATE["sources"]),
        "edges": len(_STATE["edges"]),
        "active_edges": sum(1 for e in _STATE["edges"].values() if e["status"] == "active"),
        "attestations": len(_STATE["attestations"]),
        "packages": packages,
        "current_package": current,
        "bindings": len(_STATE["bindings"]),
    }


def _fold_role(role: str | None, default: str | None = None) -> str | None:
    text = (role or default or "").strip()
    if not text:
        return None
    return _ROLE_ALIASES.get(text.lower(), _ROLE_ALIASES.get(text, text))


def _require_role(role: str | None, allowed: Iterable[str], default: str | None = None) -> str:
    folded = _fold_role(role, default)
    allowed_set = set(allowed)
    if folded not in allowed_set:
        raise CatalogLineageError("ROLE_FORBIDDEN", status_code=403)
    return folded


def _event(kind: str, operator: str, **details: Any) -> None:
    seq = int(_STATE["sequence"])
    _STATE["sequence"] = seq + 1
    _STATE["events"].append({
        "event_no": f"EVT-{seq:06d}",
        "kind": kind,
        "operator": operator,
        "at": _now(),
        **details,
    })


# ---------------------------------------------------------------------------
# 查找与投影
# ---------------------------------------------------------------------------


def _source(source_no: str) -> dict[str, Any]:
    source = _STATE["sources"].get(source_no)
    if source is None:
        raise CatalogLineageError("SOURCE_NOT_FOUND", status_code=404)
    return source


def _edge(ref: str | None) -> dict[str, Any]:
    text = str(ref or "").strip()
    if not text:
        raise CatalogLineageError("OUTPUT_NOT_FOUND", status_code=404)
    if text in _STATE["edges"]:
        return _STATE["edges"][text]
    for field in ("output_id", "output_name"):
        matches = [edge for edge in _STATE["edges"].values() if edge[field] == text]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CatalogLineageError("AMBIGUOUS_OUTPUT")
    raise CatalogLineageError("OUTPUT_NOT_FOUND", f"未找到输出 {text}", status_code=404)


def _attestation(attestation_no: str) -> dict[str, Any]:
    attestation = _STATE["attestations"].get(attestation_no)
    if attestation is None:
        raise CatalogLineageError("NO_VALID_ATTESTATION", "来源核查不存在", status_code=404)
    return attestation


def _attestation_status(attestation: dict[str, Any], as_of: dt.date) -> tuple[bool, str]:
    if not _signature_ok(attestation):
        return False, "SIGNATURE_INVALID"
    if attestation["status"] == "revoked":
        return False, "ATTESTATION_REVOKED"
    valid_from = dt.date.fromisoformat(attestation["valid_from"])
    valid_until = dt.date.fromisoformat(attestation["valid_until"])
    if as_of < valid_from:
        return False, "ATTESTATION_NOT_YET_VALID"
    if as_of > valid_until:
        return False, "ATTESTATION_EXPIRED"
    return True, "VALID"


def _coverage_for(attestation: dict[str, Any], edge: dict[str, Any]) -> dict[str, Any] | None:
    for coverage in attestation["coverages"]:
        if coverage["edge_no"] == edge["edge_no"]:
            return coverage
    return None


def _best_attestation(edge: dict[str, Any], as_of: dt.date) -> tuple[dict[str, Any] | None, str]:
    """返回当前主题仍可沿用的最新核查；不可用时给出最能说明问题的原因。"""
    source = _source(edge["source_no"])
    digest = subject_digest(edge, source)
    candidates = [
        att for att in _STATE["attestations"].values()
        if att["source_no"] == edge["source_no"]
    ]
    candidates.sort(key=lambda att: (att["signed_at"], att["attestation_no"]), reverse=True)
    reason = "NO_VALID_ATTESTATION"
    decided = False
    for att in candidates:
        coverage = _coverage_for(att, edge)
        if coverage is None:
            continue
        if coverage["subject_digest"] != digest:
            if not decided:
                reason = "SUBJECT_CHANGED"
            decided = True
            continue
        ok, code = _attestation_status(att, as_of)
        if ok:
            return att, "VALID"
        if not decided:
            reason = code
            decided = True
    return None, reason


def _edge_view(edge: dict[str, Any], as_of: dt.date) -> dict[str, Any]:
    """目录血缘索引里的一行：只有指纹和摘要，不带源表名、列名和映射值。"""
    source = _source(edge["source_no"])
    att, reason = _best_attestation(edge, as_of)
    view: dict[str, Any] = {
        "edge_no": edge["edge_no"],
        "output_id": edge["output_id"],
        "output_name": edge["output_name"],
        "consumer_domain": edge["consumer_domain"],
        "source_group": source["fingerprint"],
        "owner_domain": source["owner_domain"],
        "mapping_digest": mapping_digest(edge),
        "status": edge["status"],
        "scope_version": edge["scope_version"],
        "domain_scope": list(edge["authorized_domains"]),
        "attestation": None,
        "coverage_status": "VALID" if att else reason,
        "coverage_label": _coverage_label(att, reason, as_of),
    }
    if att is not None:
        view["attestation"] = _attestation_ref(att)
    return view


def _attestation_ref(attestation: dict[str, Any]) -> dict[str, Any]:
    return {
        "attestation_no": attestation["attestation_no"],
        "audit_batch": attestation["audit_batch"],
        "signer": attestation["signer"],
        "signed_at": attestation["signed_at"],
        "valid_from": attestation["valid_from"],
        "valid_until": attestation["valid_until"],
        "status": attestation["status"],
    }


def _coverage_label(att: dict[str, Any] | None, reason: str, as_of: dt.date) -> str:
    if att is not None:
        return "核查有效"
    if reason == "SUBJECT_CHANGED":
        return "来源或授权已变化"
    return REASON_LABELS.get(reason, reason)


def _attestation_view(attestation: dict[str, Any], as_of: dt.date) -> dict[str, Any]:
    ok, code = _attestation_status(attestation, as_of)
    return {
        "attestation_no": attestation["attestation_no"],
        "source_no": attestation["source_no"],
        "source_group": attestation["source_fingerprint"],
        "coverages": [
            {
                "edge_no": coverage["edge_no"],
                "output_id": coverage["output_id"],
                "subject_digest": coverage["subject_digest"],
                "mapping_digest": coverage["mapping_digest"],
            }
            for coverage in attestation["coverages"]
        ],
        "audit_batch": attestation["audit_batch"],
        "signer": attestation["signer"],
        "signed_at": attestation["signed_at"],
        "valid_from": attestation["valid_from"],
        "valid_until": attestation["valid_until"],
        "status": attestation["status"],
        "valid_now": ok,
        "validity_note": _coverage_label(attestation if ok else None, code, as_of),
        "supersedes": attestation["supersedes"],
        "revoked_at": attestation["revoked_at"],
        "revoke_reason": attestation["revoke_reason"],
        "signature": attestation["signature"],
        "signature_verified": _signature_ok(attestation),
    }


def _package_public(package: dict[str, Any]) -> dict[str, Any]:
    """目录包对消费域的公开形态：不含已撤边，也不含被撤权证据。"""
    return {
        "version_no": package["version_no"],
        "package_no": package["package_no"],
        "status": package["status"],
        "generated_by": package["generated_by"],
        "generated_at": package["generated_at"],
        "issued_by": package["issued_by"],
        "issued_at": package["issued_at"],
        "issued_to": list(package["issued_to"]),
        "scope_version": package["scope_version"],
        "request_id": package["request_id"],
        "entries": copy.deepcopy(package["entries"]),
        "entry_count": len(package["entries"]),
        "withdrawn_count": len(package.get("withdrawn_edges", [])),
    }


# ---------------------------------------------------------------------------
# 索引查询
# ---------------------------------------------------------------------------


def index_view(
    *, role: str | None = None, domain: str | None = None, as_of: str | None = None
) -> dict[str, Any]:
    # 未声明身份时按权限最小的消费域视图处理。
    folded = _fold_role(role) or ROLE_CONSUMER
    date = _parse_date(as_of, "查询日期", dt.date.today())
    domain = (domain or "").strip()

    edges = sorted(_STATE["edges"].values(), key=lambda e: e["edge_no"])
    if folded == ROLE_CONSUMER:
        if not domain:
            raise CatalogLineageError("DOMAIN_REQUIRED", "消费域查询需要提供 domain")
        edges = [e for e in edges if domain in e["authorized_domains"]]

    items = [_edge_view(edge, date) for edge in edges if edge["status"] == "active"]
    if folded != ROLE_CONSUMER:
        for item in items:
            item["source_no"] = _STATE["edges"][item["edge_no"]]["source_no"]
    if folded in (ROLE_MAINTAINER, ROLE_AUDITOR):
        # 维护员和审计能看到已撤下的边，但同样看不到源表名与映射值。
        revoked_items = [_edge_view(edge, date) for edge in edges if edge["status"] == "revoked"]
        for item in revoked_items:
            item["source_no"] = _STATE["edges"][item["edge_no"]]["source_no"]
        items += revoked_items

    groups: dict[str, dict[str, Any]] = {}
    for item in items:
        group = groups.setdefault(item["source_group"], {
            "source_group": item["source_group"],
            "owner_domain": item["owner_domain"],
            "outputs": [],
            "consumer_domains": [],
        })
        group["outputs"].append({
            "output_id": item["output_id"],
            "output_name": item["output_name"],
            "edge_no": item["edge_no"],
            "consumer_domain": item["consumer_domain"],
            "mapping_digest": item["mapping_digest"],
            "status": item["status"],
            "coverage_status": item["coverage_status"],
        })
        if item["consumer_domain"] not in group["consumer_domains"]:
            group["consumer_domains"].append(item["consumer_domain"])

    group_list = []
    for group in groups.values():
        group["output_count"] = len(group["outputs"])
        group["shared_across_domains"] = len(group["consumer_domains"]) > 1
        group_list.append(group)
    group_list.sort(key=lambda g: (-g["output_count"], g["source_group"]))

    return {
        "view": "consumer" if folded == ROLE_CONSUMER else "governance",
        "role": folded,
        "domain": domain or None,
        "as_of": date.isoformat(),
        "items": items,
        "total": len(items),
        "groups": group_list,
        "same_source_rule": "同一 source_group 即同源；指纹含归属域和归属方，异域同名不会合并。",
        "masked_fields": ["源表名", "源列名", "映射表达式"],
    }


def source_detail(source_no: str, *, role: str | None = None) -> dict[str, Any]:
    """维护员/审计查看原始来源字段；消费域索引不经过这里。"""
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR}, ROLE_MAINTAINER)
    source = _source(source_no)
    edges = [edge for edge in _STATE["edges"].values() if edge["source_no"] == source_no]
    return {
        "source_no": source_no,
        "source_group": source["fingerprint"],
        "owner_domain": source["owner_domain"],
        "owner": source["owner"],
        "table": source["table"],
        "column": source["column"],
        "description": source["description"],
        "edges": [
            {
                "edge_no": edge["edge_no"],
                "output_id": edge["output_id"],
                "output_name": edge["output_name"],
                "consumer_domain": edge["consumer_domain"],
                "mapping": edge["mapping"],
                "status": edge["status"],
            }
            for edge in edges
        ],
    }


# ---------------------------------------------------------------------------
# 来源核查
# ---------------------------------------------------------------------------


def _next_attestation_no(signed_at: dt.date) -> str:
    prefix = f"ATT-{signed_at.isoformat()}-"
    used = [
        att["attestation_no"] for att in _STATE["attestations"].values()
        if att["attestation_no"].startswith(prefix)
    ]
    return f"{prefix}{len(used) + 1:02d}"


def create_attestation(
    *,
    source_no: str,
    outputs: list[str],
    audit_batch: str,
    signer: str,
    operator: str | None = None,
    role: str | None = None,
    signed_at: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
    attestation_no: str | None = None,
    remark: str | None = None,
) -> dict[str, Any]:
    """一次核查可以覆盖同一来源的多个输出，例如第一版的甲、乙。"""
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    operator = (operator or signer or "").strip()
    if not operator:
        raise CatalogLineageError("OPERATOR_REQUIRED")
    signer = (signer or "").strip()
    if not signer:
        raise CatalogLineageError("SIGNER_REQUIRED")
    audit_batch = (audit_batch or "").strip()
    if not audit_batch:
        raise CatalogLineageError("AUDIT_BATCH_REQUIRED")
    if not outputs:
        raise CatalogLineageError("OUTPUT_NOT_FOUND", "核查至少需要一个输出")

    source = _source(source_no)
    edges = [_edge(ref) for ref in outputs]
    if any(edge["source_no"] != source_no for edge in edges):
        raise CatalogLineageError("OUTPUTS_NOT_IN_SOURCE")
    if any(edge["status"] != "active" for edge in edges):
        raise CatalogLineageError("EDGE_REVOKED")

    signed_date = _parse_date(signed_at, "签字日期", dt.date.today())
    valid_from_date = _parse_date(valid_from, "生效日期", signed_date)
    valid_until_date = _parse_date(
        valid_until, "失效日期", valid_from_date + dt.timedelta(days=180)
    )
    if valid_until_date < valid_from_date:
        raise CatalogLineageError("INVALID_VALIDITY", "失效日期不能早于生效日期")

    with _LOCK:
        # 锁内再查一次，防止并发撤权后仍写入核查。
        edges = [_edge(ref) for ref in outputs]
        if any(edge["source_no"] != source_no for edge in edges):
            raise CatalogLineageError("OUTPUTS_NOT_IN_SOURCE")
        if any(edge["status"] != "active" for edge in edges):
            raise CatalogLineageError("EDGE_REVOKED")

        no = (attestation_no or "").strip() or _next_attestation_no(signed_date)
        if no in _STATE["attestations"]:
            raise CatalogLineageError("VERSION_EXISTS", f"来源核查 {no} 已存在")

        previous = [
            att for att in _STATE["attestations"].values()
            if att["source_no"] == source_no and att["status"] == "active"
        ]
        previous.sort(key=lambda att: (att["signed_at"], att["attestation_no"]))
        attestation: dict[str, Any] = {
            "attestation_no": no,
            "source_no": source_no,
            "source_fingerprint": source["fingerprint"],
            "coverages": [
                {
                    "edge_no": edge["edge_no"],
                    "output_id": edge["output_id"],
                    "subject_digest": subject_digest(edge, source),
                    "mapping_digest": mapping_digest(edge),
                }
                for edge in edges
            ],
            "audit_batch": audit_batch,
            "signer": signer,
            "signed_at": signed_date.isoformat(),
            "valid_from": valid_from_date.isoformat(),
            "valid_until": valid_until_date.isoformat(),
            "status": "active",
            "supersedes": previous[-1]["attestation_no"] if previous else None,
            "revoked_at": None,
            "revoke_reason": None,
            "remark": remark,
        }
        attestation["signature"] = attestation_signature(attestation)
        _STATE["attestations"][no] = attestation
        _event(
            "attestation_signed", operator,
            attestation_no=no, source_group=source["fingerprint"],
            output_ids=[edge["output_id"] for edge in edges], audit_batch=audit_batch,
        )
        return _attestation_view(attestation, dt.date.today())


def revoke_attestation(
    attestation_no: str, *, operator: str, reason: str | None = None, role: str | None = None
) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    reason = (reason or "").strip()
    if not reason:
        raise CatalogLineageError("REVOCATION_REASON_REQUIRED")
    with _LOCK:
        attestation = _attestation(attestation_no)
        if attestation["status"] == "revoked":
            return _attestation_view(attestation, dt.date.today())
        attestation["status"] = "revoked"
        attestation["revoked_at"] = _now()
        attestation["revoke_reason"] = reason
        _event(
            "attestation_revoked", operator,
            attestation_no=attestation_no, reason=reason,
        )
        return _attestation_view(attestation, dt.date.today())


def list_attestations(*, role: str | None = None, as_of: str | None = None) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR}, ROLE_MAINTAINER)
    date = _parse_date(as_of, "查询日期", dt.date.today())
    items = [
        _attestation_view(att, date)
        for att in sorted(
            _STATE["attestations"].values(),
            key=lambda att: (att["signed_at"], att["attestation_no"]),
            reverse=True,
        )
    ]
    return {"items": items, "total": len(items)}


# ---------------------------------------------------------------------------
# 边撤下、共享范围变更
# ---------------------------------------------------------------------------


def revoke_edge(
    edge_ref: str, *, operator: str, reason: str | None = None,
    version_no: str | None = None, role: str | None = None,
) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    reason = (reason or "").strip()
    if not reason:
        raise CatalogLineageError("REVOCATION_REASON_REQUIRED")
    with _LOCK:
        edge = _edge(edge_ref)
        if edge["status"] == "revoked":
            return _edge_view(edge, dt.date.today())
        edge["status"] = "revoked"
        edge["revoked_at"] = _now()
        edge["revoked_version"] = version_no
        edge["revoked_reason"] = reason
        _event(
            "edge_revoked", operator,
            edge_no=edge["edge_no"], output_id=edge["output_id"], reason=reason,
            version_no=version_no,
        )
        return _edge_view(edge, dt.date.today())


def change_scope(
    edge_ref: str, *, authorized_domains: list[str], operator: str,
    role: str | None = None,
) -> dict[str, Any]:
    """共享范围变更会抬升 scope_version，并让旧签字不再满足当前主题摘要。"""
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    cleaned = sorted({str(item).strip() for item in authorized_domains if str(item).strip()})
    if not cleaned:
        raise CatalogLineageError("SCOPE_EMPTY")
    with _LOCK:
        edge = _edge(edge_ref)
        if edge["status"] != "active":
            raise CatalogLineageError("EDGE_REVOKED")
        before = list(edge["authorized_domains"])
        edge["authorized_domains"] = cleaned
        edge["scope_version"] = int(edge["scope_version"]) + 1
        _STATE["scope_changes"].append({
            "edge_no": edge["edge_no"],
            "before": before,
            "after": cleaned,
            "scope_version": edge["scope_version"],
            "operator": operator,
            "at": _now(),
        })
        _event(
            "scope_changed", operator,
            edge_no=edge["edge_no"], output_id=edge["output_id"],
            scope_version=edge["scope_version"], domains=cleaned,
        )
        return _edge_view(edge, dt.date.today())


# ---------------------------------------------------------------------------
# 目录包：生成、签发、报告
# ---------------------------------------------------------------------------


def _candidate_edges(
    issued_to: list[str], outputs: list[str] | None, withdrawn: set[str]
) -> list[dict[str, Any]]:
    edges = []
    for edge in sorted(_STATE["edges"].values(), key=lambda e: e["edge_no"]):
        if edge["status"] != "active" or edge["edge_no"] in withdrawn:
            continue
        if outputs and edge["edge_no"] not in outputs and edge["output_id"] not in outputs:
            continue
        if edge["consumer_domain"] in issued_to or set(edge["authorized_domains"]) & set(issued_to):
            edges.append(edge)
    return edges


def _prior_package_entries(edge: dict[str, Any]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for package in _STATE["packages"].values():
        for entry in package["entries"]:
            if entry["output_id"] == edge["output_id"]:
                history.append(entry)
    return history


def _basis_for(edge: dict[str, Any], attestation: dict[str, Any], digest: str) -> str:
    """判断本次签字从哪来：原样沿用、针对变化补签，还是首次核查。"""
    history = _prior_package_entries(edge)
    for entry in history:
        if (
            entry["subject_digest"] == digest
            and entry["attestation_no"] == attestation["attestation_no"]
        ):
            return "carried_over"
    if history:
        # 以前发过这个输出，但签字换了：说明是为当前主题补签的。
        return "new_signature"
    return "direct"


def _build_package(
    version_no: str, operator: str, issued_to: list[str],
    output_refs: list[str] | None, request_id: str | None,
    publish: bool, excluded_edges: set[str] | None = None,
) -> dict[str, Any]:
    """只计算目录包内容，不改账本；调用方必须持有 _LOCK。

    ``excluded_edges`` 用于把「本次要撤下的边」先排除在候选之外，这样范围
    不合规时会直接抛错，一条边都还没被撤下。
    """
    if version_no in _STATE["packages"]:
        raise CatalogLineageError("VERSION_EXISTS")

    candidates = _candidate_edges(issued_to, output_refs, excluded_edges or set())
    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for edge in candidates:
        source = _source(edge["source_no"])
        attestation, reason = _best_attestation(edge, dt.date.today())
        if attestation is None:
            skipped.append({
                "edge_no": edge["edge_no"],
                "output_id": edge["output_id"],
                "reason": reason,
                "reason_label": _coverage_label(None, reason, dt.date.today()),
            })
            continue
        digest = subject_digest(edge, source)
        entries.append({
            "edge_no": edge["edge_no"],
            "output_id": edge["output_id"],
            "output_name": edge["output_name"],
            "consumer_domain": edge["consumer_domain"],
            "source_group": source["fingerprint"],
            "mapping_digest": mapping_digest(edge),
            "subject_digest": digest,
            "attestation_no": attestation["attestation_no"],
            "audit_batch": attestation["audit_batch"],
            "signer": attestation["signer"],
            "signed_at": attestation["signed_at"],
            "valid_from": attestation["valid_from"],
            "valid_until": attestation["valid_until"],
            "basis": _basis_for(edge, attestation, digest),
            "scope_version": edge["scope_version"],
        })

    if not entries:
        raise CatalogLineageError("NO_EFFECTIVE_SCOPE")

    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    package: dict[str, Any] = {
        "version_no": version_no,
        "package_no": f"PKG-{version_no}-{stamp}-{_hash([version_no, request_id, stamp])[:6]}",
        "status": "issued" if publish else "draft",
        "generated_by": operator,
        "generated_at": _now(),
        "issued_by": operator if publish else None,
        "issued_at": _now() if publish else None,
        "issued_to": list(issued_to),
        "scope_version": max(entry["scope_version"] for entry in entries),
        "request_id": request_id,
        "entries": entries,
        "skipped": skipped,
        "withdrawn_edges": [],
    }
    return package


def _store_package(package: dict[str, Any]) -> dict[str, Any]:
    """把算好的目录包提交进账本并记事件；调用方必须持有 _LOCK。"""
    version_no = package["version_no"]
    _STATE["packages"][version_no] = package
    entries = package["entries"]
    _event(
        "package_generated", package["generated_by"],
        version_no=version_no, entry_count=len(entries), issued_to=package["issued_to"],
        basis={basis: sum(1 for e in entries if e["basis"] == basis)
               for basis in BASIS_LABELS},
    )
    return package


def publish_package(
    *,
    version_no: str,
    operator: str,
    issued_to: list[str],
    withdraw: list[str] | None = None,
    outputs: list[str] | None = None,
    request_id: str | None = None,
    publish: bool = True,
    reason: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """生成并（默认）签发一个目录包。

    撤下边和生成目录包在同一把锁内完成：要么一起生效，要么都不生效。
    """
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    version_no = str(version_no or "").strip()
    if not version_no:
        raise CatalogLineageError("UNKNOWN_FIELD", "版本号不能为空")
    issued_to = sorted({str(item).strip() for item in issued_to if str(item).strip()})
    if not issued_to:
        raise CatalogLineageError("SCOPE_EMPTY", "签发对象不能为空")
    withdraw_refs = [str(item).strip() for item in (withdraw or []) if str(item).strip()]
    output_refs = [str(item).strip() for item in (outputs or []) if str(item).strip()] or None
    reason = (reason or "版本发布撤下").strip()

    with _LOCK:
        existing = _STATE["packages"].get(version_no)
        if existing is not None:
            if request_id and existing["request_id"] == request_id:
                return {"package": _package_public(existing), "idempotent": True}
            raise CatalogLineageError("VERSION_EXISTS")

        withdraw_edges = [_edge(ref) for ref in withdraw_refs]
        planned_withdraw_ids = {
            edge["edge_no"] for edge in withdraw_edges if edge["status"] == "active"
        }
        # 先把目录包完整算出来；范围无效时直接抛错，此时一条边都还没动。
        package = _build_package(
            version_no, operator, issued_to, output_refs, request_id, publish,
            excluded_edges=planned_withdraw_ids,
        )

        for edge in withdraw_edges:
            if edge["status"] == "active":
                edge["status"] = "revoked"
                edge["revoked_at"] = _now()
                edge["revoked_version"] = version_no
                edge["revoked_reason"] = reason

        package["withdrawn_edges"] = sorted({edge["edge_no"] for edge in withdraw_edges})
        _store_package(package)
        _event(
            "package_published" if publish else "package_drafted", operator,
            version_no=version_no, withdrawn_count=len(package["withdrawn_edges"]),
            entry_count=len(package["entries"]),
        )
        return {"package": _package_public(package), "idempotent": False}


def issue_package(
    version_no: str, *, operator: str, issued_to: list[str] | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER}, ROLE_MAINTAINER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    with _LOCK:
        package = _STATE["packages"].get(version_no)
        if package is None:
            raise CatalogLineageError("VERSION_NOT_FOUND", status_code=404)
        targets = sorted({str(item).strip() for item in (issued_to or package["issued_to"])
                          if str(item).strip()})
        if not targets:
            raise CatalogLineageError("SCOPE_EMPTY", "签发对象不能为空")
        if package["status"] == "issued":
            if targets == sorted(package["issued_to"]):
                return {"package": _package_public(package), "idempotent": True}
            raise CatalogLineageError("VERSION_EXISTS", "该目录包已经签发，不能改签发范围")

        valid_entries = []
        for entry in package["entries"]:
            edge = _STATE["edges"].get(entry["edge_no"])
            if edge is None or edge["status"] != "active":
                continue
            source = _source(edge["source_no"])
            if subject_digest(edge, source) != entry["subject_digest"]:
                continue
            attestation, _ = _best_attestation(edge, dt.date.today())
            if attestation is None:
                continue
            valid_entries.append({
                **entry,
                "attestation_no": attestation["attestation_no"],
                "audit_batch": attestation["audit_batch"],
                "signer": attestation["signer"],
                "signed_at": attestation["signed_at"],
                "valid_from": attestation["valid_from"],
                "valid_until": attestation["valid_until"],
                "basis": _effective_basis(entry, attestation),
                "scope_version": edge["scope_version"],
            })
        if not valid_entries:
            raise CatalogLineageError("NO_EFFECTIVE_SCOPE")

        package["entries"] = valid_entries
        package["scope_version"] = max(
            [package["scope_version"]] + [entry["scope_version"] for entry in valid_entries]
        )
        package["issued_to"] = targets
        package["issued_by"] = operator
        package["issued_at"] = _now()
        package["status"] = "issued"
        _event(
            "package_issued", operator,
            version_no=version_no, issued_to=targets, entry_count=len(valid_entries),
        )
        return {"package": _package_public(package), "idempotent": False}


def get_package(version_no: str, *, role: str | None = None) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR, ROLE_CONSUMER}, ROLE_MAINTAINER)
    with _LOCK:
        package = _STATE["packages"].get(version_no)
        if package is None:
            raise CatalogLineageError("VERSION_NOT_FOUND", status_code=404)
        return _package_public(package)


def list_packages(*, role: str | None = None) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR, ROLE_CONSUMER}, ROLE_MAINTAINER)
    items = [
        _package_public(package)
        for package in sorted(_STATE["packages"].values(), key=lambda p: p["version_no"])
    ]
    return {"items": items, "total": len(items)}


def _entry_bindability(
    package: dict[str, Any], entry: dict[str, Any], as_of: dt.date
) -> tuple[bool, str, dict[str, Any] | None]:
    """目录包确定范围，当前核查决定这次能不能办理。

    返回 (是否可关联, 原因码, 当前最有效的核查)。补签之后，同一主题的新核查
    会自动成为本次办理的依据；旧核查仍留在签发包里作为历史证据。
    """
    if package["status"] != "issued":
        return False, "PACKAGE_NOT_ISSUED", None
    edge = _STATE["edges"].get(entry["edge_no"])
    if edge is None:
        return False, "OUTPUT_NOT_FOUND", None
    if edge["status"] != "active":
        return False, "EDGE_REVOKED", None
    attestation, reason = _best_attestation(edge, as_of)
    if attestation is None:
        return False, reason, None
    return True, "VALID", attestation


def _effective_basis(entry: dict[str, Any], attestation: dict[str, Any]) -> str:
    if entry["attestation_no"] == attestation["attestation_no"]:
        return entry["basis"]
    return "new_signature"


def package_report(
    version_no: str, *, as_of: str | None = None, role: str | None = None
) -> dict[str, Any]:
    """打开某个目录包的报告，核对原签发范围、审计批次和当前可办理情况。

    报告是治理视图，只给维护员和审计；消费域拿到的是已签发的目录包本身。
    """
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR}, ROLE_MAINTAINER)
    date = _parse_date(as_of, "核对日期", dt.date.today())
    with _LOCK:
        package = _STATE["packages"].get(version_no)
        if package is None:
            raise CatalogLineageError("VERSION_NOT_FOUND", status_code=404)

        entries = []
        for entry in package["entries"]:
            bindable, reason, attestation = _entry_bindability(package, entry, date)
            current = copy.deepcopy(entry)
            current["bindable_now"] = bindable
            current["current_status"] = "可关联" if bindable else _coverage_label(
                None, reason, date
            )
            current["current_reason"] = reason if not bindable else None
            current["current_attestation"] = (
                _attestation_ref(attestation) if attestation is not None else None
            )
            if attestation is not None:
                current["current_basis"] = _effective_basis(entry, attestation)
                current["current_valid_from"] = attestation["valid_from"]
                current["current_valid_until"] = attestation["valid_until"]
            entries.append(current)

        audit_batches = sorted({entry["audit_batch"] for entry in package["entries"]})
        source_groups = sorted({entry["source_group"] for entry in package["entries"]})
        valid_from = min((entry["valid_from"] for entry in package["entries"]), default=None)
        valid_until = max((entry["valid_until"] for entry in package["entries"]), default=None)
        bindings = [
            copy.deepcopy(binding) for binding in _STATE["bindings"]
            if binding["version_no"] == version_no
        ]
        frozen_attestations = [
            _STATE["attestations"][entry["attestation_no"]]
            for entry in package["entries"]
            if entry["attestation_no"] in _STATE["attestations"]
        ]
        return {
            "version_no": version_no,
            "package_no": package["package_no"],
            "status": package["status"],
            "generated_by": package["generated_by"],
            "generated_at": package["generated_at"],
            "issued_by": package["issued_by"],
            "issued_at": package["issued_at"],
            "issued_to": list(package["issued_to"]),
            "scope_version": package["scope_version"],
            "as_of": date.isoformat(),
            "issued_scope": {
                "output_ids": [entry["output_id"] for entry in package["entries"]],
                "output_count": len(package["entries"]),
                "domains": list(package["issued_to"]),
                "audit_batches": audit_batches,
                "attestation_nos": sorted({e["attestation_no"] for e in package["entries"]}),
                "source_groups": source_groups,
                "valid_from": valid_from,
                "valid_until": valid_until,
            },
            "entries": entries,
            "bindings": bindings,
            "withdrawn_count": len(package.get("withdrawn_edges", [])),
            "checks": {
                "entry_count": len(package["entries"]),
                "bindable_count": sum(1 for entry in entries if entry["bindable_now"]),
                "signatures_verified": all(
                    _signature_ok(att) for att in frozen_attestations
                ),
                # 只针对签发包本身：被撤权的核查证据不会留在包里。
                "no_revoked_evidence": all(
                    att["status"] != "revoked" for att in frozen_attestations
                ),
                "all_edges_active": all(
                    _STATE["edges"][entry["edge_no"]]["status"] == "active"
                    for entry in package["entries"]
                ),
            },
        }


# ---------------------------------------------------------------------------
# 消费域关联
# ---------------------------------------------------------------------------


def bind_output(
    *,
    version_no: str,
    output: str,
    consumer_domain: str,
    operator: str,
    role: str | None = None,
    as_of: str | None = None,
) -> dict[str, Any]:
    """消费域只能用已签发的目录包关联输出，且核查必须处在有效范围内。"""
    _require_role(role, {ROLE_CONSUMER, ROLE_MAINTAINER}, ROLE_CONSUMER)
    if not str(operator or "").strip():
        raise CatalogLineageError("OPERATOR_REQUIRED")
    consumer_domain = str(consumer_domain or "").strip()
    if not consumer_domain:
        raise CatalogLineageError("DOMAIN_REQUIRED", "关联需要提供消费域")
    date = _parse_date(as_of, "关联日期", dt.date.today())

    with _LOCK:
        package = _STATE["packages"].get(version_no)
        if package is None:
            raise CatalogLineageError("VERSION_NOT_FOUND", status_code=404)
        if package["status"] != "issued":
            raise CatalogLineageError("PACKAGE_NOT_ISSUED")
        if consumer_domain not in package["issued_to"]:
            raise CatalogLineageError("NOT_ISSUED_TO_DOMAIN")

        entry = next(
            (
                item for item in package["entries"]
                if item["output_id"] == output or item["edge_no"] == output
            ),
            None,
        )
        if entry is None:
            try:
                edge = _edge(output)
            except CatalogLineageError:
                raise CatalogLineageError("OUTPUT_NOT_FOUND", status_code=404) from None
            if edge["status"] != "active":
                raise CatalogLineageError("EDGE_REVOKED")
            raise CatalogLineageError("NOT_IN_ISSUANCE_SCOPE")

        edge = _edge(entry["edge_no"])
        if edge["status"] != "active":
            raise CatalogLineageError("EDGE_REVOKED")
        if consumer_domain not in edge["authorized_domains"]:
            raise CatalogLineageError("SOURCE_NOT_AUTHORIZED", status_code=403)

        bindable, reason, attestation = _entry_bindability(package, entry, date)
        if not bindable:
            raise CatalogLineageError(reason)
        assert attestation is not None

        basis = _effective_basis(entry, attestation)
        binding_no = f"BIND-{len(_STATE['bindings']) + 1:04d}"
        binding = {
            "binding_no": binding_no,
            "version_no": version_no,
            "package_no": package["package_no"],
            "output_id": entry["output_id"],
            "output_name": entry["output_name"],
            "edge_no": entry["edge_no"],
            "consumer_domain": consumer_domain,
            "source_group": entry["source_group"],
            "attestation_no": attestation["attestation_no"],
            "audit_batch": attestation["audit_batch"],
            "basis": basis,
            "valid_from": attestation["valid_from"],
            "valid_until": attestation["valid_until"],
            "subject_digest": entry["subject_digest"],
            "bound_at": _now(),
            "as_of": date.isoformat(),
            "operator": operator,
            "attestation_status": attestation["status"],
            "package_attestation_no": entry["attestation_no"],
        }
        _STATE["bindings"].append(binding)
        _event(
            "output_bound", operator,
            version_no=version_no, output_id=entry["output_id"],
            consumer_domain=consumer_domain, attestation_no=attestation["attestation_no"],
            basis=basis,
        )
        return copy.deepcopy(binding)


def list_bindings(
    *, version_no: str | None = None, consumer_domain: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR, ROLE_CONSUMER}, ROLE_MAINTAINER)
    items = [
        copy.deepcopy(binding) for binding in _STATE["bindings"]
        if (version_no is None or binding["version_no"] == version_no)
        and (consumer_domain is None or binding["consumer_domain"] == consumer_domain)
    ]
    return {"items": items, "total": len(items)}


def list_events(*, role: str | None = None) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR}, ROLE_MAINTAINER)
    return {"items": copy.deepcopy(_STATE["events"]), "total": len(_STATE["events"])}


def overview(*, role: str | None = None) -> dict[str, Any]:
    _require_role(role, {ROLE_MAINTAINER, ROLE_AUDITOR, ROLE_CONSUMER}, ROLE_MAINTAINER)
    return {
        **_state_summary(),
        "active_attestations": sum(
            1 for att in _STATE["attestations"].values() if att["status"] == "active"
        ),
    }
