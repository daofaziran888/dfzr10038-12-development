"""目录血缘接口：索引查询、来源核查、目录包签发、消费域关联和核对报告。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.services import catalog_lineage_ops as ops
from app.services.catalog_lineage import CatalogLineageError

router = APIRouter(prefix="/api/catalog-lineage", tags=["目录血缘"])


def _fail(error: CatalogLineageError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"ok": False, "code": error.code, "message": error.message},
    )


async def _body(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _role(request: Request) -> str | None:
    return request.query_params.get("role") or request.headers.get("X-Role")


@router.get("/overview")
def overview(request: Request):
    return ops.overview(role=_role(request))


@router.get("/index")
def index(request: Request):
    try:
        return ops.index_view(
            role=_role(request),
            domain=request.query_params.get("domain") or request.headers.get("X-Domain"),
            as_of=request.query_params.get("as_of"),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/sources/{source_no}")
def source_detail(source_no: str, request: Request):
    try:
        return ops.source_detail(source_no, role=_role(request))
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/attestations")
def list_attestations(request: Request):
    try:
        return ops.list_attestations(
            role=_role(request), as_of=request.query_params.get("as_of"))
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/attestations")
async def create_attestation(request: Request):
    payload = await _body(request)
    try:
        return ops.create_attestation(
            source_no=str(payload.get("source_no") or ""),
            outputs=[str(item) for item in payload.get("outputs") or []],
            audit_batch=str(payload.get("audit_batch") or ""),
            signer=str(payload.get("signer") or ""),
            operator=payload.get("operator"),
            role=payload.get("role") or _role(request),
            signed_at=payload.get("signed_at"),
            valid_from=payload.get("valid_from"),
            valid_until=payload.get("valid_until"),
            attestation_no=payload.get("attestation_no"),
            remark=payload.get("remark"),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/attestations/{attestation_no}/revoke")
async def revoke_attestation(attestation_no: str, request: Request):
    payload = await _body(request)
    try:
        return ops.revoke_attestation(
            attestation_no,
            operator=str(payload.get("operator") or ""),
            reason=payload.get("reason"),
            role=payload.get("role") or _role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/edges/{edge_ref}/revoke")
async def revoke_edge(edge_ref: str, request: Request):
    payload = await _body(request)
    try:
        return ops.revoke_edge(
            edge_ref,
            operator=str(payload.get("operator") or ""),
            reason=payload.get("reason"),
            version_no=payload.get("version_no"),
            role=payload.get("role") or _role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/edges/{edge_ref}/scope")
async def change_scope(edge_ref: str, request: Request):
    payload = await _body(request)
    try:
        return ops.change_scope(
            edge_ref,
            authorized_domains=[str(item) for item in payload.get("authorized_domains") or []],
            operator=str(payload.get("operator") or ""),
            role=payload.get("role") or _role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/packages")
def list_packages(request: Request):
    try:
        return ops.list_packages(role=_role(request))
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/packages")
async def publish_package(request: Request):
    payload = await _body(request)
    try:
        return ops.publish_package(
            version_no=str(payload.get("version_no") or ""),
            operator=str(payload.get("operator") or ""),
            issued_to=[str(item) for item in payload.get("issued_to") or []],
            withdraw=[str(item) for item in payload.get("withdraw") or []],
            outputs=[str(item) for item in payload.get("outputs") or []],
            request_id=payload.get("request_id"),
            publish=bool(payload.get("publish", True)),
            reason=payload.get("reason"),
            role=payload.get("role") or _role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/packages/{version_no}")
def get_package(version_no: str, request: Request):
    try:
        return ops.get_package(version_no, role=_role(request))
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/packages/{version_no}/report")
def package_report(version_no: str, request: Request):
    try:
        return ops.package_report(
            version_no, as_of=request.query_params.get("as_of"), role=_role(request))
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/packages/{version_no}/issue")
async def issue_package(version_no: str, request: Request):
    payload = await _body(request)
    try:
        return ops.issue_package(
            version_no,
            operator=str(payload.get("operator") or ""),
            issued_to=[str(item) for item in payload.get("issued_to") or []],
            role=payload.get("role") or _role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/bindings")
def list_bindings(request: Request):
    try:
        return ops.list_bindings(
            version_no=request.query_params.get("version_no"),
            consumer_domain=request.query_params.get("consumer_domain"),
            role=_role(request),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/bindings")
async def bind_output(request: Request):
    payload = await _body(request)
    try:
        return ops.bind_output(
            version_no=str(payload.get("version_no") or ""),
            output=str(payload.get("output") or ""),
            consumer_domain=str(payload.get("consumer_domain") or ""),
            operator=str(payload.get("operator") or ""),
            role=payload.get("role") or _role(request),
            as_of=payload.get("as_of"),
        )
    except CatalogLineageError as error:
        return _fail(error)


@router.get("/events")
def list_events(request: Request):
    try:
        return ops.list_events(role=_role(request))
    except CatalogLineageError as error:
        return _fail(error)


@router.post("/reset")
def reset():
    return ops.reset_state()
