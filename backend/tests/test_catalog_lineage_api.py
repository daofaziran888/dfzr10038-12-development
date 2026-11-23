"""目录血缘接口测试：HTTP 契约、权限过滤不泄露、完整第二版流程。"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.services import catalog_lineage_ops as ops


class CatalogLineageApiTest(unittest.TestCase):
    def setUp(self) -> None:
        ops.reset_state()
        self.client = TestClient(app)

    def _publish_v2(self):
        response = self.client.post("/api/catalog-lineage/packages", json={
            "version_no": "v2",
            "operator": "陈目录",
            "issued_to": ["推荐域", "营销域"],
            "withdraw": ["OUT-YI"],
            "reason": "第二版只撤下乙的边",
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_health_still_routes_before_dynamic_module(self) -> None:
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_consumer_index_hides_sensitive_material(self) -> None:
        response = self.client.get(
            "/api/catalog-lineage/index", params={"role": "consumer", "domain": "推荐域"})
        self.assertEqual(response.status_code, 200)
        body = response.text
        for secret in ("dwd_user_profile", "age_bucket_5x", "dwd_order_detail", "amount ->"):
            self.assertNotIn(secret, body)
        payload = response.json()
        self.assertEqual(payload["view"], "consumer")
        self.assertNotIn("source_no", payload["items"][0])

    def test_consumer_cannot_read_source_detail(self) -> None:
        response = self.client.get(
            "/api/catalog-lineage/sources/SRC-USER-AGE", params={"role": "consumer"})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("dwd_user_profile", response.text)

    def test_consumer_cannot_publish(self) -> None:
        response = self.client.post("/api/catalog-lineage/packages", json={
            "version_no": "v2", "operator": "推荐域值班", "role": "consumer",
            "issued_to": ["推荐域"],
        })
        self.assertEqual(response.status_code, 403)

    def test_full_second_version_flow(self) -> None:
        package = self._publish_v2()["package"]
        self.assertEqual([entry["output_id"] for entry in package["entries"]], ["OUT-JIA"])
        self.assertEqual(package["entries"][0]["basis"], "carried_over")

        bind = self.client.post("/api/catalog-lineage/bindings", json={
            "version_no": "v2", "output": "OUT-JIA",
            "consumer_domain": "推荐域", "operator": "推荐域值班",
        })
        self.assertEqual(bind.status_code, 200, bind.text)
        binding = bind.json()
        self.assertEqual(binding["attestation_no"], "ATT-2026-11-01-01")
        self.assertEqual(binding["audit_batch"], "AUD-2026-11-01-B1")
        self.assertEqual(binding["valid_from"], "2026-11-01")
        self.assertEqual(binding["valid_until"], "2027-05-31")
        self.assertEqual(binding["basis"], "carried_over")

        refused = self.client.post("/api/catalog-lineage/bindings", json={
            "version_no": "v2", "output": "OUT-YI",
            "consumer_domain": "营销域", "operator": "营销域值班",
        })
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(refused.json()["code"], "EDGE_REVOKED")

        report = self.client.get("/api/catalog-lineage/packages/v1/report")
        self.assertEqual(report.status_code, 200)
        scope = report.json()["issued_scope"]
        self.assertEqual(scope["output_ids"], ["OUT-JIA", "OUT-YI"])
        self.assertEqual(scope["audit_batches"], ["AUD-2026-11-01-B1"])

        signed = self.client.post("/api/catalog-lineage/attestations", json={
            "source_no": "SRC-USER-AGE", "outputs": ["OUT-JIA"],
            "audit_batch": "AUD-2026-11-23-B9", "signer": "陈目录",
            "operator": "陈目录", "signed_at": "2026-11-23",
            "valid_from": "2026-11-23", "valid_until": "2027-06-30",
        })
        self.assertEqual(signed.status_code, 200, signed.text)
        attestation_no = signed.json()["attestation_no"]

        rebound = self.client.post("/api/catalog-lineage/bindings", json={
            "version_no": "v2", "output": "OUT-JIA",
            "consumer_domain": "推荐域", "operator": "推荐域值班",
        })
        self.assertEqual(rebound.status_code, 200, rebound.text)
        self.assertEqual(rebound.json()["attestation_no"], attestation_no)
        self.assertEqual(rebound.json()["basis"], "new_signature")
        self.assertEqual(rebound.json()["valid_until"], "2027-06-30")

        bindings = self.client.get(
            "/api/catalog-lineage/bindings", params={"version_no": "v2"})
        rows = bindings.json()["items"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            [(row["attestation_no"], row["valid_until"]) for row in rows],
            [("ATT-2026-11-01-01", "2027-05-31"), (attestation_no, "2027-06-30")],
        )

    def test_duplicate_version_returns_conflict(self) -> None:
        self._publish_v2()
        again = self.client.post("/api/catalog-lineage/packages", json={
            "version_no": "v2", "operator": "陈目录", "issued_to": ["推荐域"],
        })
        self.assertEqual(again.status_code, 409)
        self.assertEqual(again.json()["code"], "VERSION_EXISTS")

    def test_same_named_source_has_distinct_groups_in_api(self) -> None:
        user = self.client.get(
            "/api/catalog-lineage/sources/SRC-USER-AGE").json()
        member = self.client.get(
            "/api/catalog-lineage/sources/SRC-MEMBER-AGE").json()
        self.assertNotEqual(user["source_group"], member["source_group"])

    def test_consumer_cannot_open_governance_report(self) -> None:
        self._publish_v2()
        response = self.client.get(
            "/api/catalog-lineage/packages/v1/report", params={"role": "consumer"})
        self.assertEqual(response.status_code, 403)

    def test_consumer_can_read_issued_package(self) -> None:
        self._publish_v2()
        response = self.client.get(
            "/api/catalog-lineage/packages/v2", params={"role": "consumer"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            [entry["output_id"] for entry in payload["entries"]], ["OUT-JIA"])
        for secret in ("dwd_user_profile", "age_bucket_5x", "mapping\""):
            self.assertNotIn(secret, response.text)

    def test_errors_are_json_and_do_not_leak(self) -> None:
        response = self.client.post("/api/catalog-lineage/bindings", json={
            "version_no": "missing", "output": "OUT-JIA",
            "consumer_domain": "推荐域", "operator": "推荐域值班",
        })
        self.assertEqual(response.status_code, 404)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "VERSION_NOT_FOUND")
        self.assertNotIn("dwd_user_profile", response.text)


if __name__ == "__main__":
    unittest.main()
