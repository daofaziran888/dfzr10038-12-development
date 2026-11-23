"""目录血缘领域测试：权限转换、核查沿用、撤权证据隔离、并发签发。"""
from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from app.services import catalog_lineage_ops as ops
from app.services.catalog_lineage import CatalogLineageError

SOURCE_JIA = "SRC-USER-AGE"
OUTPUT_JIA = "OUT-JIA"
OUTPUT_YI = "OUT-YI"
OUTPUT_MEMBER = "OUT-MEMBER-AGE"

FORBIDDEN_IN_CONSUMER_INDEX = [
    "dwd_user_profile",
    "age_bucket_5x",
    "age_band_10y",
    "member_age_band_30d",
    "dwd_order_detail",
    "order_amount_sum_30d",
]


class CatalogLineageTest(unittest.TestCase):
    def setUp(self) -> None:
        ops.reset_state()

    # ---- 权限转换 -----------------------------------------------------
    def test_consumer_index_masks_source_table_and_mapping(self) -> None:
        view = ops.index_view(role="consumer", domain="推荐域")
        text = repr(view)
        for secret in FORBIDDEN_IN_CONSUMER_INDEX:
            self.assertNotIn(secret, text)
        self.assertEqual(view["view"], "consumer")
        self.assertTrue(view["groups"][0]["source_group"].startswith("SG-"))

    def test_consumer_index_requires_domain(self) -> None:
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.index_view(role="consumer")
        self.assertEqual(ctx.exception.code, "DOMAIN_REQUIRED")

    def test_source_detail_is_governance_only(self) -> None:
        detail = ops.source_detail(SOURCE_JIA, role="maintainer")
        self.assertEqual(detail["table"], "dwd_user_profile")
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.source_detail(SOURCE_JIA, role="consumer")
        self.assertEqual(ctx.exception.code, "ROLE_FORBIDDEN")

    def test_same_source_two_domains_share_group(self) -> None:
        marketing = ops.index_view(role="consumer", domain="营销域")
        jia_view = next(item for item in marketing["items"] if item["output_id"] == OUTPUT_JIA)
        output_ids = {
            output["output_id"]
            for group in marketing["groups"]
            if group["source_group"] == jia_view["source_group"]
            for output in group["outputs"]
        }
        self.assertEqual(output_ids, {OUTPUT_JIA, OUTPUT_YI})

    def test_same_named_source_in_other_domain_keeps_identity(self) -> None:
        user = ops.source_detail(SOURCE_JIA, role="maintainer")
        member = ops.source_detail("SRC-MEMBER-AGE", role="maintainer")
        self.assertEqual(user["table"], member["table"])
        self.assertEqual(user["column"], member["column"])
        self.assertNotEqual(user["source_group"], member["source_group"])

    # ---- 核查范围与异域同名来源 ---------------------------------------
    def test_member_attestation_is_independent(self) -> None:
        member_att = ops.list_attestations(role="maintainer")["items"]
        att = next(item for item in member_att if item["source_no"] == "SRC-MEMBER-AGE")
        self.assertEqual(
            {coverage["output_id"] for coverage in att["coverages"]}, {OUTPUT_MEMBER})

        ops.revoke_attestation(
            att["attestation_no"], operator="陈目录", reason="会员域核查撤回",
        )
        member_view = ops.index_view(role="consumer", domain="会员运营域")
        self.assertEqual(member_view["items"][0]["coverage_status"], "ATTESTATION_REVOKED")
        # 用户域的甲、乙不受会员域撤权影响。
        marketing_view = ops.index_view(role="consumer", domain="营销域")
        self.assertEqual(
            {item["output_id"]: item["coverage_status"] for item in marketing_view["items"]},
            {OUTPUT_JIA: "VALID", OUTPUT_YI: "VALID"},
        )

    # ---- 第二版：只撤乙，甲沿用未变签字 --------------------------------
    def _publish_v2(self) -> dict:
        return ops.publish_package(
            version_no="v2",
            operator="陈目录",
            issued_to=["推荐域", "营销域"],
            withdraw=[OUTPUT_YI],
            reason="第二版撤下乙的边",
        )["package"]

    def test_v2_withdraws_only_yi_and_carries_over_jia(self) -> None:
        package = self._publish_v2()
        output_ids = [entry["output_id"] for entry in package["entries"]]
        self.assertEqual(output_ids, [OUTPUT_JIA])
        self.assertEqual(package["withdrawn_count"], 1)
        self.assertEqual(package["entries"][0]["basis"], "carried_over")
        self.assertEqual(package["entries"][0]["attestation_no"], "ATT-2026-11-01-01")
        self.assertNotIn("OUT-YI", repr(package))

    def test_v1_report_keeps_original_scope_and_batch(self) -> None:
        self._publish_v2()
        report = ops.package_report("v1", role="maintainer")
        self.assertEqual(
            report["issued_scope"]["output_ids"], [OUTPUT_JIA, OUTPUT_YI])
        self.assertEqual(
            report["issued_scope"]["audit_batches"], ["AUD-2026-11-01-B1"])
        self.assertEqual(
            report["issued_scope"]["attestation_nos"], ["ATT-2026-11-01-01"])
        flags = {entry["output_id"]: entry["bindable_now"] for entry in report["entries"]}
        self.assertEqual(flags, {OUTPUT_JIA: True, OUTPUT_YI: False})

    def test_bind_jia_with_carried_signature_reports_basis_and_validity(self) -> None:
        self._publish_v2()
        binding = ops.bind_output(
            version_no="v2", output=OUTPUT_JIA, consumer_domain="推荐域",
            operator="推荐域值班",
        )
        self.assertEqual(binding["attestation_no"], "ATT-2026-11-01-01")
        self.assertEqual(binding["basis"], "carried_over")
        self.assertEqual(binding["valid_from"], "2026-11-01")
        self.assertEqual(binding["valid_until"], "2027-05-31")
        self.assertEqual(binding["audit_batch"], "AUD-2026-11-01-B1")

    def test_bind_yi_after_v2_is_refused(self) -> None:
        self._publish_v2()
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.bind_output(
                version_no="v2", output=OUTPUT_YI, consumer_domain="营销域",
                operator="营销域值班",
            )
        self.assertEqual(ctx.exception.code, "EDGE_REVOKED")

    def test_bind_requires_issued_package(self) -> None:
        ops.publish_package(
            version_no="v2-draft", operator="陈目录", issued_to=["推荐域"],
            publish=False,
        )
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.bind_output(
                version_no="v2-draft", output=OUTPUT_JIA, consumer_domain="推荐域",
                operator="推荐域值班",
            )
        self.assertEqual(ctx.exception.code, "PACKAGE_NOT_ISSUED")

    def test_bind_requires_domain_in_issued_scope(self) -> None:
        self._publish_v2()
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.bind_output(
                version_no="v2", output=OUTPUT_JIA, consumer_domain="风控域",
                operator="风控域值班",
            )
        self.assertEqual(ctx.exception.code, "NOT_ISSUED_TO_DOMAIN")

    # ---- 补签甲：新旧两次关联的来源与有效期 ----------------------------
    def test_supplementary_signature_changes_binding_evidence(self) -> None:
        self._publish_v2()
        first = ops.bind_output(
            version_no="v2", output=OUTPUT_JIA, consumer_domain="推荐域",
            operator="推荐域值班",
        )
        attestation = ops.create_attestation(
            source_no=SOURCE_JIA, outputs=[OUTPUT_JIA],
            audit_batch="AUD-2026-11-23-B9", signer="陈目录", operator="陈目录",
            signed_at="2026-11-23", valid_from="2026-11-23", valid_until="2027-06-30",
        )
        second = ops.bind_output(
            version_no="v2", output=OUTPUT_JIA, consumer_domain="推荐域",
            operator="推荐域值班",
        )
        self.assertEqual(first["attestation_no"], "ATT-2026-11-01-01")
        self.assertEqual(first["valid_until"], "2027-05-31")
        self.assertEqual(second["attestation_no"], attestation["attestation_no"])
        self.assertEqual(second["basis"], "new_signature")
        self.assertEqual(second["valid_from"], "2026-11-23")
        self.assertEqual(second["valid_until"], "2027-06-30")
        # 已落地的旧关联不被改写，审计仍能看到当时的依据。
        bindings = ops.list_bindings(version_no="v2", role="auditor")["items"]
        self.assertEqual([item["binding_no"] for item in bindings], ["BIND-0001", "BIND-0002"])
        self.assertEqual(bindings[0]["attestation_no"], "ATT-2026-11-01-01")
        report = ops.package_report("v2", role="maintainer")
        entry = report["entries"][0]
        self.assertEqual(entry["attestation_no"], "ATT-2026-11-01-01")
        self.assertEqual(entry["current_attestation"]["attestation_no"], attestation["attestation_no"])

    def test_new_signature_does_not_cover_sibling_output(self) -> None:
        attestation = ops.create_attestation(
            source_no=SOURCE_JIA, outputs=[OUTPUT_JIA], audit_batch="AUD-B9",
            signer="陈目录", operator="陈目录",
        )
        self.assertEqual(
            [coverage["output_id"] for coverage in attestation["coverages"]], [OUTPUT_JIA])
        ops.revoke_attestation(
            "ATT-2026-11-01-01", operator="陈目录", reason="旧核查被新范围替代",
        )
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.bind_output(
                version_no="v1", output=OUTPUT_YI, consumer_domain="营销域",
                operator="营销域值班",
            )
        self.assertEqual(ctx.exception.code, "ATTESTATION_REVOKED")

    # ---- 共享范围变更让旧签字失效 -------------------------------------
    def test_scope_change_invalidates_old_signature(self) -> None:
        self._publish_v2()
        ops.change_scope(
            OUTPUT_JIA, authorized_domains=["推荐域", "营销域", "风控域"],
            operator="陈目录",
        )
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.bind_output(
                version_no="v2", output=OUTPUT_JIA, consumer_domain="推荐域",
                operator="推荐域值班",
            )
        self.assertEqual(ctx.exception.code, "SUBJECT_CHANGED")
        re_signed = ops.create_attestation(
            source_no=SOURCE_JIA, outputs=[OUTPUT_JIA], audit_batch="AUD-B10",
            signer="陈目录", operator="陈目录", signed_at="2026-11-23",
        )
        binding = ops.bind_output(
            version_no="v2", output=OUTPUT_JIA, consumer_domain="推荐域",
            operator="推荐域值班",
        )
        self.assertEqual(binding["attestation_no"], re_signed["attestation_no"])

    def test_revoked_evidence_never_enters_new_package(self) -> None:
        ops.revoke_attestation(
            "ATT-2026-11-01-01", operator="陈目录", reason="签字证据失效",
        )
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.publish_package(
                version_no="v2", operator="陈目录",
                issued_to=["推荐域", "营销域"], withdraw=[OUTPUT_YI],
            )
        self.assertEqual(ctx.exception.code, "NO_EFFECTIVE_SCOPE")
        self.assertNotIn("v2", ops.list_packages(role="maintainer")["items"][0]["version_no"])

    def test_failed_publish_does_not_revoke_any_edge(self) -> None:
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.publish_package(
                version_no="v2", operator="陈目录", issued_to=["推荐域", "营销域"],
                withdraw=[OUTPUT_JIA, OUTPUT_YI],
            )
        self.assertEqual(ctx.exception.code, "NO_EFFECTIVE_SCOPE")
        active = {
            item["output_id"]: item["status"]
            for item in ops.index_view(role="maintainer")["items"]
        }
        self.assertEqual(active[OUTPUT_JIA], "active")
        self.assertEqual(active[OUTPUT_YI], "active")

    def test_withdrawn_edge_evidence_absent_from_v2(self) -> None:
        package = self._publish_v2()
        self.assertNotIn(OUTPUT_YI, repr(package))
        report = ops.package_report("v2", role="maintainer")
        self.assertEqual(
            [entry["output_id"] for entry in report["entries"]], [OUTPUT_JIA])
        self.assertEqual(
            report["issued_scope"]["audit_batches"], ["AUD-2026-11-01-B1"])

    # ---- 一次性签发与并发 ---------------------------------------------
    def test_duplicate_version_cannot_publish_twice(self) -> None:
        self._publish_v2()
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.publish_package(
                version_no="v2", operator="陈目录", issued_to=["推荐域"],
            )
        self.assertEqual(ctx.exception.code, "VERSION_EXISTS")
        self.assertEqual(
            [package["version_no"] for package in ops.list_packages(role="maintainer")["items"]],
            ["v1", "v2"],
        )

    def test_same_request_is_idempotent(self) -> None:
        first = ops.publish_package(
            version_no="v2", operator="陈目录", issued_to=["推荐域", "营销域"],
            withdraw=[OUTPUT_YI], request_id="req-1",
        )
        second = ops.publish_package(
            version_no="v2", operator="陈目录", issued_to=["推荐域", "营销域"],
            withdraw=[OUTPUT_YI], request_id="req-1",
        )
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["package"]["package_no"], second["package"]["package_no"])

    def test_concurrent_publish_only_one_package(self) -> None:
        def publish() -> str:
            try:
                package = ops.publish_package(
                    version_no="v2", operator="陈目录",
                    issued_to=["推荐域", "营销域"], withdraw=[OUTPUT_YI],
                )
                return "published:" + package["package"]["package_no"]
            except CatalogLineageError as error:
                return "error:" + error.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: publish(), range(24)))

        published = {result for result in results if result.startswith("published:")}
        errors = {result for result in results if result.startswith("error:")}
        self.assertEqual(len(published), 1)
        self.assertEqual(errors, {"error:VERSION_EXISTS"})
        packages = [
            package for package in ops.list_packages(role="maintainer")["items"]
            if package["version_no"] == "v2"
        ]
        self.assertEqual(len(packages), 1)

    def test_concurrent_scope_change_and_publish_never_double_issues(self) -> None:
        barrier = threading.Barrier(2)
        results: list[str] = []

        def publish() -> None:
            barrier.wait()
            try:
                ops.publish_package(
                    version_no="v2", operator="陈目录",
                    issued_to=["推荐域", "营销域"], withdraw=[OUTPUT_YI],
                )
                results.append("published")
            except CatalogLineageError as error:
                results.append(error.code)

        def scope() -> None:
            barrier.wait()
            try:
                ops.change_scope(
                    OUTPUT_JIA, authorized_domains=["推荐域", "营销域", "风控域"],
                    operator="陈目录",
                )
                results.append("scoped")
            except CatalogLineageError as error:
                results.append(error.code)

        for _ in range(20):
            ops.reset_state()
            results.clear()
            threads = [threading.Thread(target=publish), threading.Thread(target=scope)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            packages = [
                package for package in ops.list_packages(role="maintainer")["items"]
                if package["version_no"] == "v2"
            ]
            self.assertLessEqual(len(packages), 1)
            if packages:
                package = packages[0]
                self.assertEqual(package["status"], "issued")
                self.assertEqual(package["issued_to"], ["推荐域", "营销域"])
                self.assertTrue(package["package_no"].startswith("PKG-v2-"))
            self.assertIn("scoped", results)

    # ---- 其他不变量 ---------------------------------------------------
    def test_attestation_signature_tamper_is_rejected(self) -> None:
        ops.revoke_attestation(
            "ATT-2026-11-01-01", operator="陈目录", reason="重新签字前的占位",
        )
        re_signed = ops.create_attestation(
            source_no=SOURCE_JIA, outputs=[OUTPUT_JIA], audit_batch="AUD-B11",
            signer="陈目录", operator="陈目录",
        )
        # 直接篡改账本里的有效期，签字校验必须拒绝它。
        ops._STATE["attestations"][re_signed["attestation_no"]]["valid_until"] = "2099-12-31"
        view = ops.index_view(role="consumer", domain="推荐域")
        jia = next(item for item in view["items"] if item["output_id"] == OUTPUT_JIA)
        self.assertEqual(jia["coverage_status"], "SIGNATURE_INVALID")

    def test_attestation_requires_audit_batch_and_signer(self) -> None:
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.create_attestation(
                source_no=SOURCE_JIA, outputs=[OUTPUT_JIA],
                audit_batch="", signer="陈目录", operator="陈目录",
            )
        self.assertEqual(ctx.exception.code, "AUDIT_BATCH_REQUIRED")
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.create_attestation(
                source_no=SOURCE_JIA, outputs=[OUTPUT_JIA],
                audit_batch="AUD-B", signer="", operator="陈目录",
            )
        self.assertEqual(ctx.exception.code, "SIGNER_REQUIRED")

    def test_mixed_source_attestation_refused(self) -> None:
        with self.assertRaises(CatalogLineageError) as ctx:
            ops.create_attestation(
                source_no=SOURCE_JIA, outputs=[OUTPUT_JIA, OUTPUT_MEMBER],
                audit_batch="AUD-B", signer="陈目录", operator="陈目录",
            )
        self.assertEqual(ctx.exception.code, "OUTPUTS_NOT_IN_SOURCE")


if __name__ == "__main__":
    unittest.main()
