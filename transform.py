import os
import re
import sys
from csaf_types import CSAF_JSON, from_path, Vulnerability as CVuln
from vulnerability_db import (
    Vulnerability,
    VulnerabilityDB,
    VulnerabilityMetadata,
    VulnerabilityRecordPair,
    compare_vulnerability_sets,
)

SEVERITY_MAP = {
    "critical": "Critical",
    "important": "High",
    "moderate": "Medium",
    "low": "Low",
}


RENAMED_PACKAGES = {
    # "kernel-rt": "realtime-kernel",
    # "realtime-kernel": "kernel-rt",
}

RHEL_VERSIONS_TO_NAMESPACES = {
    "5": "redhat:distro:redhat:5",
    "6": "redhat:distro:redhat:6",
    "7": "redhat:distro:redhat:7",
    "8": "redhat:distro:redhat:8",
    "9": "redhat:distro:redhat:9",
}

LANGPACK_RE = r"-langpack(-[a-z]{2,3})?"

APP_STREAM_RE = r"Red Hat Enterprise Linux AppStream \(v\. (\d+)\)"
BASE_OS_RE = r"Red Hat Enterprise Linux BaseOS \(v\. (\d+)\)"
RHEL_5_SERVER_RE = r"Red Hat Enterprise Linux \(v\. (\d+) server\)"
RHEL_5_SERVER_RE2 = r"^Red Hat Enterprise Linux Server \(v\. (\d+)\)"
RHEL_DESKTOP_RE = r"^Red Hat Enterprise Linux Desktop \(v\. (\d+)\)"
RHEL_CLIENT_OPTIONAL_RE = r"Red Hat Enterprise Linux Client Optional \(v\. (\d+)\)"
RHEL_CLIENT_RE = r"Red Hat Enterprise Linux Client \(v\. (\d+)\)"
RHEL_RT_RE = r"Red Hat Enterprise Linux RT \(v\. (\d+)\)"
RHEL_RT_RE2 = r"Red Hat Enterprise Linux for Real Time \(v\. (\d+)\)"
RHEL_CRB_RE = r"Red Hat CodeReady Linux Builder \(v\. (\d+)\)"


def debug_print(msg: str, file=sys.stderr):
    if "-v" not in sys.argv:
        return
    filters = set()
    for i, v in enumerate(sys.argv):
        if v == "-g" and len(sys.argv) >= i:
            filters.add(sys.argv[i + 1])

    if filters and not all(f in msg for f in filters):
        return
    print(msg, file=file)


def namespace_or_none_if_ignored(distro_like_name: str) -> str | None:
    result = None
    version = None
    res = [
        APP_STREAM_RE,
        BASE_OS_RE,
        RHEL_5_SERVER_RE,
        RHEL_5_SERVER_RE2,
        RHEL_DESKTOP_RE,
        RHEL_CLIENT_OPTIONAL_RE,
        RHEL_CLIENT_RE,
        RHEL_RT_RE,
        RHEL_RT_RE2,
        RHEL_CRB_RE,
    ]
    for r in res:
        match = re.search(r, distro_like_name)
        if match:
            version = match.group(1)
            break
    if not version and " " in distro_like_name:
        distro, v = distro_like_name.rsplit(" ", 1)
        if distro == "Red Hat Enterprise Linux":
            version = v

    if version:
        result = RHEL_VERSIONS_TO_NAMESPACES.get(version)

    debug_print(f"getting ns for {distro_like_name}: {result}", file=sys.stderr)
    return result


def get_severity(aggregate_severity_text: str) -> str:
    if aggregate_severity_text not in SEVERITY_MAP:
        debug_print(f"missing {aggregate_severity_text}", file=sys.stderr)
    return SEVERITY_MAP.get(aggregate_severity_text, "TODO")


def trim_rpm_version_suffix(product_id: str) -> str:
    version_suffix = r"-(\d+):.*$"
    return re.sub(version_suffix, "", product_id)


def renamed_product(name: str) -> str:
    if name not in RENAMED_PACKAGES:
        return name
    return RENAMED_PACKAGES[name]


def transform(c: CSAF_JSON) -> set[VulnerabilityRecordPair]:
    result = list()
    for v in c.vulnerabilities:
        unaffected = (
            set(v.product_status.known_not_affected) if v.product_status else set()
        )
        fixed = set(v.product_status.fixed) if v.product_status else set()
        not_fixed = set(v.product_status.known_affected) if v.product_status else set()
        id = v.cve
        severity = get_severity(c.document.aggregate_severity.text)
        products = list()
        ids_to_first_parents = {
            pid: c.product_tree.first_parent(pid)
            for pid in unaffected | fixed | not_fixed
        }
        ids_to_second_parents = {
            pid: c.product_tree.second_parent(pid)
            for pid in unaffected | fixed | not_fixed
        }
        distro_ids_to_names = {
            b.product.product_id: b.product.name
            for b in c.product_tree.branches[0].product_name_branches()
            if b.product
        }

        # TODO: make this dict[str,str] where keys are original ids and values are cleaned up ids
        def clean_product_id(pid: str) -> str:
            second_parent = ids_to_second_parents.get(pid)
            p = pid
            if second_parent:
                # p = p.removeprefix(second_parent)
                p = second_parent
                p = re.sub(r":\d(\.\d)*:\d{19}:[a-fA-F0-9]{8}$", "", p)
            p = trim_rpm_version_suffix(p)
            p = p.removeprefix(ids_to_first_parents.get(pid, ""))
            # p = p.removeprefix(":").removesuffix("-devel").removesuffix("-headers")
            p = p.removeprefix(":").removesuffix("-headers")
            return p.lower()

        products = [trim_rpm_version_suffix(p) for p in fixed | not_fixed]
        products = [p.removeprefix(ids_to_first_parents.get(p, "")) for p in products]
        products = [p.removeprefix(":") for p in products]
        # products = [renamed_product(p) for p in products]
        product_ids_to_logical_products = {
            p: clean_product_id(p) for p in fixed | not_fixed
        }
        product_ids_to_namespaces = {
            p: namespace_or_none_if_ignored(
                distro_ids_to_names.get(ids_to_first_parents.get(p, ""), "")
            )
            for p in unaffected | fixed | not_fixed
        }

        data_source = ""
        for r in c.document.references:
            if r.category == "self":
                data_source = r.url

        source_rpm_ids = c.product_tree.branches[0].source_rpm_product_ids()
        rpm_module_branches = {
            b.product.product_id
            for b in c.product_tree.product_branches()
            if b.product
            and b.product.product_identification_helper
            and b.product.product_identification_helper.purl
            and "rpmmod" in b.product.product_identification_helper.purl
        }

        for k, p in product_ids_to_logical_products.items():
            namespace = product_ids_to_namespaces.get(k)
            if k == "red_hat_enterprise_linux_6:php":
                debug_print(f"{k}: {p} in {namespace}")
            if not namespace:
                debug_print(f"for {k} ({p}) skipping b/c no namespace")
                continue
            debug_print(f"{k}: ({p}) found namespace {namespace}")
            found = False
            for srpm_id in source_rpm_ids:
                if c.product_tree.has_ancestor(k, srpm_id) or k.endswith(srpm_id):
                    found = True
                    debug_print(f"for {k} ({p}) found src rpm: {srpm_id}")
            module_branch = next((m for m in rpm_module_branches if m in k), None)
            if module_branch:
                debug_print(f"for {k} ({p}) found rpm module branch: {module_branch}")
                found = True
            else:
                debug_print(f"for {k} ({p}) no module branch in {rpm_module_branches}")
            if not found:
                debug_print(f"skipping {k} ({p}) b/c no src rpm found", file=sys.stderr)
                continue
            if "-langpack" in p:
                debug_print(f"skipping {k} ({p}) b/c langpack", file=sys.stderr)
                continue
            debug_print(f"appending {p}", file=sys.stderr)
            result.append(
                VulnerabilityRecordPair(
                    vulnerability=Vulnerability(
                        id=id,
                        package_name=p,
                        namespace=namespace,
                    ),
                    metadata=VulnerabilityMetadata(
                        id=id,
                        namespace=namespace,
                        severity=severity,
                        data_source=data_source,
                        record_source=data_source,
                        description="todo",
                    ),
                )
            )
    return set(result)


def summarize_diff(db_only, csaf_only):
    if db_only:
        print("vulns only in old data")
        for e in db_only:
            print(f"  {e}")

    if csaf_only:
        print("vulns only in new data")
        for m in csaf_only:
            print(f"  {m}")


def main():
    db_path = os.path.join(
        os.getenv("HOME", default=""),
        "Library/Caches/grype/db/5/vulnerability.db",
    )
    vuln_db = VulnerabilityDB(db_path=db_path)
    for line in sys.stdin.readlines():
        line = line.strip()
        if not line or "/" not in line:
            continue
        debug_print(f"loading from path: {line}")
        c = from_path(line)
        from_csaf_jsons = transform(c)
        up_id = line.split("/")[-1].removesuffix(".json").upper()
        debug_print(f"up id is {up_id}")
        from_db = vuln_db.get_vulnerability_records(up_id)
        csaf_only, db_only = compare_vulnerability_sets(
            set(from_csaf_jsons),
            set(from_db),
            ["id", "severity", "package_name", "namespace"],
        )
        if db_only or csaf_only:
            summarize_diff(db_only, csaf_only)
            print(f"failed for line {line}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"yay - no diff for {line}")


if __name__ == "__main__":
    main()
