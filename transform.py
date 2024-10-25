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


def namespace_or_none_if_ignored(distro_like_name: str) -> str | None:
    result = None
    match = re.search(APP_STREAM_RE, distro_like_name)
    base_os_match = re.search(BASE_OS_RE, distro_like_name)
    if match:
        version = match.group(1)
        result = RHEL_VERSIONS_TO_NAMESPACES.get(version)
    elif base_os_match:
        version = base_os_match.group(1)
        result = RHEL_VERSIONS_TO_NAMESPACES.get(version)
    elif " " in distro_like_name:
        distro, version = distro_like_name.rsplit(" ", 1)
        if distro == "Red Hat Enterprise Linux":
            result = RHEL_VERSIONS_TO_NAMESPACES.get(version)

    # print(f"getting ns for {distro_like_name}: {result}", file=sys.stderr)
    return result


def get_severity(aggregate_severity_text: str) -> str:
    if aggregate_severity_text not in SEVERITY_MAP:
        print(f"missing {aggregate_severity_text}", file=sys.stderr)
    return SEVERITY_MAP.get(aggregate_severity_text, "TODO")


def trim_rpm_version_suffix(product_id: str) -> str:
    version_suffix = r"-(0|1):.*$"
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
        distro_ids_to_names = {
            b.product.product_id: b.product.name
            for b in c.product_tree.branches[0].product_name_branches()
            if b.product
        }

        # TODO: make this dict[str,str] where keys are original ids and values are cleaned up ids
        def clean_product_id(pid: str) -> str:
            p = trim_rpm_version_suffix(pid)
            p = p.removeprefix(ids_to_first_parents.get(pid, ""))
            p = p.removeprefix(":").removesuffix("-devel").removesuffix("-headers")
            return p

        products = [trim_rpm_version_suffix(p) for p in fixed | not_fixed]
        products = [p.removeprefix(ids_to_first_parents.get(p, "")) for p in products]
        products = [p.removeprefix(":") for p in products]
        # products = [renamed_product(p) for p in products]
        product_ids_to_logical_products = {
            p: clean_product_id(p) for p in fixed | not_fixed
        }
        # TODO: collapses a namespace
        # use product_ids_to_namespaces
        logical_products_to_namespaces = {
            product_ids_to_logical_products.get(p): namespace_or_none_if_ignored(
                distro_ids_to_names.get(ids_to_first_parents.get(p, ""), "")
            )
            for p in product_ids_to_logical_products
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

        for k, p in product_ids_to_logical_products.items():
            namespace = product_ids_to_namespaces.get(k)
            if k == "red_hat_enterprise_linux_6:php":
                print(f"{k}: {p} in {namespace}")
            if not namespace:
                # print(f"for {k} ({p}) skipping b/c no namespace")
                continue
            found = False
            for srpm_id in source_rpm_ids:
                if k.endswith(srpm_id):
                    found = True
            if not found:
                print(f"skipping {k} ({p}) b/c no src rpm found", file=sys.stderr)
                continue
            if "-langpack" in p:
                print(f"skipping {k} ({p}) b/c langpack", file=sys.stderr)
                continue
            # print(f"appending {p}", file=sys.stderr)
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
        print(f"loading from path: {line}")
        c = from_path(line)
        from_csaf_jsons = transform(c)
        up_id = line.split("/")[-1].removesuffix(".json").upper()
        print(f"up id is {up_id}")
        from_db = vuln_db.get_vulnerability_records(up_id)
        csaf_only, db_only = compare_vulnerability_sets(
            set(from_csaf_jsons),
            set(from_db),
            ["id", "severity", "package_name", "namespace"],
        )
        if db_only or csaf_only:
            summarize_diff(db_only, csaf_only)
        else:
            print(f"yay - no diff for {line}")


if __name__ == "__main__":
    main()
