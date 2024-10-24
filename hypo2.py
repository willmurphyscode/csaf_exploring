import json
from typing import Callable
import requests
import os
import re
import sys
import tarfile
import zstandard as zstd
from csaf_types import CSAF_JSON

import jellyfish


LEGACY_DIR = "legacy_jsons"
LEGACY_API_TEMPLATE = "https://access.redhat.com/hydra/rest/securitydata/cve/ID.json"
CSAF_DIR = "csaf_vex_jsons"
CSAF_VEX_ARCHIVE = "csaf_vex_2024-10-06.tar.zst"


def normalize_java_package_name(package_name: str) -> str:
    # Regex to remove the version details after the second hyphen or after a colon
    pattern = r"^([^:]+)-\d+(:.*)?$"

    # Apply the regex and return the trimmed name
    match = re.match(pattern, package_name)
    if match:
        return match.group(1)  # Return the core package name
    return package_name


def normalize_kernel_name(package_name: str) -> str:
    # Regex to match and reduce kernel package names to their base
    pattern = r"^kernel(?:-rt)?(?:[.:].*)?$"

    # If the name matches the pattern, return just "kernel"
    if re.match(pattern, package_name):
        return "kernel"
    return package_name


def remove_rpm_version(package_string: str) -> str:
    # Regex pattern to match the version suffix, e.g. '-0:1.36.2.4-1.el6op'
    pattern = r"-\d+:[\d\.]+-\d+\.\w+"
    # Substitute the matching pattern with an empty string
    return re.sub(pattern, "", package_string)


def normalize_package_names_with_versions(package_name: str) -> str:
    """
    Normalizes package names to ensure consistent formatting between legacy and vex sets.

    This function assumes that vex uses colons `:` instead of dashes `-` in some places, and dots `.`
    might be used in versioning. It will reformat the package name to follow the vex format.
    """
    if "java" in package_name:
        package_name = normalize_java_package_name(package_name)
    package_name = remove_rpm_version(package_name)
    package_name = normalize_kernel_name(package_name)
    # Replace the first `-` (often between product and version) with a colon `:`
    # convert foo:rhel-8050020211001230723.b4937e53 to foo:rhel:8050020211001230723:b4937e53
    pattern = r"(rhel-)(\d{19})\.([a-f0-9]{8})$"

    # Check if the string matches the pattern at the end
    return re.sub(pattern, r"rhel:\2:\3", package_name)


def download_file(url, path):
    response = requests.get(url, stream=True)  # Stream the content
    response.raise_for_status()  # Ensure the request was successful

    with open(path, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):  # Download in chunks
            file.write(chunk)


def get_legacy_products(up_id: str) -> set[str]:
    not_json_path = os.path.join(LEGACY_DIR, up_id)
    json_path = os.path.join(LEGACY_DIR, f"{up_id}.json")
    if os.path.exists(not_json_path) and not os.path.exists(json_path):
        os.rename(not_json_path, json_path)

    if not os.path.exists(json_path):
        url = LEGACY_API_TEMPLATE.replace("ID", up_id)
        download_file(url, json_path)

    with open(json_path, "r") as file:
        data = json.load(file)
        results = set(
            [item.get("package") for item in data.get("affected_release", [])]
            + [item.get("package_name") for item in data.get("package_state", [])]
        )
        return {
            normalize_package_names_with_versions(item)
            for item in results
            if item is not None
        }


def unzip_from_vex_archive(id: str, year: str):
    with open(CSAF_VEX_ARCHIVE, "rb") as compressed_file:
        # Initialize the decompressor
        dctx = zstd.ZstdDecompressor()

        # Decompress the .tar.zst into a stream
        with dctx.stream_reader(compressed_file) as decompressed_stream:
            # Wrap the decompressed stream into a file-like object
            with tarfile.open(fileobj=decompressed_stream, mode="r|") as tar:
                for member in tar:
                    if id in member.name:
                        tar.extract(
                            member,
                            path=CSAF_DIR,
                        )


def get_vex_logical_products(id: str, year: str) -> set[str]:
    path = os.path.join(CSAF_DIR, year, f"{id}.json")
    if not os.path.exists(path):
        unzip_from_vex_archive(id, year)

    with open(path, "r") as file:
        data = json.load(file)
        c = CSAF_JSON.from_dict(data)
        return set([p.product_id for p in c.product_tree.logical_products()])


# Levenshtein distance as a more flexible alternative
def levenshtein_distance(str1: str, str2: str) -> float:
    if len(str1) < len(str2):
        return levenshtein_distance(str2, str1)
    if len(str2) == 0:
        return len(str1)
    previous_row = range(len(str2) + 1)
    for i, c1 in enumerate(str1):
        current_row = [i + 1]
        for j, c2 in enumerate(str2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# Jaro-Winkler distance function
def jaro_winkler_distance(str1: str, str2: str) -> float:
    return 1 - jellyfish.jaro_winkler_similarity(str1, str2)


# Function to find the closest match
def find_closest_match(
    target: str, candidates: list[str], distance_func: Callable[[str, str], float]
) -> str:
    closest_match = None
    closest_distance = float("inf")
    for candidate in candidates:
        distance = distance_func(target, candidate)
        if distance < closest_distance:
            closest_distance = distance
            closest_match = candidate
    return closest_match


def process_line(
    line: str, similarity_func: Callable[[str, str], float] = jaro_winkler_distance
):
    year, rest = line.split("/")
    if int(year) <= 2003:
        print("skipping " + line, file=sys.stderr)
        return

    id, suffix = rest.split(".")
    up_id = id.upper()
    legacy_products = get_legacy_products(up_id)
    vex_products = get_vex_logical_products(id, year)
    legacy_only = legacy_products - vex_products
    vex_only = vex_products - legacy_products

    if not legacy_only and not vex_only:
        print(f"Yay! no diff for {line}")
        return

    print(f"Differences for file {line}")

    if legacy_only:
        print("Legacy only:")
        for legacy_product in sorted(list(legacy_only)):
            closest_vex_product = find_closest_match(
                legacy_product, list(vex_products), similarity_func
            )
            print(f"* {legacy_product} (closest in vex: {closest_vex_product})")

    if vex_only:
        print("Vex only:")
        for vex_product in sorted(list(vex_only)):
            closest_legacy_product = find_closest_match(
                vex_product, list(legacy_products), similarity_func
            )
            print(f"* {vex_product} (closest in legacy: {closest_legacy_product})")


for line in sys.stdin.readlines():
    if not line or "/" not in line:
        continue

    # get cve id from like 2015/cve-2015-5580.json
    try:
        process_line(line)
    except Exception as e:
        print(f"failed to process line {line}: {e.__class__}")
        raise
