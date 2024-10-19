import json
import requests
import os
import sys
import tarfile
import zstandard as zstd
from csaf_types import CSAF_JSON

LEGACY_DIR = "legacy_jsons"
LEGACY_API_TEMPLATE = "https://access.redhat.com/hydra/rest/securitydata/cve/ID.json"
CSAF_DIR = "csaf_vex_jsons"
CSAF_VEX_ARCHIVE = "csaf_vex_2024-10-06.tar.zst"


def download_file(url, path):
    response = requests.get(url, stream=True)  # Stream the content
    response.raise_for_status()  # Ensure the request was successful

    with open(path, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):  # Download in chunks
            file.write(chunk)


def get_legacy_products(up_id: str) -> set[str]:
    path = os.path.join(LEGACY_DIR, up_id)
    if not os.path.exists(path):
        url = LEGACY_API_TEMPLATE.replace("ID", up_id)
        download_file(url, path)

    with open(path, "r") as file:
        data = json.load(file)
        return set(
            [item["package"] for item in data.get("affected_release", [])]
            + [item["package_name"] for item in data.get("package_state", [])]
        )


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


def process_line(line: str):
    year, rest = line.split("/")
    id, suffix = rest.split(".")
    up_id = id.upper()
    legacy_products = get_legacy_products(up_id)
    vex_products = get_vex_logical_products(id, year)
    legacy_only = legacy_products - vex_products
    vex_only = vex_products - legacy_products
    if not legacy_only and not vex_only:
        print(f"Yay! no diff for {line}")
        return

    print(f"differences for file {line}")
    print("legacy only:")
    for p in sorted(list(legacy_only)):
        print(f"* {p}")
    print("vex only:")
    for p in sorted(list(vex_only)):
        print(f"* {p}")


for line in sys.stdin.readlines():
    if not line or "/" not in line:
        continue

    # get cve id from like 2015/cve-2015-5580.json
    try:
        process_line(line)
    except Exception as e:
        print(f"failed to process line {line}: {e.__class__}")
        raise
