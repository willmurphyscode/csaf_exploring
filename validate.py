import json
import os
import tarfile
import zstandard as zstd
import csaf

# from pydantic import ValidationError
import logging


def fixup_json_document(json_content):
    fixup_keys = {"availabilityImpact", "confidentialityImpact", "integrityImpact"}
    fixup_map = {
        "PARTIAL": "LOW",
    }
    doc = json.loads(json_content)
    for vulnerability in doc["vulnerabilities"]:
        for score in vulnerability["scores"]:
            for key in score:
                if key in fixup_keys and score[key] in fixup_map:
                    score[key] = fixup_map[score[key]]
    return doc


def log_is_valid_json_file(path, json_content):
    try:
        # Attempt to parse the JSON content
        doc = fixup_json_document(json_content)
        exit_code, message = csaf.csaf.verify_document(doc)
        if exit_code != 0:
            log.warning(f"INVALID: {path} ({message})")
    except Exception as e:
        logging.error(f"COULD NOT VALIDATE: {path} ({e.__class__})")


def instantiate_model(path, json_content):
    try:
        # Attempt to parse the JSON content
        doc = fixup_json_document(json_content)
        model = csaf.csaf.CSAF(**doc)
    except Exception as e:
        logging.error(f"COULD NOT INSTANTIATE: {path} ({e.__class__})")


def process_json_file(path, json_content):
    log_is_valid_json_file(path, json_content)
    instantiate_model(path, json_content)


def process_zst_file(zst_file_path):
    # Open the zst file for streaming decompression
    with open(zst_file_path, "rb") as zst_file:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(zst_file) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    if member.isfile() and member.name.endswith(".json"):
                        try:
                            # Extract JSON content from the tar archive
                            json_file = tar.extractfile(member)
                            if json_file:
                                json_content = json_file.read().decode("utf-8")
                                # Process the JSON file
                                process_json_file(member.name, json_content)
                        except Exception as e:
                            logging.error(
                                f"FAILED to read or process: {member.name} ({e})"
                            )


def main():
    # Configure logging
    logging.basicConfig(
        filename="csaf_validation.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )
    # Process both zst files in the current directory
    zst_files = ["csaf_advisories_2024-10-06.tar.zst", "csaf_vex_2024-10-06.tar.zst"]

    for zst_file in zst_files:
        if os.path.exists(zst_file):
            process_zst_file(zst_file)


if __name__ == "__main__":
    main()
