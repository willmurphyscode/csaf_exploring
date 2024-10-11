import json
import sys

import csaf


def fix_up_data(data: dict) -> dict:
    return data


def summarize_csaf(model: csaf.csaf.CSAF):
    if model.document:
        print(model.document.title)
    if model.vulnerabilities:
        print("addresses: ")
        for v in model.vulnerabilities:
            print(f"- {v.cve}")


def csaf_from_path(path: str) -> csaf.csaf.CSAF:
    with open(path) as FH:
        data = json.load(FH)
        fixed_up_data = fix_up_data(data)
        return csaf.csaf.CSAF(**fixed_up_data)


def model_info(model):
    for name, info in model.model_fields.items():
        print(f" * {name}: {info}")
        print()


def main(args: list[str]):
    for p in args:
        model = csaf_from_path(p)
        summarize_csaf(model)


if __name__ == "__main__":
    main(sys.argv[1:])
