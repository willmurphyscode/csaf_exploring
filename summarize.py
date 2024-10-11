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
    if model.product_tree:
        print("displaying product tree")
        print_product_tree(model.product_tree.branches)


def print_product_tree(
    branches: csaf.product.Branches, indent: str = "", is_last: bool = True
):
    """
    Recursively prints the product tree, showing each branch's name,
    category, and product.
    """
    for index, branch in enumerate(branches.root):
        # Determine if the current branch is the last one at this level
        last_item = index == len(branches.root) - 1

        # Determine the tree symbol based on position (last or not)
        tree_connector = "└── " if last_item else "├── "

        # Print branch information
        purl = (
            f"{branch.product.product_identification_helper.purl}"
            if branch.product and branch.product.product_identification_helper
            else None
        )
        if purl:
            print(f"{indent}{tree_connector}{purl}")

        # If the branch has children, print them recursively
        if branch.branches:
            new_indent = indent + ("    " if last_item else "│   ")
            print_product_tree(branch.branches, new_indent, last_item)


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
