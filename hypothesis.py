import json
import sys


# given the vunnel full CVE JSON
# import the vunnel code, call parse affected release
# get the filtered affected releases for this CVE


# other half: go to new CSAF data, and filter source RPMs
# how do we filter out source RPMs?


# we should see that the same filtering works
# results in source of the same data.

# in other works, our filter is:
# for all CVEs, for all affected packages:
# is the affected package part of a lineage we care about? like RHEL8
# and not JBoss for IBM Turntables
# is the affect package a _source_ RPM
# if yes to both keep
# CSAF side
# to_keep = []
# for cve in cves:
#   for prodcut in cve.all_the_products
#       if product.is_from_rhel and product.is_source_rpm
#           to_keep.append(product)

example = """
            "branches": [
              {
                "category": "product_version",
                "name": "httpd-0:2.4.37-51.module+el8.7.0+16050+02173b8e.src",
                "product": {
                  "name": "httpd-0:2.4.37-51.module+el8.7.0+16050+02173b8e.src",
                  "product_id": "httpd-0:2.4.37-51.module+el8.7.0+16050+02173b8e.src",
                  "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/httpd@2.4.37-51.module%2Bel8.7.0%2B16050%2B02173b8e?arch=src"
                  }
                }
              },


"""

## yay we can look for this:
##             "category": "architecture",
##             "name": "src"

## some deduping based on default component of
## for example mod_md is a default_component_of httpd
## and so doesn't appear to be a separate vulnerability


# Vunnel side:
# basically just run vunnel normally

# so then vunnel and this code can get roughly the
# same set of packages, or else we know we're wrong.


def dict_from_json_at_path(path: str) -> dict | list:
    with open(path) as f:
        return json.load(f)


def build_tree(relationships):
    # Dictionary to hold child-parent mappings
    tree = {}

    # Helper function to insert a child under the correct parent
    def insert_node(parent_id, child_id):
        # If the parent doesn't exist, create it
        if parent_id not in tree:
            tree[parent_id] = {}
        # Insert the child under the parent
        tree[parent_id][child_id] = tree.get(child_id, {})

    # Build the tree from the relationships
    for relationship in relationships:
        if relationship["category"] != "default_component_of":
            continue
        child_id = relationship["full_product_name"]["product_id"]
        parent_id = relationship["relates_to_product_reference"]
        insert_node(parent_id, child_id)

    # Find the root (node without any parent in the relationships)
    all_children = {
        rel.get("full_product_name", {}).get("product_id", None)
        for rel in relationships
        if rel.get("category") == "default_component_of"
    }
    all_parents = {
        rel["relates_to_product_reference"]
        for rel in relationships
        if rel.get("category") == "default_component_of"
    }
    root_nodes = all_parents - all_children  # root nodes are parents with no parent

    # Handle multiple root nodes if necessary
    result_tree = {root: tree[root] for root in root_nodes} if root_nodes else tree
    return result_tree


def print_tree(tree, indent=""):
    """
    Recursively prints the tree in a nicely formatted way.
    """
    for key, value in tree.items():
        print(f"{indent}{key}")
        if isinstance(value, dict):
            print_tree(value, indent + "    ")


def run(path: str):
    doc = dict_from_json_at_path(path)
    vulnerability = doc["vulnerabilities"][0]
    cve_id = vulnerability["cve"]
    product_status = vulnerability["product_status"]
    affected_product_codes = set()
    for name, products in product_status.items():
        if name == "known_not_affected":
            continue
        for pid in products:
            affected_product_codes.add(pid)
    tree = build_tree(doc["product_tree"]["relationships"])
    print_tree(tree)


if __name__ == "__main__":
    run(sys.argv[1])
