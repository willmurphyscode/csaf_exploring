import json
import logging
import sys

logging.basicConfig(
    stream=sys.stdout,  # Output to stdout
    level=logging.INFO,  # Set the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s:%(levelname)s: %(message)s",  # Define the log format
    datefmt="%Y-%m-%d %H:%M:%S",  # Define the date format
)


def find_purl_by_product_id(product_tree, product_id):
    """
    Recursively searches the product_tree for the product_id and returns the corresponding PURL.
    """
    if isinstance(product_tree, dict):
        # Check if the current node has a product_id and a PURL
        if "product_id" in product_tree and product_tree["product_id"] == product_id:
            return product_tree.get("product_identification_helper", {}).get("purl")

        # Recurse into branches if they exist
        for key, value in product_tree.items():
            result = find_purl_by_product_id(value, product_id)
            if result:
                return result
    elif isinstance(product_tree, list):
        for item in product_tree:
            result = find_purl_by_product_id(item, product_id)
            if result:
                return result
    return None


def recursive_check_branches(branches, product_reference):
    if not product_reference or not branches:
        return None
    for b in branches:
        # is b the branch with the stuff?
        product = b.get("product", {})
        product_id = product.get("product_id", None)
        if product_id == product_reference:
            purl = product.get("product_identification_helper", {}).get("purl", None)
            if purl:
                return purl
        sub_branches = b.get("branches", [])
        if sub_branches:
            result = recursive_check_branches(sub_branches, product_reference)
            if result:
                return result


def find_purl_good(data, product_id):
    relationships = data.get("product_tree", {}).get("relationships", [])
    logging.debug(f"for {product_id} found {len(relationships)} relationships")
    product_reference = None
    for r in relationships:
        this_id = r.get("full_product_name", {}).get("product_id", None)
        if this_id == product_id:
            product_reference = r.get("product_reference", None)
            break

    if not product_reference:
        return None

    branches = data.get("product_tree", {}).get("branches", [])
    purl = recursive_check_branches(branches, product_reference)
    return purl


def get_purls_for_vulnerabilities(data):
    vulnerabilities = data.get("vulnerabilities", [])
    # product_tree = data.get("product_tree", {})

    for vulnerability in vulnerabilities:
        vid = vulnerability.get("cve", "UNLABELED")
        logging.debug(f"found vulnerability {vid}")
        fixed_products = vulnerability.get("product_status", {}).get("fixed", [])
        logging.debug(f"for {vid} found {len(fixed_products)} fixed product ids")
        purls = []

        for product_id in fixed_products:
            # Find the corresponding PURL for the product_id in the product_tree
            purl = find_purl_good(data, product_id)
            if purl:
                purls.append(purl)

        print(f"Vulnerability {vulnerability.get('cve', 'Unknown CVE')}:")
        if purls:
            for purl in purls:
                print(f"  Fixed by: {purl}")
        else:
            print("  No PURLs found.")
        print()


# Load the JSON document
with open(sys.argv[1], "r") as f:
    data = json.load(f)

# Get PURLs for each vulnerability
get_purls_for_vulnerabilities(data)
