from random import shuffle
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, LetterCase, config
from collections import defaultdict


@dataclass_json
@dataclass
class Reference:
    category: str
    summary: str
    url: str


@dataclass_json
@dataclass
class Note:
    category: str
    text: str
    title: str


@dataclass_json
@dataclass
class ProductStatus:
    fixed: list[str] = field(default_factory=list)
    known_affected: list[str] = field(default_factory=list)
    known_not_affected: list[str] = field(default_factory=list)


@dataclass_json
@dataclass
class Threat:
    category: str
    details: str
    product_ids: list[str]


@dataclass_json
@dataclass
class CWE:
    id: str
    name: str


@dataclass_json
@dataclass
class Flag:
    label: str
    product_ids: list[str]


@dataclass_json
@dataclass
class VulnID:
    system_name: str
    text: str


@dataclass_json
@dataclass
class Remediation:
    category: str
    details: str
    product_ids: list[str]
    url: str | None = None


@dataclass_json(letter_case=LetterCase.CAMEL)
@dataclass
class CVSS_V3:
    attack_complexity: str
    attack_vector: str
    availability_impact: str
    base_score: str
    base_severity: str
    confidentiality_impact: str
    integrity_impact: str
    privileges_required: str
    scope: str
    user_interaction: str
    vector_string: str
    version: str


@dataclass_json
@dataclass
class Score:
    cvss_v3: CVSS_V3
    products: list[str]


@dataclass_json
@dataclass
class Vulnerability:
    title: str
    cve: str
    cwe: str
    discovery_date: str
    flags: list[Flag]
    ids: list[VulnID]
    notes: list[Note]
    product_status: ProductStatus
    references: list[Reference]
    release_date: str
    remediations: list[Remediation]
    threats: list[Threat]


@dataclass_json
@dataclass
class FullProductName:
    name: str
    product_id: str


@dataclass_json
@dataclass
class Relationship:
    category: str
    full_product_name: FullProductName
    product_reference: str
    relates_to_product_reference: str


@dataclass_json
@dataclass
class ProductIdentificationHelper:
    cpe: str | None = None
    purl: str | None = None


@dataclass_json
@dataclass
class Product:
    name: str
    product_id: str
    product_identification_helper: ProductIdentificationHelper | None


# Discriminator function for deserializing based on structure
# def branch_decoder(data):
#     if "product" in data:  # If 'product' field is present, it's a ProductBranch
#         return ProductBranch.from_dict(data)
#     else:  # Otherwise, it's a CategoryBranch
#         return CategoryBranch.from_dict(data)


# @dataclass_json
# @dataclass
# class ProductBranch:
#     category: str
#     name: str
#     product: Product


# @dataclass_json
# @dataclass
# class CategoryBranch:
#     category: str
#     name: str
#     branches: list["ProductBranch | CategoryBranch"] = field(
#         default_factory=list, metadata=config(decoder=branch_decoder)
#     )

#     def acculumulate_categories_recursively(self, accumulator: set[str] = set()):
#         accumulator.add(self.category)
#         for b in self.branches:
#             if isinstance(b, CategoryBranch):
#                 b.acculumulate_categories_recursively(accumulator)

#     def product_branches(self) -> list[ProductBranch]:
#         result = list()
#         for b in self.branches:
#             if isinstance(b, ProductBranch):
#                 result.append(b)
#             elif isinstance(b, CategoryBranch):
#                 result.extend(b.product_branches())
#         return result


@dataclass_json
@dataclass
class Branch:
    category: str
    name: str
    branches: list["Branch"] = field(default_factory=list)
    product: Product | None = None

    def acculumulate_categories_recursively(self, accumulator: set[str] = set()):
        accumulator.add(self.category)
        for b in self.branches:
            b.acculumulate_categories_recursively(accumulator)

    # def product_branches(self) -> list[ProductBranch]:
    def product_branches(self) -> list["Branch"]:
        result = list()
        for b in self.branches:
            if b.product:
                result.append(b)
            elif b.branches:
                result.extend(b.product_branches())
        return result

    def product_version_branches(self) -> list["Branch"]:
        result = list()
        if self.category == "product_version":
            result.append(self)
        for b in self.branches:
            result.extend(b.product_version_branches())

        return result


@dataclass_json
@dataclass
class ProductTree:
    relationships: list[Relationship]
    # branches: list[CategoryBranch | ProductBranch] = field(
    #     default_factory=list, metadata=config(decoder=branch_decoder)
    # )
    branches: list[Branch] = field(default_factory=list)
    product_id_to_parent: dict[str, str] = field(init=False)

    def __post_init__(self):
        self.product_id_to_parent = dict()
        for r in self.relationships:
            self.product_id_to_parent[r.full_product_name.product_id] = (
                r.relates_to_product_reference
            )

    def parent(self, product_id: str) -> str | None:
        return self.product_id_to_parent.get(product_id)

    def first_parent(self, product_id: str) -> str:
        here = product_id
        last_product_id = product_id
        while here:
            last_product_id = here
            here = self.parent(here)
        return last_product_id

    def second_parent(self, product_id: str) -> list[str]:
        result = []

        for child, parent in self.product_id_to_parent.items():
            # Check if the parent has a parent (i.e., a grandparent for the child)
            if parent not in self.product_id_to_parent:
                # If the parent is not in the dictionary, it has no parent (grandparent of child doesn't exist)
                result.append(child)

        return result

    def distinct_branch_categories(self) -> set[str]:
        result = set()
        for b in self.branches:
            b.acculumulate_categories_recursively(result)

        return result

    def longest_path(self) -> tuple[int, list[str]]:
        # Reverse the graph: store children for each parent
        tree = self.product_id_to_parent
        reverse_tree = defaultdict(list)
        for child, parent in tree.items():
            reverse_tree[parent].append(child)

        # Find root nodes (nodes that are never a child)
        all_nodes = set(tree.keys()) | set(tree.values())  # Get all unique nodes
        root_nodes = all_nodes - set(
            tree.keys()
        )  # Roots are nodes that are only parents, not children

        # Function to perform DFS and return both the length of the longest path and the path itself
        def dfs(node):
            if node not in reverse_tree:
                return 1, [
                    node
                ]  # This is a leaf node, path length is 1, path is just this node
            # Recursively find the longest path in children
            max_length = 0
            longest_subpath = []
            for child in reverse_tree[node]:
                child_length, child_path = dfs(child)
                if child_length > max_length:
                    max_length = child_length
                    longest_subpath = child_path
            # Return the length and the path from the current node
            return 1 + max_length, [node] + longest_subpath

        # Compute the longest path from each root
        max_length = 0
        longest_path_list = []
        roots = list(root_nodes)
        shuffle(roots)

        for root in roots:
            path_length, path = dfs(root)
            if path_length > max_length:
                max_length = path_length
                longest_path_list = path

        return max_length, longest_path_list

    def logical_products(self) -> list[Product]:
        vendor_branch = self.branches[0]
        top_level_products = [
            b.product
            for b in vendor_branch.branches
            if b.category == "product_version" and b.product
        ]
        noarch_branches = [
            b
            for b in self.branches[0].branches
            if b.category == "architecture" and b.name == "noarch"
        ]
        noarch_products = [
            b.product
            for noarch_branch in noarch_branches
            for b in noarch_branch.branches
            if b.product
            and b.product.product_identification_helper
            and b.product.product_identification_helper.purl
            and "rpmmod" in b.product.product_identification_helper.purl
        ]
        return top_level_products + noarch_products

    def has_ancestor(self, product_id: str, maybe_ancestor_id: str) -> bool:
        parent = self.parent(product_id)
        while parent:
            if parent == maybe_ancestor_id:
                return True
            parent = self.parent(parent)
        return False

    # def product_branches(self) -> list[ProductBranch]:
    #     result = list()
    #     for b in self.branches:
    #         if isinstance(b, ProductBranch):
    #             result.append(b)
    #         elif isinstance(b, CategoryBranch):
    #             result.extend(b.product_branches())
    #         else:
    #             raise ValueError(
    #                 f"wanted CategoryBranch or ProductBranch, got {b.__class__}"
    #             )

    #     return result

    def product_branches(self) -> list[Branch]:
        result = list()
        for b in self.branches:
            if b.product:
                result.append(b)
            else:
                result.extend(b.product_branches())
        return result


@dataclass_json
@dataclass
class AggregateSeverity:
    namespace: str
    text: str


@dataclass_json
@dataclass
class TLP:
    label: str
    url: str


@dataclass_json
@dataclass
class Distribution:
    text: str
    tlp: TLP


@dataclass_json
@dataclass
class Publisher:
    category: str
    contact_details: str
    issuing_authority: str
    name: str
    namespace: str


@dataclass_json
@dataclass
class GeneratorEngine:
    name: str
    version: str


@dataclass_json
@dataclass
class Generator:
    date: str
    engine: GeneratorEngine


@dataclass_json
@dataclass
class RevisionEntry:
    date: str
    number: str  # yes, really
    summary: str


@dataclass_json
@dataclass
class Tracking:
    current_release_date: str
    generator: Generator
    id: str
    initial_release_date: str
    revision_history: list[RevisionEntry]
    status: str
    version: str


@dataclass_json
@dataclass
class Document:
    aggregate_severity: str
    category: str
    csaf_version: str
    distribution: Distribution
    lang: str
    notes: list[Note]
    publisher: Publisher
    references: list[Reference]
    title: str
    tracking: Tracking


# vulnerable package is a human readable
# statement of what a CSAF vex means
@dataclass_json
@dataclass
class VulnerableProduct:
    cve: str
    package_name: str
    purl: str
    namespace: str
    fixed_version: str | None

    def string(self) -> str:
        fixed_in = ""
        if self.fixed_version:
            fixed_in = f"- fixed in {self.fixed_version}"

        return f"{self.package_name} - {self.cve}{fixed_in} ({self.purl})"


@dataclass_json
@dataclass
class CSAF_JSON:
    document: Document
    product_tree: ProductTree
    vulnerabilities: list[Vulnerability]

    def has_fix(
        self, rhel_version: int, product_id: str, cve_id: str | None = None
    ) -> bool:
        if not cve_id:
            cve_id = self.vulnerabilities[0].cve

        # get best red hat version:
        vendor_branch = self.product_tree.branches[0]
        rhel_product_id = None
        for b in vendor_branch.branches:
            if (
                b.category == "product_family"
                and f"Red Hat Enterprise Linux {rhel_version}" in b.name
            ):
                if b.branches and b.branches[0].product:
                    rhel_product_id = b.branches[0].product.product_id

        if not rhel_product_id:
            raise ValueError(f"could not find product id for {rhel_version}")

        vuln = next((v for v in self.vulnerabilities if v.cve == cve_id), None)
        if not vuln:
            raise ValueError(f"no vulnerability for {cve_id}")

        for fixed in vuln.product_status.fixed:
            if self.product_tree.has_ancestor(
                fixed, product_id
            ) and self.product_tree.has_ancestor(fixed, rhel_product_id):
                return True

        return False

    # def resolve_package_id(self, product_id: str) -> Product:
    #     return Product()

    # def vp(self, package_id: str, cve: str, fixed: bool) -> VulnerableProduct:
    #     return VulnerableProduct(cve=cve, package_name=self.resolve_package_id())

    # def vulnerability_rows(self) -> list[VulnerableProduct]:
    #     result = []
    #     for v in self.vulnerabilities:
    #         for ka in v.product_status.known_affected:
    #             result.append(self.vp(ka, None))

    #     return result


# Function to recursively instantiate TreeNode from a dictionary
def from_dict(cls, data):
    if hasattr(cls, "__dataclass_fields__"):
        fieldtypes = {f.name: f.type for f in cls.__dataclass_fields__.values()}
        try:
            return cls(
                **{
                    f: from_dict(fieldtypes[f], data[f]) if f in data else None
                    for f in data
                }
            )
        except Exception as e:
            print(f"error making {cls}: {e.__class__}, couldn't use:")
            raise e
    elif isinstance(data, list):
        return [from_dict(cls.__args__[0], item) for item in data]
    else:
        return data


if __name__ == "__main__":
    import sys
    import json

    path = sys.argv[1]
    with open(path) as fh:
        c = CSAF_JSON.from_dict(json.load(fh))
        print()
        print(f"loaded csaf file: {c.document.title}")
        print()
        first_parents = set()
        second_parents = set()
        for fixed in c.vulnerabilities[0].product_status.fixed:
            fp = c.product_tree.first_parent(fixed)
            first_parents.add(fp)
            sp = c.product_tree.second_parent(fixed)

        length, longest_path = c.product_tree.longest_path()
        print(f"longest path has length {length}")
        indent = ""
        for p in longest_path:
            print(f"{indent}{p}")
            indent = f"{indent}  "

        print("product ids with no ancestors: ")
        for fp in first_parents:
            print(f" * {fp}")

        print()
        print("product ids with exactly 1 ancestor")
        for sp in second_parents:
            print(f" * {sp}")

        print()
        print("categories:")
        for cat in c.product_tree.distinct_branch_categories():
            print(f"* {cat}")

        # for b in c.product_tree.product_branches():
        #     print(b.product.product_identification_helper)

        # for b in c.product_tree.branches:
        #     for b2 in b.branches:
        #         if b2.category != "architecture":
        #             print(b2)
        # arch_indepented_product_ids = set()
        # for b in c.product_tree.branches:
        #     if b.category == "product_version":
        #         print(b.product.product_id)
        #         arch_indepented_product_ids.add(b.product.product_id)
        #     for b2 in b.branches:
        #         if b2.category != "architecture":
        #             for b3 in b2.product_version_branches():
        #                 print(b3.product.product_id)
        #                 arch_indepented_product_ids.add(b3.product.product_id)
        print()
        print("trying for real products")
        for p in sorted(c.product_tree.logical_products(), key=lambda x: x.name):
            print(f"* {p.product_id}")

        # for rhel_version in [7, 8, 9]:
        for rhel_version in [8, 9]:
            for p in c.product_tree.logical_products():
                has_fix = c.has_fix(rhel_version, p.product_id)
                print(f"on RHEL{rhel_version}, {p.product_id} has_fix -> {has_fix}")
