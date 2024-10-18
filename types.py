from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, LetterCase


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
    fixed: list[str]
    known_affected: list[str]
    known_not_affected: list[str]


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
    cpe: str | None
    purl: str | None


@dataclass_json
@dataclass
class Product:
    name: str
    product_id: str
    product_identification_helper: ProductIdentificationHelper


@dataclass_json
@dataclass
class ProductBranch:
    category: str
    name: str
    product: Product


@dataclass_json
@dataclass
class CategoryBranch:
    category: str
    name: str
    branches: list["ProductBranch | CategoryBranch"] = field(default_factory=list)


@dataclass_json
@dataclass
class ProductTree:
    relationships: list[Relationship]
    branches: list[CategoryBranch | ProductBranch] = field(default_factory=list)

    def parent(self, product_id: str) -> str | None:
        rels = [
            r
            for r in self.relationships
            if r.full_product_name.product_id == product_id
        ]
        if rels:
            return rels[0].relates_to_product_reference
        return None

    def first_parent(self, product_id: str) -> str:
        here = product_id
        last_product_id = product_id
        while here:
            last_product_id = here
            here = self.parent(here)
        return last_product_id


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
        first_parents = set()
        for fixed in c.vulnerabilities[0].product_status.fixed:
            fp = c.product_tree.first_parent(fixed)
            first_parents.add(fp)
        for fp in first_parents:
            print(fp)
