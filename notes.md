## Parsing notes

I think we need to parse cve-foo.json and rhsa-foo.json to get the fixes:

There's a cve-foo per (relevant) cve.
There's an rh[bes]a-foo per patch issues

Unless they're redundant.

Maybe we can get away with the cve-foos.json? I think maybe CVE-foo.json has
the set of all PURLs that fix CVE-foo, and RHSA-foo.json has the set of all
CVEs fixed by patchset RHSA-foo. If that's true, getting a good picture of
the data might only require a few of the 

## A hypothesis

There are lots of `:` in the product IDs.

For example, if you look at the JSON for `cve-2024-9407`, you can see
that `red_hat_enterprise_linux_8:container-tools:rhel8/buildah` is a product id

I hypothesize that in relationships we'll have:
* `red_hat_enterprise_linux_8:container-tools:rhel8/buildah` is a part of `red_hat_enterprise_linux_8:container-tools`
* `red_hat_enterprise_linux_8:container-tools` is a part of `red_hat_enterprise_linux_8`
* which is the root of its little sub tree.

Quick! To the bat-interpreter!
    
## Questions about products

So there is product information in several places in these documents,
and I want to try to understand all the places:

``` sh
❯ cat rhsa-*.json cve-*.json | jq -c 'paths | select(.[0:5] | any(type == "string" and contains("product"))) | .[0:5]' \
  | awk '{gsub(/[0-9]+/, "*")}1' \
  | sort -r \
  | uniq

["vulnerabilities",*,"threats",*,"product_ids"]
["vulnerabilities",*,"scores",*,"products"]
["vulnerabilities",*,"remediations",*,"product_ids"]
["vulnerabilities",*,"product_status"]
["vulnerabilities",*,"product_status","known_not_affected"]
["vulnerabilities",*,"product_status","known_not_affected",*]
["vulnerabilities",*,"product_status","known_affected"]
["vulnerabilities",*,"product_status","known_affected",*]
["vulnerabilities",*,"product_status","fixed"]
["vulnerabilities",*,"product_status","fixed",*]
["vulnerabilities",*,"flags",*,"product_ids"]
["product_tree"]
["product_tree","relationships"]
["product_tree","relationships",*]
["product_tree","relationships",*,"relates_to_product_reference"]
["product_tree","relationships",*,"product_reference"]
["product_tree","relationships",*,"full_product_name"]
["product_tree","relationships",*,"full_product_name","product_id"]
["product_tree","relationships",*,"full_product_name","name"]
["product_tree","relationships",*,"category"]
["product_tree","branches"]
["product_tree","branches",*]
["product_tree","branches",*,"name"]
["product_tree","branches",*,"category"]
["product_tree","branches",*,"branches"]
["product_tree","branches",*,"branches",*]
```

Let's try to enumerate what all these are:

In vulnerabilities, there are a bunch of places product IDs appear:

1. `vulnerabilities.*.threats.*.product_ids` - this is a list of product IDs by
   threat category. For example, it might say `category: impact; details:
   Moderate` meaning the product IDs in the list face a threat of moderate
   impact.
2. `vulnerabilities.*.scores.*.product_ids` -  these are per product cvss v2 or
   v3 scores
3. `vulnerabilities.*.remediations.*.product_ids` - this includes a bunch of
   different things, for example: on cve-2024-9407, it lists some packages as
   having "workarounds" but then the details are just an apology saying
   mitigation is not available. Then there are some "no_fix_planned"
   remediations. Then there are some "none_available" remediations. This is
   also where you find N `vendor_fix` remediation entries, which we want to
   capture.
4. `vulnerabilities.*.product_status.*.<status>` where status is "fixed" or
   "known_affected" or "known_not_affected". (there are also "first_affected"
   and some others, but Red Hat CSAF doesn't seem to use all of them.)
5. `vulnerabilities.*.flags.*.<label>` where you can write down product
   information from the following enum variables: component_not_present,
   inline_mitigations_already_exist,
   vulnerable_code_cannot_be_controlled_by_adversary,
   vulnerable_code_not_in_execute_path, vulnerable_code_not_present. Red Hat
   seems to use `component_not_present`, `vulnerable_code_not_present`

In sum, product IDs appear in 5 places in the CSAF VEX JSON: threats, scores,
remediations, product_status, and flags:

## Interpreting product related fields

1. _threats_ tell us impact, e.g. "important" and "exploit_status", which
   sometimes has a link to KEV like
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog and a date.

We only see two categories:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.threats != null) | .threats[] | .category' | sort | uniq -c | sort -nr
66029 impact
 954 exploit_status
```

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.threats != null) | .threats[] | .details' | sort | uniq -c | sort -nr
33518 Moderate
17845 Important
9490 Low
5176 Critical
 954 CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

When there's a KEV link it seems to be accompanied by a date.

2. _scores_ tell us CVSS scores for different product IDs.
``` json 
      "scores": [
        {
          "cvss_v3": {
            ... snip ...
          },
          "products": [
            ... snip ...
          ]
        }
      ]
```

There is always exactly 1 score in observed data so far, though the spec is
silent on this point:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.scores != null) | .scores | length' | sort | uniq -c | sort -nr
61642 1
```

This means that the cvss_v3 score is applicable to all the products in
`products`

3. _remediations_ tell us what remedy is available. There are only 2 used
in the Red Hat dataset:

``` sh

❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.threats != null) | .remediations[] | .category' | sort | uniq -c | sort -nr
66029 vendor_fix
12843 workaround
```
4. *product_status* gives us information about the status. It has sub objects
   whose key tells us about the product status. Red Hat only uses two: fixed,
   and known_not_affected:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.product_status != null) | .product_status | keys' | sort | uniq -c | sort -n
6593 ["fixed","known_not_affected"]
59612 ["fixed"]
```

5. *flags* gives us additional information, such as for which product IDs the vulnerable
code is not present. We have 2 labels in use here:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.flags != null) | .flags[] | .label' | sort | uniq -c | sort -n
 179 component_not_present
6414 vulnerable_code_not_present
```

## Algorithm

What I really want out of all this research is a procedure for getting to a
clean, accurate, simple view of the vulnerability and it's affected packages
based on digging through the CSAF_VEX JSONs and maybe (though I hope I only
need the vex) the CSAF Advisory JSONs if necessary.

I need to go from this giant JSON to a human-readable package name.

For example, cve-2022-23943 is about a vulnerability in httpd2. But there
are 349 unique product IDs listed in the remediations section:

``` sh
❯ cat cve-2022-23943.json| jq '.vulnerabilities[0].remediations[] | .product_ids[]' | sort |uniq | wc -l
     349
```

This process breaks down into 2 pieces:

1. scan through the arrays of product IDs (the 5 kinds above) to identify
   groups of products with given conditions
2. De-reference and de-dupe the product IDs by looking a `.product_tree` in the
   doc

I think the biggest issue I'm having is understanding the product tree node of
the doc. There are _two_ different product trees.

`.product_tree.branches` is an array of sub-trees (objects in the array might
have `branches` as a key, recursively), and describes a tree of products.

`product_tree.relationships` is _also_ a forest, except that it is expressed as
a flat list of relationships, e.g. `product A is a default component of product
B`

What I'm trying to understand is, why are there two trees of product relationships?

The answer, I guess, is that the relate the products on different axes.

The outer most `product_tree.branches` always has length 1:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches | length' | sort | uniq -c
17410 1

❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches[0].category' | sort | uniq -c
17410 vendor

csaf on  main [!?] is 📦 v0.1.0 via 🐍 v3.11.8 (csaf) took 43s 
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches[0].name' | sort | uniq -c
17410 Red Hat
```

So everything under `branches[0]` is just `vendor: Red Hat`.

But `.product_tree.brances[0].branches` has very variable length, ranging from
1018 to 3.

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches[0].branches[] | .category' | sort | uniq -c | sort
 -n 
17410 product_family
18450 product_version
73536 architecture
```

So this is telling me that there are 3 substrees under the "Vendor: Red Hat"
tree.

Lets see what product families exist:

``` sh
$ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches[0].branches[] | select(.category == "product_famil
y") | .name ' | sort | uniq -c | sort -n
... snip ... 
 182 Red Hat JBoss Web Server
 200 Red Hat Linux
 314 Red Hat Virtualization
 342 Red Hat Software Collections
 542 Red Hat Enterprise Linux Supplementary
 604 Red Hat JBoss Enterprise Application Platform
 733 Red Hat OpenStack Platform
1073 Red Hat OpenShift Enterprise
10426 Red Hat Enterprise Linux
```

There are a few architectures:

``` sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.branches != null) | .product_tree.branches[0].branches[] | select(.category == "architecture"
) | .name ' | sort | uniq -c | sort -n
  24 ia32e
  26 ppc64pseries
  30 athlon
  55 i586
  81 ppc64iseries
 521 arm64
1146 amd64
1844 ia64
2383 i386
2587 s390
2875 ppc
3525 ppc64
4399 aarch64
4585 i686
6452 noarch
7618 ppc64le
9116 s390x
12455 x86_64
13814 src
```

Product versions are too numerous to list.

So now the question is: what do we do next with the relationships.

First observation: Every relationship in the rhel data is just "default_component_of":

```sh
❯ zstdcat *.tar.zst | tar -Oxf - | jq -c -r 'select(.product_tree != null) | select(.product_tree.relationships != null) | .product_tree.relationships[] | .category ' | sort | uniq -c | sort 
-n
2092023 default_component_of
```

The example of on the CSAF spec might be instructive here:

Example 42:
``` json 
  "product_tree": {
    "full_product_names": [
      {
        "product_id": "CSAFPID-908070601",
        "name": "Cisco AnyConnect Secure Mobility Client 4.9.04053"
      },
      {
        "product_id": "CSAFPID-908070602",
        "name": "Microsoft Windows"
      }
    ],
    "relationships": [
      {
        "product_reference": "CSAFPID-908070601",
        "category": "installed_on",
        "relates_to_product_reference": "CSAFPID-908070602",
        "full_product_name": {
          "product_id": "CSAFPID-908070603",
          "name": "Cisco AnyConnect Secure Mobility Client 2.3.185 installed on Microsoft Windows"
        }
      }
    ]
  }
```

> The product Cisco AnyConnect Secure Mobility Client 4.9.04053" (Product ID:
> CSAFPID-908070601) and the product Microsoft Windows (Product ID:
> CSAFPID-908070602) form together a new product with the separate Product ID
> CSAFPID-908070603. The latter one can be used to refer to that combination in
> other parts of the CSAF document. In example 34, it might be the case that
> Cisco AnyConnect Secure Mobility Client 4.9.04053" is only vulnerable when
> installed on Microsoft Windows.

[source](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-product-tree-property---relationships)


So let's find an example relationship from Red Hat CSAF JSON and try to
write an analogous paragraph:

``` json
      {
        "category": "default_component_of",
        "full_product_name": {
          "name": "mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le as a component of Red Hat Enterprise Linux AppStream (v. 9)",
          "product_id": "AppStream-9.1.0.GA:mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le"
        },
        "product_reference": "mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le",
        "relates_to_product_reference": "AppStream-9.1.0.GA"
      },
```

A snippet of [this document](https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-23943.json)

Regarding the `default_component_of` relationship, the spec helpfully says:

> The value default_component_of indicates that the entity labeled with one
> Product ID (e.g. CSAFPID-0001) is a default component of an entity with
> another Product ID (e.g. CSAFPID-0002).

This says:

> There's a new "product" referred to within this CVE as
> `AppStream-9.1.0.GA:mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le`,
> which refers to `mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le` when
> it is a default_component_of `AppStream-9.1.0.GA`

Basically, when you see
`AppStream-9.1.0.GA:mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le` in a product id
field, like the list of "known_not_affected" or the list of threats or versions
with vendor fixes, you know that it means the package
`mod_ssl-debuginfo-1:2.4.53-7.el9.ppc64le` installed from AppStream-9, which I
think in our terms means, we found it on a RHEL9 system.

So what I want to understand is this: how do the trees relate?

The `product_reference` items from relationships can be leaves in the
`branches` tree from the product tree. Example:

``` json
  "product_tree": {
    "branches": [
            "branches": [
              {
                "category": "product_version",
                "name": "openstack-nova-1:20.4.1-1.20221005193235.el8ost.src",
                "product": {
                  "name": "openstack-nova-1:20.4.1-1.20221005193235.el8ost.src",
                  "product_id": "openstack-nova-1:20.4.1-1.20221005193235.el8ost.src",
                  "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/openstack-nova@20.4.1-1.20221005193235.el8ost?arch=src&epoch=1"
                  }
                }
              },
              ... snip ...
            "branches": [
              {
                "category": "product_name",
                "name": "Red Hat OpenStack Platform 16.1",
                "product": {
                  "name": "Red Hat OpenStack Platform 16.1",
                  "product_id": "8Base-RHOS-16.1",
                  "product_identification_helper": {
                    "cpe": "cpe:/a:redhat:openstack:16.1::el8"
                  }
                }
... snip ...
      {
        "category": "default_component_of",
        "full_product_name": {
          "name": "openstack-nova-1:20.4.1-1.20221005193235.el8ost.src as a component of Red Hat OpenStack Platform 16.1",
          "product_id": "8Base-RHOS-16.1:openstack-nova-1:20.4.1-1.20221005193235.el8ost.src"
        },
        "product_reference": "openstack-nova-1:20.4.1-1.20221005193235.el8ost.src",
        "relates_to_product_reference": "8Base-RHOS-16.1"
      },
... snip ...
    "vulnerabilities": [
     {
      "product_status": {
        "fixed": [
          "8Base-RHOS-16.1:openstack-nova-1:20.4.1-1.20221005193235.el8ost.noarch",
          "8Base-RHOS-16.1:openstack-nova-1:20.4.1-1.20221005193235.el8ost.src",
          ... snip ...
        ],
     "known_not_affected": [
          "red_hat_openstack_platform_18.0:openstack-nova"
        ]

```

So this is telling me that, a vulnerability matcher should consider:

1. If we're on RedHat OpenStack 16.1
2. We have installed openstack-nova less than 1:20.4.1
3. Then the package is vulnerable to CVE-2024-40767

Also:

1. If we're on RedHat Openstack 18, openstack-nova is not affected

## But what about subsetting?

One of the keys here is going to be making a reasonable set of packages.

Consider this:

``` sh
❯ cat cve-2024-41946.json| jq '.vulnerabilities[0].product_status.fixed | length'
335
```

That's really a lot. It doesn't seem like a human would think of there as being
335 different packages affected by this CVE. Let's have a look.

``` json
{
    "vulnerabilities":[
      "product_status": {
        "fixed": [
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6",
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-bundled-gems-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-bundled-gems-debuginfo-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-debuginfo-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-debugsource-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-devel-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.aarch64",
            ... snip ... - more architectures
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:ruby-doc-0:3.3.5-3.module+el8.10.0+22271+6a48b0b9.noarch",
            ... snip ... - more debuginfo, debugsource, etc.
          "AppStream-8.10.0.Z.MAIN.EUS:ruby:3.3:8100020240906074654:489197e6:rubygem-irb-0:1.13.1-3.module+el8.10.0+22271+6a48b0b9.noarch",
            ... snip ... - more architectures
            ... snip ... - more gems
          "AppStream-9.4.0.Z.MAIN.EUS:ruby:3.3:9040020240906110954:9:rubygem-bigdecimal-0:3.1.5-3.module+el9.4.0+22273+463af10f.x86_64",
          ],
        "known_affected": [
          "red_hat_enterprise_linux_8:ruby:2.5/ruby",
          "red_hat_enterprise_linux_8:ruby:3.1/ruby",
          "red_hat_enterprise_linux_9:pcs",
          "red_hat_enterprise_linux_9:ruby:3.0/ruby",
          "red_hat_enterprise_linux_9:ruby:3.1/ruby",
          "red_hat_openstack_platform_16.1:puppet-datacat",
          "red_hat_openstack_platform_16.1:puppet-etcd",
          "red_hat_openstack_platform_16.1:puppet-opendaylight",
          "red_hat_satellite_6:foreman",
          "red_hat_satellite_6:foreman-proxy"
        ],
        "known_not_affected": [
          "red_hat_openstack_platform_16.2:puppet-datacat",
          "red_hat_openstack_platform_16.2:puppet-etcd",
          "red_hat_openstack_platform_16.2:puppet-opendaylight",
          "red_hat_openstack_platform_17.1:puppet-etcd"
        ]
      }    
    ]
```

The description says:

> A flaw was found in the REXML package. Reading an XML file that contains many
> entity expansions may lead to a denial of service due to resource starvation.
> An attacker can use this flaw to trick a user into processing an untrusted
> XML file.

It seems like there are a few things, in human readable terms, that are vulnerable here:

1. Ruby itself
2. The RPM "ruby-bundled-gems"
3. Many specific ruby gems

But there's a lot of multiplication, because this set of vulnerabilities is multiplied by:

* N for the N bundled gems
* A for the A architectures
* V for the V variants of what are sort of the same package (ruby vs ruby-devel, for example)
* D for the D distros / AppStreams that are affected.

The "known_affected" list is honestly much more human readable. It says things
like "ruby 2.5 for RHEL8 is known to be vulnerable" which is a super easy thing
to understand. So why the craziness in fixed?

``` sh 
# fixed avg length
❯ zstdcat csaf_vex_2024-10-06.tar.zst| tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.product_status.fixed != null) | .product_status.fixed | length' |
 awk '{ sum += $1; count += 1 } END { if (count > 0) print sum / count }'
413.231

# known_not_affected avg length
csaf on  main [!?] is 📦 v0.1.0 via 🐍 v3.11.8 (csaf) took 1m45s 
❯ zstdcat csaf_vex_2024-10-06.tar.zst| tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.product_status.known_not_affected != null) | .product_status.know
n_not_affected | length' | awk '{ sum += $1; count += 1 } END { if (count > 0) print sum / count }'
65.5004

# known_affected avg length
❯ zstdcat csaf_vex_2024-10-06.tar.zst| tar -Oxf - | jq -c -r 'select(.vulnerabilities != null) | .vulnerabilities[] | select(.product_status.known_affected != null) | .product_status.known_af
fected | length' | awk '{ sum += $1; count += 1 } END { if (count > 0) print sum / count }' 
3.89124
```

That's itneresting - fixed is ~100x longer than `known_affected` and ~7x longer
than `known_not_affected`.

I have a thought here though:

### It's for patching

The reason there are tons more `fixed` products than any other kind, and that
the fixed products all look crazy, is that someone needs to know where to get a
patch. So when we right down, "Ruby 2.5 for RHEL 7 is affected and won't be
fixed", we need one product, but when we right don't that a patch was issued,
suddenly we need to list every RPM that the new patch was built into, which 
necessitates literally hundreds of changes. Because if the change was to something
like `libxml` or whatever, then suddenly you need every ruby gem whose native
extensions link to libxml, and their debug symbol variants, for every architecture
because native extensions. That's why there's 415 fixed RPMs, 65 "not affected"
RPMs, and 4 "wont fix" RPMs.

## What about inferring "wont fix"?

I _think_ we can just say, "known_affected". Actually, is "known_affected"
"not-fixed" or "wont-fix"? That's an important question and I don't know yet.


