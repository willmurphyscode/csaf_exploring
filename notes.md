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

