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
   

