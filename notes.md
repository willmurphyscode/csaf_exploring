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
    

