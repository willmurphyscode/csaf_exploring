## Parsing notes

I think we need to parse cve-foo.json and rhsa-foo.json to get the fixes:

There's a cve-foo per (relevant) cve.
There's an rh[bes]a-foo per patch issues

Unless they're redundant.

Maybe we can get away with the cve-foos.json? I think maybe CVE-foo.json has
the set of all PURLs that fix CVE-foo, and RHSA-foo.json has the set of all
CVEs fixed by patchset RHSA-foo. If that's true, getting a good picture of
the data might only require a few of the 
