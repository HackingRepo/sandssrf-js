Thank's for your beautiful contribition

Before contributing, if you like the repo, give it a star, we want the tool to be adopted because mitigates the big problem SSRF parsing differentaionals, that is the good thing

first:

1. Make sure all tests passes, if one fails, meaning a security issue introduced, double check your code
2. PRs that add new entries to ip lists or mock ports, first check is that ip is really private or false positive, blocking public ips give no security benefit while introducing false positives, and for modifying mock ports, make sure common HTTP port
3. CI must pass green, including scanning tools and the sandbox tests, if it is failing intermittently then just CI noise
4. Your contribution must stand with MIT license, incompatible code must not be introduced like copying from other projects Microsoft AntiSSRF and others
5. Introducing deps is not accepted, Because of supply chain problems
6. We use the style `fix(): ` and `fix: `

Before opening an issue:
1. Check is already open
2. we use the style `feat: ` and `bug: `, so that how your title looks like
3. Make sure you use Linux and have linux namespaces enabled, if that just your issue, you need resolve it
