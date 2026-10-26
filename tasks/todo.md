# java:cve-report

Goal: report known vulnerabilities (CVE / GHSA) of the Maven dependencies of Java projects.

## Design
- New command `java:cve-report` in a new package `...security.java`.
- Input: one or more project directories (`-d`) or a works directory (`-w`, every child dir with a pom.xml).
- Dependencies: `mvn dependency:list` (runtime+compile, transitive) parsed into group:artifact:version.
- Lookup: OSV.dev `POST /v1/querybatch`, then `GET /v1/vulns/{id}` for severity and fixed version.
  Requests are paced (>= 3 s) as the project rule for external APIs.
- Output: TSV (project, dependency, version, vuln id, aliases/CVE, severity, fixed version, summary).

## Steps
- [x] 1. MavenDependencyLister: parse `dependency:list` output (unit test with fixture)
- [x] 2. OsvClient: querybatch + vulns/{id} parsing (unit test with fixture JSON, no network)
- [x] 3. JavaCveReporter: join and emit TSV (unit test)
- [x] 4. Register `java:cve-report` in App, update README
- [x] 5. rm -rf target && mvn package (tests on), run against html-saurus

## Review
- 141 tests pass (`rm -rf target && mvn package`).
- html-saurus: 43 dependencies, 0 known vulnerabilities (live OSV query).
- Sanity check with log4j-core 2.14.1 in a temporary project: 7 findings incl. CVE-2021-44228 (CRITICAL).
- Not done: CVSS score parsing (severity is the advisory database's label), `-w ~/works` full run, OSV pagination (`next_page_token`).
