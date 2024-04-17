# Cryptographic Libraries
*An Empirical Study of Vulnerabilities in Cryptographic Libraries*

## 0. Overview

This repository accompanies the academic paper "Cryptography in the Wild: An Empirical Study of Vulnerabilities in Cryptographic Libraries". We present an empirical analysis of the causes and characteristics of vulnerabilities in 22 widely used cryptographic libraries written in C, C++, Java, Python, and Rust.

The primary component of the repository is the compiled vulnerability dataset, available in cve_database/crypto_lib_cve_dataset.csv. We relied on the NVD to generate an initial vulnerability list, which we then heavily augmented with data from individual project security advisories, project repositories, academic papers, and project version release information.

A particular focus of this work is classifying vulnerabilities according to type. We describe taxonomies for classifying vulnerabilities in cryptographic software and cryptographic vulnerabilities in Sections 1 and 2 below. In addition to the overall vulnerability dataset, the repository also contains experiment data for project complexity meaasurements, version release data, and a separate case study of the OpenSSL, LibreSSL, and BoringSSL projects.


## 1. General Vulnerability Taxonomy

We categorize vulnerabilities according to their root cause. There is a fair amount of nuance here: vulnerabilities are sometimes composed of a chain of errors, causing an inevitable degree of overlap among categories. In these cases, we select the category that best describes the initial problem that started the chain (e.g., an integer overflow that led to a buffer overflow would be considered a Numeric Issue). 

Category | Description | Examples
------------------ | ------------------ | ------------------
Cryptographic Issue | Vulnerabilities arising from a direct flaw in the design or implementation of cryptographic primitives, protocols, and algorithms (i.e., the cryptographic nature of the source code). | Implementation does not follow the recommended RFC practice, using a weak or broken protocol, protocol downgrade attacks, use of unsafe primes to generate cipher parameters, allowing incorrect parameter input for a cipher based on cipher spec (e.g., one parameter should always be larger than the other).
Memory Management | Vulnerabilities caused by memory management—namely, allocating, reading and writing, and freeing data. This category also includes issues that can affect non-memory-safe languages, such as infinite loops and other memory exhaustion issues. | Source code does not check whether an input is null prior to access, missing bounds check while reading a buffer (such as a field from an X.509 certificate).
Side-Channel Attack | An attack that exploits variations in time taken to complete an operation or physical hardware, including timing and memory-cache attacks. | Non-constant scalar multiplication, padding oracle attack.
Numeric Error | Incorrect numeric calculations or conversions, particularly in large number arithmetic, that are not specific to any one cryptographic cipher or algorithm. | Integer overflow, carry propagating bug, bit calculation errors, integer type size variations on different architectures.
Systems Issue | Vulnerabilities arising from library interactions with the local OS. | Files stored in a writable sub-directory, command injection in a shell script, thread safety/concurrency issues.
Miscellaneous | All other issues that don’t fit precisely into one of the above categories. | Wildcard string matching (e.g., matching two domain names), missing documentation, and miscellaneous other implementation bugs.


## 2. Cryptographic Vulnerability Taxonomy

All vulnerabilities broadly classified as a 'Cryptographic Issue' per the taxonomy given in Section 1 are further classified based on the taxonomy below.

Cryptographic Sub-Category  | Examples
------------------ | ----------------
Protocol Attack | Attacks on the protocol specification (e.g., Logjam, POODLE).
Incorrect Implementation of Algorithm | Incorrect calculation of factor size, incorrect implementation of mathematical algorithm (e.g., modular exponentiation).
Parameter Validation | Implementation accepts parameters that are unsafe or don’t make sense for a particular cipher (such as a low public exponent for RSA), does not enforce minimum tag length.
Certificate Verification | Logic and other implementation issues in certificate parsing and verification, such as a missing check on certificate expiration, not checking for a match between the signature algorithm used and the algorithm listed in the certificate, OCSP parsing issues.
Support for Broken or Risky Algorithm | Allowing signatures using MD5 in handshake, weak default key sizes.
Insufficient Randomness | Using an all-zero key, a non-random IV, or an unseeded PRNG.
TLS Implementation | Logic issues in ciphersuite negotiation (e.g., selecting shared ciphers), invalid state machine transitions, other logical flaws in protocol flow.
Miscellaneous | One-line bugs due to typos and copy & paste errors, missing important bit shift, problems with error handling.


## 3. Vulnerability Dataset

In total, our dataset consists of 549 vulnerabilities published from 2005 through 2022 in 22 open-source libraries.

For each CVE, we include the following fields:
1. cve_id: Unique CVE identifier assigned by the NVD.
2. project_name: Most widely used name for the project.
3. project_language: Primary development language used by the project.
4. affects_multiple: Indicates whether the CVE was filed under multiple projects. In certain cases where the same issue (such as a novel side-channel attack vector) is filed under multiple projects under different CVE IDs, we list the IDs for the other projects.
5. version_introduced: Project version in which the vulnerability was introduced. This information is much more challenging to obtain than the patch version since most projects do not track this, and it is therefore unavailable for the majority of CVEs. This is listed as 'N/A' for projects that do not have formal version releases (namely, BoringSSL).
6. version_patched: Project version in which the vulnerability was patched. A 'N' value indicates that the project explicitly opted not to patch.
7. cve_publish_date: Date (MM/DD/YYYY) when the CVE was first published by the NVD (which may differ from the date on which the vulnerability was first discovered).
8. cvss: Common Vulnerability Scoring System (CVSS) numerical value representing the severity of the issue. The CVSS scoring system transitioned from v2.0 and v3.0 in June 2015, and some CVEs were assigned values from both versions. In these cases, we list both v2.0 and v3.0 values separated by a semicolon.
9. project_severity_rating: Some projects assign vulnerabilities their own severity rating (separately from the NVD's CVSS score). We include ratings that we were able to recover from project security advisories here.
10. known_exploited: Indicates whether a vulnerability is known to have been widely exploited as per SecurityScorecard (used by CVEDetails).
11. patch_commit: Link to the patch commit if we were able to recover it through the project's security advisory or by searching targeted keywords.
12. patch_language: Language of the file where the vulnerability was located (may differ from a project's primary language).
13. patch_path: File path of patch commit. This field contains the path at the time of the patch since it is pulled from the patch commit---if the project source code structure has since been modified, the path listed here may no longer exist.
14. patch_location: Semantic characterization of the vulnerability location (i.e., the affected component), which is often more specific than the location_cateogry field below (e.g., may specifcy SSLv2.0 instead of simply SSL). TLS and SSL are used interchangeably here and in location_category.
15. location_category: Mapping from patch_location to a broader component location category (e.g., SSL/TLS, X.509 parsing and verification, signature schemes, etc.).
16. nvd_cwe: The official CWE label(s) assigned by the NVD.
17. manual_label: The category from the taxonomy given in Section 1 that best characterizes the vulnerability as determined from a manual review of the NVD description, the project's description, the patch commit, and other relevant references (see the taxonomy in Section 1 and the accompanying paper for a more detailed description of these categories and the methodology used for classifying each issue).
18. subclass_label: For some categories (namely 'Cryptographic Issue' and 'Memory Management') we additionally provide sub-classifications for vulnerabilities in these categories. The cryptographic sub-class taxonomy is shown in Section 2 above.
19. nvd_override: A flag indicating whether the manual label differed semantically from the NVD label. There are four possible values: "Y", "N", "N/A" (if the CVE does not have a CWE label), and "N (side channel)", indicating that the CVE was reclassified under the specific side-channel category.
20. memory_unsafety: A flag for vulnerabilities in C/C++ source code indicating whether the issue would have been mitigated or prevented altogether by the use of a memory-safe language.
21. primary_advisory: Link to the project's security advisory if available, or the NVD database if no specific security advisory was published or recoverable.
22. other_references: Links to any additional references useful in understanding the vulnerability, such as links to academic papers or blog posts from industry practitioners describing the issue in greater depth. In some cases we also include the NVD link here is the official CVE description provided additional information and/or clarity beyond the project's own security advisory.
23. summary: A brief, 1-2 sentence summary of each CVE with emphasis on the root causes of the issue within the source code. This is intended as a supplement to the NVD's official CVE description rather than a replacement. Since we are primarily interested in the salient aspects of a CVE as relevant to the type classification, this often omits granular details relevant to exploitability (e.g., in some cases the issue is only relevant when a particular flag is enabled).
24. additional_notes: Any additional notes (e.g., relevant quotations from external references, link to commit introducing the vulnerability, observed inaccuracies with NVD data, etc.).

In all fields, a '-' value indicates that the information was unavailable or otherwise unable to be recovered. The Python script database_scraper.py in the same directory will help users to make use of the compile dataset and analyzes several of these fields.