# Security policy

## Supported versions

Security fixes are provided for the latest 3.x release on `main`.

## Reporting a vulnerability

Please use GitHub's private security advisory feature for vulnerabilities that
could expose files outside the requested extension root, execute scanned input,
cause uncontrolled resource use, produce unsafe SARIF paths, or otherwise harm
users. Do not include real secrets, browsing data, or harmful payloads in a
public issue.

Include the affected commit/version, operating system and Node version, a
minimal synthetic reproducer, expected behavior, and impact. Maintainers should
acknowledge a report within seven days and coordinate disclosure after a fix.

## Safe operating assumptions

MVX Audit treats extension content as untrusted text and does not execute it.
Still, analyze only material you are authorized to possess. Do not load unknown
fixtures into a daily-use Chrome profile. Report parser escapes and filesystem
boundaries must be reviewed whenever a new format or archive reader is added.
The package inventory hashes bounded regular-file bytes and recognizes a small
set of executable magic signatures; recognition never imports, disassembles,
or executes those files. Inventory limits fail closed instead of silently
claiming a complete content identity.

Declarative rule packs are also untrusted input, not plugins. The loader uses
bounded no-follow regular-file reads, strict UTF-8 and schema validation,
duplicate-key rejection, normalized safe paths, literal rather than regular-
expression matching, bounded nesting and match counts, and escaped report
rendering. It never imports code or fetches pack references. A valid pack is not
trusted intelligence: operators remain responsible for its source, license,
expiry, integrity, and conclusions.

The optional sample fetcher writes live CRX files only after explicit risk
acknowledgement. Quarantine files are not safe merely because their hashes were
verified. Keep quarantine outside backups and shared folders, never open it
with a daily-use browser, and delete it according to your organization's
malware-handling policy.

Direct CRX/ZIP audit also requires explicit CLI risk acknowledgement. It uses
bounded parsing and an automatically removed private extraction, but the
original archive remains live malware and must stay under quarantine handling
controls. The library API is non-interactive and places that acknowledgement
responsibility on its caller.

CRX2/CRX3 verification establishes byte integrity only under the public key
embedded in the same archive and checks that a developer proof derives the
declared extension ID. It does not identify the publisher, consult a trust
store, establish Chrome Web Store authorization, or make signed content safe.
Use an independently trusted extension ID and archive digest when provenance
matters. `--require-valid-signature` rejects invalid CRX and unsigned ZIP input
before extraction; default mode retains invalid CRX content for forensic audit
and emits `MVX004`.

Live browser analysis is accepted only through the documented container lab:
no public network, no host browser profile, no real user data, no writable
sample mount, and no sandbox-disabling Chromium flag. If Docker or the Chromium
sandbox cannot start under those controls, report `inconclusive`; weakening a
boundary to obtain a result is a security defect.
