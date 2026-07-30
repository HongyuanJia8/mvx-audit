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

Live browser analysis is accepted only through the documented container lab:
no public network, no host browser profile, no real user data, no writable
sample mount, and no sandbox-disabling Chromium flag. If Docker or the Chromium
sandbox cannot start under those controls, report `inconclusive`; weakening a
boundary to obtain a result is a security defect.
