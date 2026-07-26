# Legacy result retirement

The pre-2.0 repository published success-rate claims derived from 461 tiny CSV
files and several incompatible runner generations. Those results were removed
because they were not scientifically or operationally valid.

The baseline audit found:

- only 36 distinct file contents among 461 CSV files;
- browser infrastructure failures counted as attacks being blocked;
- remote payload download attempts counted as payload execution;
- MV2 and MV3 tested in different browser versions;
- hard-coded “actual” outcomes in the comparison script;
- scripts that disabled the browser sandbox and visited real pages;
- one MV3 keylogging proof of concept configured with a public collection
  endpoint; and
- copied samples with incomplete provenance and licensing information.

Git history preserves the files for forensic review. They must not be reused as
evidence, combined with new results, or presented as measured MV2/MV3 security
rates.

Version 2.0 resets the project to deterministic static evidence. The acceptance
contract for any future browser experiment is documented in
[methodology.md](methodology.md#runtime-experiments).

