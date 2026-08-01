# Third-party notices

The npm package bundles the following exact runtime parser dependencies for
offline, reproducible analysis:

- Acorn 8.18.0 — MIT — https://github.com/acornjs/acorn
- entities 6.0.1 — BSD-2-Clause — https://github.com/fb55/entities
- Parse5 7.3.0 — MIT — https://github.com/inikulin/parse5
- Saxes 6.0.0 — ISC — https://github.com/lddubeau/saxes
- xmlchars 2.2.0 — MIT — https://github.com/lddubeau/xmlchars

The bundled Acorn, entities, Parse5, and xmlchars directories include their
upstream license files. The Saxes npm artifact does not include its repository
license file, so its upstream notice is reproduced below. The project does not
bundle browser binaries, malware, or third-party extension source. Synthetic
fixtures and project code are provided under the repository MIT license.

## Saxes 6.0.0 license

The ISC License

Copyright (c) Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Saxes was forked from sax, whose notice is:

The ISC License

Copyright (c) Isaac Z. Schlueter and Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

The upstream Saxes license also retains this historical notice for
`String.fromCodePoint` code that is no longer used:

Copyright Mathias Bynens <https://mathiasbynens.be/>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Threat-intelligence sources

The normalized threat-intelligence snapshot incorporates data from:

- MalExt Sentry by toborrm9 and contributors, licensed under MIT.
- Malicious Chrome Extension IOC Database by Mallory Bowes Brown and
  contributors, licensed under CC BY 4.0. Extension IOC data sourced from
  chrome-mal-ids: https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids
- MaliciousBrowserExtensions metadata and Git tree by Gherardo Fiori,
  licensed under MIT.

Upstream repository URLs, exact revisions, input checksums, and attribution are
recorded in `intel/sources.json`. Referenced CRX packages are not redistributed
and may have separate rights from their index metadata.

Documentation links to Chrome for Developers as primary technical references.
Linked material remains under its respective publisher's terms and is not
redistributed by this repository.
