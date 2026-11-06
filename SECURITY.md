# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: **Security →
Advisories → Report a vulnerability** on this repository. Do not open a public
issue for them.

Include the affected version and platform, the token or driver involved if
relevant, what an attacker could do, and steps to reproduce. We aim to
acknowledge reports within a few working days.

## Supported versions

Fixes go into the latest release.

## Scope

`dsc` signs data with a key held on a token, after the user confirms in a
native dialog. Issues where a signature can be made **without** that
confirmation, where the dialog can be made to show the wrong site, document
or signer, or where a web page can reach `dsc` without going through the hey
hub's origin checks are in scope and high priority. See the README's
"Security model" section for the design.
