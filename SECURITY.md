# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest code
on the default branch. Users should reproduce issues with the newest release or
commit before reporting them.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability in syncburst.

Use GitHub's private vulnerability reporting form:

<https://github.com/skaterzeal/syncburst/security/advisories/new>

Include, when possible:

- the affected version or commit;
- operating system and Go version;
- a minimal reproducer using a local or otherwise authorized target;
- expected and observed behavior;
- security impact; and
- any suggested mitigation.

Never include credentials, production data, or details of a target you are not
authorized to test. A report should concern the security of syncburst itself,
not a vulnerability found in a third-party target with the tool.

You should receive an acknowledgement within seven days. Confirmed issues will
be investigated privately, assigned severity based on impact and
exploitability, and disclosed with a fix when practical.

## Safe research

Good-faith research against your own local copy of syncburst and systems you
are authorized to test is welcome. This policy does not grant permission to
test third-party systems or to violate applicable law or contractual terms.
