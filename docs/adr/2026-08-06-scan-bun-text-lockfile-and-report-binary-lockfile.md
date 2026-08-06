---
status: proposed
date: 2026-08-06
decision-makers: hokupod
---

# Scan bun.lock and Report bun.lockb as Unreadable

## Context and Problem Statement

Neither of Bun's lockfiles was read. `scanAction` looked for `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` and the Python files, and `scanDependencyFile` matched the same set, so an action repository that uses Bun scanned clean no matter what its lockfile pinned. Its `package.json` was still read, but that only records direct dependencies as ranges. Transitive dependencies were invisible, and that is where the August 2026 keyv/cacheable compromise landed for most victims.

Bun has two lockfile formats and they need different answers.

`bun.lock` is the text lockfile and has been the default since Bun 1.2 (January 2025). It is JSONC — JSON that also permits comments and trailing commas — and Go's `encoding/json` rejects both. Bun writes a trailing comma after the last entry of every object, so this is not a theoretical concern; every file Bun produces needs preprocessing. Comments were confirmed to be accepted as well: a `bun.lock` with `//` and `/* */` comments added by hand is parsed and rewritten by `bun install` without complaint.

`bun.lockb` is the older binary lockfile. Its format is undocumented and carries no stability guarantee, so reading it in Go would mean reverse engineering a moving target. Shelling out to `bun` is not viable either, because the scanning environment will not reliably have Bun installed.

The layout of `bun.lock` was established by generating lockfiles with Bun 1.3.14 rather than from recollection. Each entry under `packages` is an array, and its shape varies with how the dependency was resolved:

```jsonc
"@ctrl/tinycolor": ["@ctrl/tinycolor@4.2.0", "", {}, "sha512-kzyuwO…"],
"is-number": ["is-number@github:jonschlinkert/is-number#98e8ff1", {}, "jonschlinkert-is-number-98e8ff1", "sha512-VRiId6…"],
"left-pad": ["left-pad@https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", {}, "sha512-XI5MPz…"],
"@probe/app": ["@probe/app@workspace:pkgs/app"],
"chalk/supports-color": ["supports-color@7.2.0", "", { "dependencies": { "has-flag": "^4.0.0" } }, "sha512-qpCAvR…"],
```

Two properties of that layout drive the implementation. The map key is an install path, not a package name — a second copy of a dependency is keyed `chalk/supports-color` — so the name cannot be read from it. And the array is heterogeneous: a registry package puts the registry string in second position, a git dependency puts the metadata object there, a tarball dependency has three elements and a workspace package has one. The first element is the only one that is always present and always a string.

An npm alias makes the first property load-bearing. For `"tc": "npm:@ctrl/tinycolor@3.6.1"` Bun writes `"tc": ["@ctrl/tinycolor@3.6.1", "", {}, "sha512-SITSV6…"]`: the alias appears only as the key and the descriptor names the package that is actually installed. Reading the descriptor therefore matches an aliased compromised package, while reading the key would miss it.

## Decision

Scan `bun.lock` by stripping JSONC to plain JSON in-process, and report `bun.lockb` as an unreadable file rather than parsing or skipping it.

In scope:

- Strip comments and trailing commas with a hand-written, string-aware pass, then decode with `encoding/json`. No new dependency: the project has three, and a JSONC library would be a fourth for roughly sixty lines of work.
- Make the stripper string-aware rather than a regex. `//` occurs inside string literals throughout a real `bun.lock` — a tarball dependency is recorded as `left-pad@https://registry.npmjs.org/…` and a custom registry is stored as a URL — so cutting at the first `//` truncates the string and corrupts the rest of the document. This is a natural property of the format, not an edge case, and it has its own test.
- Take the name and version from the descriptor at the head of each entry, not from the map key, and decode only that element. The rest of the entry is kept as raw JSON so that the varying array shapes never cause a decode failure.
- Split the descriptor at the first `@` after position zero. A package name only ever contains `@` as the scope prefix, so this handles `@ctrl/tinycolor@4.1.1` correctly, and unlike splitting at the last `@` it does not mis-split a tarball URL that carries userinfo.
- Report `bun.lockb` through the `actionScanResult.FileErrors` path, so it is counted in `Files failed`, its detail goes to stderr, and the other dependency files in the same directory are still scanned. Reject it in `scanDependencyFile` too, so `--local` on the file itself fails loudly.
- Do not report a `bun.lockb` that sits next to a `bun.lock` **that was read successfully**. From Bun 1.2 onwards the text lockfile is the one Bun honours, so those dependencies were already scanned and the leftover binary file is not a coverage gap. Suppressing it on the mere presence of a `bun.lock` would be wrong: if the text lockfile failed to parse, nothing was read, and the binary file is then the only remaining record of the dependencies.
- Fail the file when the decoded `lockfileVersion` is higher than the version this parser was checked against, or when there is no `packages` object at all. Both shapes decode into the struct without error and would otherwise yield zero packages and no complaint. Bun deletes the lockfile outright when a project has no packages, so an existing `bun.lock` always carries a `packages` object; its absence means the dependencies live somewhere this parser does not look. This was checked both ways with Bun 1.3.14: a project with no dependencies produces no lockfile at all, and a workspace whose members declare no external dependencies still writes a `packages` object holding the workspace entries.

Non-goals:

- Do not parse `bun.lockb`, in Go or by invoking `bun`.
- Do not report a name-only match for a dependency whose version is a git ref, a workspace path or a tarball URL. Those entries carry no resolvable version, and the catalog matches on name and version together; flagging on the name alone would be a different detection policy than the rest of the scanner applies.

## Consequences

- Good, because an action that uses Bun is now scanned against its full transitive dependency tree instead of only the ranges in its `package.json`.
- Good, because the parser was written against lockfiles generated by Bun 1.3.14, including the workspace, git, tarball and duplicate-version shapes, rather than against an assumed layout.
- Good, because a `bun.lockb` can no longer be mistaken for a clean result, which is the exact false-clean this tool exists to prevent. With `--fail-on-error` it exits `2`.
- Bad, because the JSONC stripper is a hand-written parser the project now maintains. It is covered by unit tests for comments in strings, escaped quotes and trailing commas, but a future JSONC construct outside that set would need handling here rather than in a library.
- Bad, because an action that ships only a `bun.lockb` still cannot be scanned. It is reported instead of missed, but the dependencies remain unread until someone regenerates the lockfile as text.
- Bad, because the decoder is strict: a `packages` value that is not an array, a missing `packages` object, or a newer `lockfileVersion` fails the whole file. That surfaces format drift as a reported error rather than as silently missing packages, which is the safer direction for a security tool, but it does mean a future Bun format change turns into a failed file rather than a partial scan, and `maxKnownBunLockfileVersion` has to be raised deliberately when Bun bumps the version.
- Bad, because an entry whose first element is not a string is still skipped silently rather than reported. Bun does not produce such an entry today, and the two checks above catch the wholesale format changes, but a change confined to the descriptor position would pass unnoticed.
