---
status: proposed
date: 2026-08-06
decision-makers: hokupod
---

# Scan pnpm Lockfile v6 to v9 and Isolate Per-File Scan Errors

## Context and Problem Statement

`PnpmLock.LockfileVersion` was typed as `int`. pnpm writes `lockfileVersion` as a number (`5.4`) up to lockfile v5, but as a quoted string (`'6.0'`, `'9.0'`) from v6 onwards, so decoding a v6+ lockfile failed with `cannot unmarshal !!str '9.0' into int`.

That failure was not contained to the lockfile. `scanAction` returned on the first error, so the whole directory scan was abandoned and the findings already collected from `package.json`, `package-lock.json`, and `yarn.lock` in the same directory were discarded. In workflow mode the failure only appeared as an `Error details` line on stdout and the process still exited `0`, so an automation that greps stdout could not tell a partial scan from a clean one.

Even with the version field decoded, the package keys of v6+ lockfiles were still unreadable. `extractPackageNameAndVersionFromPnpmPath` assumed the v5 `/name/version` shape, while v6 through v8 use `/name@version` and v9 uses `name@version` with the resolved graph moved to `importers` and `snapshots`. As a result no package from a v6+ lockfile was ever matched against the catalog.

## Decision

Read every pnpm lockfile version the tool is likely to encounter, and make a failing dependency file a per-file outcome rather than a per-directory one.

In scope:

- Decode `lockfileVersion` as a raw `yaml.Node` so both the numeric and the quoted-string form are accepted.
- Resolve package keys for lockfile v5 (`/name/version`), v6 to v8 (`/name@version`), and v9 (`name@version`), stripping the peer-dependency suffix in both the v5 (`_vue@2.6.14`) and v6+ (`(vue@3.0.0)`) form.
- Split a `name@version` key at the first `@` after the scope rather than the last one, and reject a version candidate containing `@` or `/`, so that a name starting with a digit (`@scope/7zip-bin`) or containing an underscore (`string_decoder`) is not silently mismatched against the catalog.
- Collect packages from `importers` (v6+) and `snapshots` (v9) in addition to `packages`, `dependencies`, and `devDependencies`, reporting each name/version pair once.
- Accept both the scalar and the `specifier`/`version` mapping form of a dependency entry, and ignore non-registry references such as `link:../shared`.
- Collect per-file failures in `actionScanResult.FileErrors` and keep scanning the remaining files in the directory.
- Report the number of unscanned files as `Files failed` in the summary and write error details to stderr.
- Add `--fail-on-error` to exit with status code `2` when at least one file could not be scanned.

Non-goals:

- Do not change the default exit codes: `1` still means a vulnerability was found and `0` still means the scan finished without one, whether or not some files failed.
- Do not scan pnpm workspace members outside the scanned directory; `importers` entries are read from the lockfile only.
- Do not resolve the peer-dependency variants of a package as separate findings; the base version is what the catalog matches.

## Consequences

- Good, because pnpm-based actions and repositories are actually scanned instead of silently failing; every pnpm lockfile from v5 to v9 is now readable.
- Good, because an unparsable file can no longer hide the findings of its neighbours, which was the failure mode with the largest blast radius.
- Good, because `Files failed` and the stderr error output give automation a way to distinguish a partial scan from a clean one, and `--fail-on-error` makes that distinction enforceable in CI.
- Good, because the default exit codes are unchanged, so existing pipelines keep working.
- Bad, because moving error details to stderr changes what a pipeline capturing only stdout sees; such a pipeline now observes the `Files failed` count instead of the error text.
- Bad, because `ScanAction` now returns findings together with an error, so callers that treat a non-nil error as "no results" will under-report until they read both values.
