---
status: proposed
date: 2026-08-06
decision-makers: hokupod
---

# Scan Dependency Files Recursively

## Context and Problem Statement

`scanAction` built its candidate paths with `filepath.Join(actionDir, "package.json")` and the equivalent for `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`. It then stat'd exactly those paths. Anything one level down was invisible.

For `--local` that is the common layout rather than an edge case. A monorepo keeps its lockfiles in `packages/*/` or `apps/*/` and has nothing at the root, so `actions-npm-scanner --local .` opened zero files and printed `✅ No vulnerabilities found.` with exit code 0. The output was identical to a genuine clean result — "we checked and found nothing" and "we never checked" were indistinguishable. This was found empirically at v0.6.0 while scanning 163 repositories.

For a false-clean the cost is asymmetric. A false positive is visible: the finding names a file, and a human can look at it and dismiss it. A missed finding produces no output at all, so nothing prompts anyone to look. A scanner that silently answers "clean" is worse than one that is noisy.

The same gap exists on the workflow path. `DownloadAction` clones the whole repository and ignores `Action.Path`, so an action referenced as `owner/repo/subdir@v1` had its dependency files scanned from the clone root, where they are not.

## Decision

Walk the directory tree in `scanAction`, and make the walk the default rather than something the user has to know to ask for.

In scope:

- Add `collectScanDirectories`, which lists the directories to scan relative to the scan root via `filepath.WalkDir`. `scanAction` then runs the existing per-directory scan over each. `filepath.WalkDir` does not follow symlinks, so a link pointing back into the tree cannot loop.
- Prune `node_modules`, `.git`, `vendor`, `.venv`, and `venv`. The shared property is that they hold installed third-party artifacts or version-control internals, not the dependency declarations of the project being scanned. A directory named here is still scanned when the scan is pointed at it directly, since that is an explicit request.
- Keep `dist` and `build`. They are build output, but they are small, so pruning them buys almost nothing, and for a GitHub Action `dist/` is committed and is the code that actually runs — a dependency file in there is worth reading. The skip list is about cost and relevance, and these fail both tests for exclusion.
- Recurse by default, with `--no-recursive` to restore the previous behaviour.
- Apply the same walk to the downloaded action repositories on the workflow path, which closes the path-scoped action gap described above.
- Carry the file each finding came from through `actionScanResult` as a `fileVulnerability{Path, Message}` instead of a bare string, so the summary can attribute a finding to `packages/foo/package-lock.json` rather than to the directory the scan started at. `ScanFinding.Target` already existed for this and now holds the file for a local scan and the subdirectory for a workflow scan. A finding at the scan root is formatted exactly as before.
- Print `Dependency files scanned: N` in the summary. Recursion removes the layout that caused the false-clean, but not the class of it — pointing the scanner at the wrong directory still yields a clean report. A count of zero now says so on its own line.
- Report only the found files in verbose output for subdirectories. The `not found. Skipping.` lines stay, but only for the directory the scan was pointed at; repeating eight of them per directory would bury the findings in a tree of any size.

Non-goals:

- Do not make `getFiles` recursive. GitHub only runs the workflow files directly in `.github/workflows`, so YAML below that directory is something else — a composite action's `action.yml`, a Dependabot config, a Kubernetes manifest — and parsing those as workflows would report errors for files that were never workflows. The workflow path also already prints `Workflows scanned: 0`, so pointing it at the wrong directory is visible in a way the local scan was not. This is a separate decision from the dependency walk and is left as it stands.
- Do not scan inside `node_modules` even though an installed compromised package is a real finding. The lockfile that produced the tree is scanned instead, and it records the same versions at a fraction of the cost.
- Do not add a depth limit or a configurable skip list. Neither has a demanded use yet, and both would be additions on top of this decision rather than changes to it.

## Consequences

- Good, because the layout that produced the silent false-clean no longer does. A monorepo scanned at its root now reports the lockfiles it actually contains.
- Good, because findings stay attributable: the summary names the dependency file, so a monorepo with 40 packages tells the user which one to fix.
- Good, because an action referenced as `owner/repo/subdir@v1` is no longer scanned only at the clone root.
- Good, because `Dependency files scanned: 0` makes an empty scan self-reporting rather than indistinguishable from a clean one.
- Bad, because the default changes behaviour for anyone already running `--local .`. Findings appear that did not before, and a green CI job can turn red. The change is one-directional — recursion only adds findings, never removes them — but a red build is still a surprise, and `--no-recursive` is the escape hatch.
- Bad, because the walk reports dependency files that are not the project's own dependencies. Committed fixtures are the clearest case: this repository's own `testdata/some-user/some-action-with-vulnerable-dep/package.json` pins `@ctrl/tinycolor@4.1.1`, so `--local .` here goes from 0 findings to 1. The finding names the path, so it can be recognised and dismissed, which is the trade this decision accepts over silence.
- Bad, because a large tree costs more to scan. Pruning `node_modules` covers the dominant term; what remains is eight `stat` calls per surviving directory, which is negligible next to parsing the files that are found.
