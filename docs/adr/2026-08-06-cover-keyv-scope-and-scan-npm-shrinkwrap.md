---
status: proposed
date: 2026-08-06
decision-makers: hokupod
---

# Cover the @keyv Scope and Scan npm-shrinkwrap.json

## Context and Problem Statement

The August 4, 2026 compromise started in the `keyv` and `cacheable` npm namespaces, but the catalog only covered one side of it. `@cacheable/memory`, `@cacheable/net`, `@cacheable/node-cache`, and `@cacheable/utils` were listed, and so was the unscoped `keyv`, yet the `@keyv` scope had no entries at all. A lockfile pinning `@keyv/redis@6.0.0` therefore scanned clean.

The published analyses disagree about that scope. Socket lists `@keyv/redis`, `@keyv/sqlite`, and `@keyv/mongo` at `6.0.0` and notes that the tarballs were published without a confirmed malicious payload, while Snyk states that the other packages under the `@keyv` scope were not compromised. Aikido does not mention the scope. Choosing between the two readings from prose alone would either leave a detection gap or add entries the tool cannot justify.

The npm registry settles it. Seventeen `@keyv/*` packages have a recorded `6.0.0` publish timestamp between 09:30:01Z and 09:32:24Z on August 4, 2026 — a five-second cadence that matches an automated republish rather than a release — and every one of those versions has since been removed from the registry. `keyv` itself was published as `6.0.0` at 09:35:00Z in the same batch. Two packages in the scope, `@keyv/serialize` and `@keyv/offline`, exist on npm but carry no `6.0.0` record.

Separately, `npm-shrinkwrap.json` was never read. It uses the `package-lock.json` format and, unlike `package-lock.json`, is published inside the package tarball, so an action can ship one as its only dependency lockfile.

## Decision

Base the `@keyv` entries on the npm registry publish record rather than on any single vendor's prose, and read `npm-shrinkwrap.json` with the existing `package-lock.json` scanner.

In scope:

- Add the 17 `@keyv/*` packages that have a recorded `6.0.0` publish, each pinned to `6.0.0` only.
- Leave out `@keyv/serialize` and `@keyv/offline`, which have no `6.0.0` publish record.
- Leave out `file-entry-cache@11.1.7`. Socket's article lists it, but the registry has no publish record for that version, and Aikido, Snyk, and the existing catalog entry all name `11.1.6`. Listing a version that was never published would only misfire if the maintainer later releases `11.1.7` legitimately; the current `latest` is `11.1.5`, so that is a live possibility.
- Scan `npm-shrinkwrap.json` in `scanAction` and accept it in `scanDependencyFile`, reusing `scanPackageLockJSONOptimized` because the two formats are identical.

Non-goals:

- Do not add a registry lookup at scan time. The catalog stays static and offline; the registry was consulted only while compiling these entries.
- Do not widen the `@cacheable` scope. Its monorepo publishes exactly the four scoped packages already listed.

## Consequences

- Good, because the campaign's second namespace is now covered; `@keyv/redis@6.0.0` and its 16 siblings are detected instead of scanning clean.
- Good, because the entries rest on a verifiable registry record with timestamps, so a future reviewer can re-check them without relying on which vendor wrote what.
- Good, because an action that ships only an `npm-shrinkwrap.json` is no longer skipped entirely.
- Bad, because the 17 versions are all removed from npm, so the entries only fire on a lockfile or cache that still pins them. That is exactly the case worth catching, but it means the additions will never match a fresh install.
- Bad, because leaving out `file-entry-cache@11.1.7` diverges from Socket's published list. If Socket's entry turns out to be correct rather than a typo, this catalog will miss it until the entry is added.
