// Commit message rules for this workspace.
//
// Extends @commitlint/config-conventional, which implements Conventional
// Commits v1.0.0: https://www.conventionalcommits.org/en/v1.0.0/
//
// Only deliberate departures from that baseline are listed here, so anything
// not mentioned is the upstream default. The types are the upstream set
// unchanged; only the scopes are ours.

import {readFileSync} from 'node:fs';
import {join} from 'node:path';

/**
 * Package names taken from the `workspace:` list in the root pubspec.yaml.
 *
 * Reading them rather than repeating them means adding a package cannot leave
 * this file behind, which would reject the new package's own commits.
 */
function workspacePackages() {
  // Normalized because checkouts on Windows runners use CRLF by default,
  // which would otherwise break the literal '\n' the block regex below
  // expects immediately after "workspace:".
  const pubspec = readFileSync(
    join(import.meta.dirname, 'pubspec.yaml'),
    'utf8',
  ).replace(/\r\n/g, '\n');

  // The block runs until the next line that starts in column zero.
  const block = pubspec.match(/^workspace:\n((?:[ \t]+.*\n?)*)/m);
  const names = block
    ? [...block[1].matchAll(/^\s*-\s*packages\/([A-Za-z0-9_]+)\s*$/gm)].map(
        (match) => match[1],
      )
    : [];

  if (names.length === 0) {
    // An empty list would silently become an empty scope-enum, which rejects
    // every scoped commit for a reason nobody would guess from the message.
    throw new Error(
      'commitlint.config.mjs: found no packages in the workspace: list of ' +
        'pubspec.yaml; the scope rules cannot be derived',
    );
  }
  return names;
}

/**
 * The short form of a package name, or null when it has none.
 *
 * Mirrors `shortScopeFor` in tool/changelog.dart, which decides what a scope
 * routes to. test/changelog_test.dart asserts the two agree.
 */
function shortScopeFor(name) {
  if (name.startsWith('c2pa_')) {
    return name.slice(5);
  }
  if (name === 'c2patool_dart') {
    return 'c2patool';
  }
  return null;
}

const packages = workspacePackages();

const scopes = [
  ...packages,
  ...packages.map(shortScopeFor).filter((scope) => scope !== null),
  // Changes to CI, tooling, and documentation belong to no package and reach
  // the root changelog alone.
  'root',
  // Dependabot's `include: scope` (and its own detection of this repo's
  // conventional-commit style) only ever writes `deps` or `deps-dev` as the
  // scope, e.g. `chore(deps): bump actions/setup-node from 4 to 7`. That
  // vocabulary is not configurable per-repo, so both are accepted here too;
  // tool/changelog.dart routes them to the root changelog, same as `root`.
  'deps',
  'deps-dev',
];

export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // A scope has to name something the changelog tooling can route to.
    // Without this an invented scope is accepted and then quietly reaches the
    // root changelog only, which is indistinguishable from it having worked.
    //
    // The scope itself stays optional: an unscoped commit applies everywhere.
    // Several may be given using commitlint's default delimiters, so
    // `fix(codec,io):` reaches both packages.
    'scope-enum': [2, 'always', scopes],
  },
};
