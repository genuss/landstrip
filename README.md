# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock on Linux,
Seatbelt on macOS, and AppContainer or restricted users on Windows.

## Quick start

Install the CLI and native binary for your platform:

```sh
npm install --save-dev @landstrip/landstrip-api
```

For Linux or macOS, save this as `policy.json`. Windows requires explicit read
grants for the program and its dependencies; see the manual below.

```json
{
  "filesystem": {
    "allowWrite": ["."],
    "denyWrite": ["**/.env", "**/*.pem"],
    "denyRead": ["~/.ssh"],
    "allowRead": ["~/.ssh/config"]
  },
  "network": {
    "allowNetwork": false,
    "allowLocalBinding": false
  }
}
```

```sh
npx landstrip run -p policy.json -- cargo test
npx landstrip policy validate -p policy.json
npx landstrip doctor
```

See [landstrip(1)](packages/landstrip/man/man1/landstrip.1) for policy rules,
merged-policy inspection, CLI options, and platform limits.

## Integrations

- [Node.js API](packages/landstrip-api/README.md): native binary access and trap types.
- [OpenCode](packages/opencode-landstrip/README.md): `opencode-landstrip` plugin.
- [Pi](packages/pi-landstrip/README.md): `pi-landstrip` extension and subagents.

## Development

Run `make ci` from the repository root.

For a release, create a signed tag with `scripts/release.sh VERSION`, push the
commit and tag yourself, then check out the tag commit. Run `make ci`,
`PACKAGE_STRICT=1 make package`, and `make publish VERSION=VERSION` locally.
This builds and packs all npm packages on your machine and uploads the exact
`.tgz` files and SHA-256 checksums to a draft GitHub release; crates.io is
published locally. The tag must be the current commit when packing, so npm
provenance points to the same source. Nothing is pushed by these commands.

For each of the nine npm packages, configure npm's GitHub Actions **trusted
publisher** for organization `landstrip`, repository `landstrip`, workflow
`publish-npm.yml`, with direct `npm publish` allowed. The repository and
packages must be public. Once the workflow is on the default branch, manually
run the command printed by `make publish` (select the release tag as its ref).
GitHub only downloads, verifies, and publishes the already-packed tarballs with
OIDC and npm provenance; it does not rebuild them. Provenance attests to this
hosted publish step and its tag, not to the local build environment. After the
workflow succeeds, run `make publish-finish VERSION=VERSION` locally. This
checks the published tarball integrity and provenance before making the draft
release public and committing updated npm integrity lockfile entries. Push
that final commit yourself.

## License

- Native sandbox: [LGPL-3.0-or-later](packages/landstrip/LICENSE).
- Node.js API and agent extensions: Apache-2.0; see each package's `LICENSE`.
