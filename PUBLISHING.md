# Publishing egov-helper

You'll do this once. After that, your teammates run `npm install @atasuai/egov-helper` / `dotnet add package Atasuai.EgovHelper` and it works — no further setup on their end.

There are two paths. Pick the one that matches how open you want this to be.

---

## Path A — Public on npm + nuget.org (recommended)

Free, no auth setup for teammates, anyone in the world can `npm install` it. Your code is open-source under MIT.

### A.1 One-time GitHub setup

```bash
# from the repo root
gh auth login                                    # if not already logged in
gh repo create atasuai/egov-helper \
    --public \
    --source . \
    --description "KZ e-Gov digital signatures without NCALayer" \
    --push
```

### A.2 One-time npm setup

```bash
npm adduser                                      # creates an npmjs.com account if needed
npm org create atasuai                           # claims the @atasuai scope (free for public)
```

Then create an automation token for CI: <https://www.npmjs.com/settings/[your-username]/tokens> → Generate New Token → "Automation". Copy it.

```bash
gh secret set NPM_TOKEN --body "<paste-the-token>"
```

### A.3 One-time NuGet setup

1. Sign in at <https://www.nuget.org/> (Microsoft account is fine).
2. Reserve the `Atasuai.*` ID prefix: <https://www.nuget.org/account/Manage> → "Reserved Package ID Prefixes" (optional but worth it).
3. Generate API key: <https://www.nuget.org/account/apikeys> → "Create" → name `egov-helper publish`, glob pattern `Atasuai.*`. Copy.

```bash
gh secret set NUGET_API_KEY --body "<paste-the-key>"
```

### A.4 Cut a release

```bash
# Bump versions (the release workflow reads the tag, so the source values are mainly for local dev)
# package.json: "version": "0.1.0"
# packages/dotnet/EgovHelper.Net/EgovHelper.Net.csproj: <Version>0.1.0</Version>

git tag v0.1.0
git push origin v0.1.0
```

Watch the run at `https://github.com/atasuai/egov-helper/actions`. Within ~3 minutes both packages are live.

### A.5 Teammates use it

```bash
# JS
npm install @atasuai/egov-helper

# .NET
dotnet add package Atasuai.EgovHelper
```

Zero auth. Done.

---

## Path B — Private (GitHub Packages)

Free if your GitHub org is OK with public repos *or* you're on a paid plan with private repos. Code stays closed; teammates need a Personal Access Token to install.

### B.1 GitHub setup

```bash
gh repo create atasuai/egov-helper \
    --private \
    --source . \
    --description "KZ e-Gov digital signatures without NCALayer" \
    --push
```

### B.2 Reconfigure the release workflow for GitHub Packages

Replace the `publish-npm` job in `.github/workflows/release.yml` with:

```yaml
publish-npm:
  runs-on: ubuntu-latest
  permissions:
    contents: read
    packages: write
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: '20'
        registry-url: 'https://npm.pkg.github.com'
        scope: '@atasuai'
    - run: npm ci
    - run: npm run build
    - run: node scripts/smoke-test.mjs
    - run: npm publish
      env:
        NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

And the `publish-nuget` job's push step:

```yaml
- run: dotnet nuget push "./out/*.nupkg" \
    --api-key "${{ secrets.GITHUB_TOKEN }}" \
    --source "https://nuget.pkg.github.com/atasuai/index.json" \
    --skip-duplicate
```

`GITHUB_TOKEN` is auto-injected — no secret to set.

### B.3 Teammates need a one-time `.npmrc`

In their home folder (`~/.npmrc`), they add:

```
@atasuai:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_xxxxxxxxxxxx
```

The token is a GitHub Personal Access Token with `read:packages` scope: <https://github.com/settings/tokens/new?scopes=read:packages>.

For .NET (`~/.config/NuGet/NuGet.Config` on macOS / Linux, `%appdata%\NuGet\NuGet.Config` on Windows):

```xml
<configuration>
  <packageSources>
    <add key="atasuai-github" value="https://nuget.pkg.github.com/atasuai/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <atasuai-github>
      <add key="Username" value="<their-github-username>" />
      <add key="ClearTextPassword" value="ghp_xxxxxxxxxxxx" />
    </atasuai-github>
  </packageSourceCredentials>
</configuration>
```

### B.4 Cut a release

Same as A.4: tag and push, CI does the rest.

---

## Path C — Quick alternative: just install from git

If you want zero registry hassle right now and only have a couple of teammates:

```bash
gh repo create atasuai/egov-helper --public --source . --push
```

Teammates skip npm entirely:

```bash
npm install git+ssh://git@github.com:atasuai/egov-helper.git
# or pin to a tag:
npm install git+ssh://git@github.com:atasuai/egov-helper.git#v0.1.0
```

For this to work over `npm install`, the package builds during install. Add to `package.json`:

```json
"scripts": {
  "prepare": "npm run build"
}
```

(Note: `prepare` runs both on `npm install` from a git URL **and** before `npm publish`. It's a Good Default to add even if you go with Path A or B.)

For .NET, teammates use `<ProjectReference>` after cloning, or you publish to a local `.nupkg` folder.

---

## Versioning

Use semver. Update both files in lockstep before tagging:

- `package.json` — `"version": "0.2.0"`
- `packages/dotnet/EgovHelper.Net/EgovHelper.Net.csproj` — `<Version>0.2.0</Version>`

Then:

```bash
git commit -am "release 0.2.0"
git tag v0.2.0
git push && git push --tags
```

The release workflow takes the version from the tag for the .NET pack step, but it doesn't auto-bump the source files — keep them in sync manually so local dev installs report the right version.

---

## Troubleshooting

**`npm publish` says "402 payment required"** — you forgot `--access public` (it's already in `publishConfig`, but if you publish from a different package.json that lacks it, the default for scoped packages is private which requires a paid plan).

**`npm publish` says "403 forbidden"** — either the `@atasuai` scope isn't yours, or the version you're pushing already exists. Run `npm view @atasuai/egov-helper versions` to see what's published.

**`dotnet nuget push` says "duplicate"** — `--skip-duplicate` is already set in the workflow so this is logged as a warning, not a failure. If you want to overwrite, increment the version.

**Teammates' `npm install` is slow over a git URL** — that's because it clones the whole repo and runs the build. Switch to Path A or B for faster installs.
