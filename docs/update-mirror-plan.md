# Update mirror

Plan for a second place Ember can fetch its updates from, for users who
cannot reach GitHub.

**Status:** proposed, not scheduled. Nothing here is built. 1.7.5 already
has the two cheaper fixes from the same report: the updater goes through the
system HTTP or HTTPS proxy (`system_proxy_for` in
`src-tauri/src/commands/updater.rs`), and a connection failure says "Couldn't
reach the update server" instead of "Secure update check failed" (see
`docs/post-1.7.4.md`). This plan is for the users those do not help: no
proxy at all, on a network where GitHub's download hosts are blocked.

## The problem

Every update check fetches
`https://github.com/untaimed18/Ember-P2P/releases/latest/download/latest.json`
and its `.sig`, and every download comes from the same release. Both redirect
to GitHub's asset hosts (`*.githubusercontent.com`), which are commonly
blocked or DNS-poisoned in mainland China. There the check fails every time,
and so does downloading the installer by hand.

## What the user gets

Nothing to set. When GitHub cannot be reached, Ember tries the mirror, with
exactly the same checks, and either offers the update or says it could not
reach either. A user who can reach GitHub never touches the mirror.

The website's download band could also link the mirror's installers, for
people who cannot download from GitHub in a browser either. That is optional
and separate from the updater.

## What must not change

- **Trust rests on the signing key, never on the host.** The mirror's
  manifest is signed with the same key as GitHub's, and it names the same
  installers with the same hashes, sizes and `.sig` signatures, byte for byte.
  A compromised mirror can withhold an update, but not alter one or offer an
  older one.
- **Downgrade protection is shared.** Both sources feed the one observed floor
  in `updater-security-state.json` (`persist_observed_floor`). A mirror that
  lags behind GitHub is "no update", never a rollback, as
  `candidate_is_older_than_running_build_only` already treats an older
  manifest.
- **The signing key stays in one job.** The release workflow's rule, enforced
  by `scripts/verify-release-policy.mjs`, is that only `sign-publish` holds the
  key and it runs nothing from the dependency tree. The mirror's storage
  credentials must not join it there.
- **Drafts stay private.** GitHub only serves `latest.json` once a release is
  published. The mirror must follow the same rule, or it would offer a release
  still under review.

## Choosing the host

Picked by whether it is reachable from mainland China, not by price: at
Ember's size any of these costs a few dollars a release. For scale, v1.7.4's
assets are a 19.6 MB NSIS installer, a 29 MB MSI, a 29 MB `.deb` and a
101 MB AppImage, and `latest.json` had about 136 fetches in its first day.

| Host | From mainland China | Notes |
|---|---|---|
| **Alibaba Cloud OSS, Hong Kong region** | The most dependable without an ICP licence | Its own bucket address works, so no domain is needed. Small per-GB fees. Needs an international Alibaba Cloud account |
| **Cloudflare R2 behind a domain we own** | Usually reachable, via overseas servers, so speed varies | No download fees. The free `r2.dev` address is for testing only and often blocked there, so it needs a domain (about $10 a year). Easiest to drive from GitHub Actions |
| VPS in Hong Kong, Japan or Singapore | Often good, depending on the provider's routes | $5–10 a month, and the server and its TLS certificate are ours to run |
| Mainland cloud or CDN | Best | Needs an ICP licence, in practice a Chinese company or resident |

Not suitable: Gitee (Chinese phone number, content review, limits on release
files), jsDelivr (file size limit below the installers, no release assets),
SourceForge (downloads through unpredictable mirrors), and the Fly.io app the
rendezvous server runs on (`fly.dev` is no more dependable from China than
GitHub, and it would serve files from the rendezvous server).

**Step 0, before any code:** put one small file on OSS Hong Kong and on R2,
and ask the user who reported this to download both from China and say which
works and how fast. That settles the only real unknown.

## Layout on the mirror

One prefix per release, plus the manifest at a fixed address:

```
<base>/latest.json
<base>/latest.json.sig
<base>/v1.7.5/Ember_1.7.5_x64-setup.exe
<base>/v1.7.5/Ember_1.7.5_x64-setup.exe.sig
<base>/v1.7.5/Ember_1.7.5_x64_en-US.msi
...
```

`latest.json` and its `.sig` are served with a short cache lifetime (for
example `Cache-Control: max-age=300`), so a CDN does not keep an old manifest
for hours. Release folders are immutable. Keep the current and previous
release, so an install started just before an upload still finds its file.

## Release workflow

### In `sign-publish` (no new secrets)

After "Add the Linux targets to latest.json" and before hardening, write a
second manifest, `latest-mirror.json`, identical except that every platform
`url` points at `<base>/vX.Y.Z/<asset name>`. A small script,
`scripts/derive-mirror-manifest.mjs`, does the rewrite and refuses anything
whose asset name differs from GitHub's.

Then harden and sign both. `scripts/harden-update-manifest.mjs` already finds
each artifact by the last part of its URL, so it works on the mirror manifest
unchanged and gives both the same hashes and sizes. Upload
`latest-mirror.json` and its `.sig` to the draft release with the rest.

The mirror base address is fixed in the workflow, not a secret, so it is
signed into the manifest and reviewed with the workflow.

### A new workflow, `mirror.yml` (holds the mirror credentials only)

Runs on `release: published`, so a draft never reaches the mirror:

1. Download the published release's installers, their `.sig` files, and
   `latest-mirror.json` with its `.sig`.
2. Verify `latest-mirror.json` against the public key in `tauri.conf.json`,
   and every installer against the hash and size in it. Refuse to upload on
   any mismatch.
3. Upload the installers and `.sig` files to `<base>/vX.Y.Z/`.
4. Upload `latest-mirror.json` and its `.sig` as `<base>/latest.json` and
   `<base>/latest.json.sig`, last, so the manifest never names a file that is
   not there yet.
5. Delete release folders older than the previous release.

Its storage credentials live in an environment of their own (for example
`release-mirror`). `scripts/verify-release-policy.mjs` already holds every
workflow to pinned actions, `persist-credentials: false` and top-level
`contents: read`. Its no-secrets rule covers the jobs of `release.yml` only,
so `mirror.yml` passes as it stands. Add a check that `mirror.yml` never
references the signing key secrets, and that it triggers only on
`release: published`.

A manual re-run (`workflow_dispatch` with a tag) is useful when an upload
fails. It must refuse a tag whose GitHub release is still a draft.

## Updater changes (`src-tauri/src/commands/updater.rs`)

- **Two endpoints.** `tauri.conf.json` lists GitHub first and the mirror
  second. `embedded_updater_config` accepts an ordered list of one or two
  instead of exactly one, and validates each with `validate_url`.
- **Fallback only on unreachable.** `secure_check` tries GitHub. Only if that
  fails with `is_unreachable` (connection, DNS or timeout) does it try the
  mirror. A signature failure, malformed manifest or HTTP error from GitHub
  stays an error and is not papered over by the mirror. A missing manifest
  (404) stays "no update", as now.
- **Same path for both.** Manifest and signature fetch, `verify_minisign`,
  `validate_manifest`, the floor, and the plugin's second fetch bound by
  `raw_json` equality all run unchanged against whichever source answered.
  The installer download comes from the URLs in that source's manifest.
- **Proxy and pinning per source.** `system_proxy_for` and DNS pinning
  already work per URL, so the mirror gets the same treatment.
- **Time budget.** Each source keeps `METADATA_DEADLINE`, and a source that
  cannot connect fails within `CONNECT_TIMEOUT`, so a blocked GitHub costs
  about ten seconds before the mirror is tried. Remember which source
  answered last and try it first next time, so a user in China does not wait
  on GitHub every hour.
- **Errors.** When both fail, report the GitHub failure through
  `public_failure` and log both.

Silent updates (`docs/silent-update.md`) go through the same check, so they
gain the mirror without changes of their own.

## Testing

- **Unit, with the local fixtures** (`NetworkPolicy::local_fixture`, two local
  servers):
  - The primary is unreachable: the mirror is used.
  - The primary serves a bad signature: an error, and the mirror is not tried.
  - The mirror serves a manifest signed with another key: refused.
  - The mirror lags behind the running version: no update, and the floor is
    unchanged.
  - The mirror's installer differs from its manifest's hash: refused.
  - The source that answered last is tried first.
- **Workflow:** script tests for `derive-mirror-manifest.mjs`: URLs
  rewritten, asset names unchanged, output identical otherwise. Policy tests
  for `mirror.yml`.
- **Manual, per release:** with GitHub blocked locally (a hosts entry pointing
  `github.com` and `objects.githubusercontent.com` nowhere), an install finds,
  downloads and installs the update from the mirror. And once from mainland
  China, by a volunteer.

## Rollout

1. Step 0: pick the host with a real test from China.
2. Release workflow writes, hardens and signs `latest-mirror.json`, and
   attaches it to the release. Ship one release this way and check the file.
3. `mirror.yml` uploads on publish. Check the mirror by hand for a release or
   two.
4. Updater fallback, in the release after that. Older builds keep using
   GitHub only, so this can only help.
5. Optionally, mirror links on the website's download band.

## Running costs

- Storage: two releases of about 180 MB each.
- Downloads: per GB on OSS, free on R2.
- A domain, if R2.
- One storage credential to keep and rotate, in its own GitHub environment.

## Open questions

- Which host, after step 0.
- Whether the website should link the mirror too, and for which installers.
- Whether to mirror the AppImage: it is the largest file, and Linux users in
  China are few.
- How long to keep old release folders, if users report installs failing
  partway through a release.
