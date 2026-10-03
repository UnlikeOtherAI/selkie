# Coordinated Coder and Selkie broker activation

Status: preflight complete; production activation remains held for the approved
UOA mapping and exact Coder release artifacts. This document authorizes no
merge, production migration, service stop or deployment by itself.

## Release inputs and compatibility

Selkie PR [#9](https://github.com/UnlikeOtherAI/selkie/pull/9) was inspected at
`6f4f5d91e0a082832d4c4e15c86cc4dfa3dbf189`, with all five CI checks green.
The coordinated Coder implementation is merged revision
`0f7e8cf7466466d41a6583e26b02274468ec2aa4`; its approved publisher must produce
both API and admin images for the selected reviewed release revision. Record
immutable digests before activation rather than relying on a moving image tag.
If the publisher changes the chosen revision, review that exact revision and
record its successful checks and artifacts before replacing this release input.

The old broker accepts `{uoaSub,email,displayName}`. The new broker accepts only
`{uoaSub,capability}` at `POST /api/v1/internal/mint-session`, using the existing
service-key transport. UOA validates the delegated capability, exact destination,
current membership, epoch and policy. The response remains `{token,expires_at}`,
and its expiry cannot exceed the five-minute capability expiry. Mixed old/new
broker callers and servers are incompatible; there is no profile-copy fallback.

The exact operator mapping is source domain `coder.unlikeotherai.com`, product
`coder`, resource `https://api.selkie.live`, and scope `session:broker`.
It must be approved through the live UOA permission form and verified as enabled
in durable state. Preparing the form is not approval. The parent reports the
UOA broker backend and permission editor deployed, with editor revision
`d0244a182ac455ee698e869216bfc07b58b87a21`; mapping approval is still pending.

## Verified production preflight, 3 October 2026

The public Selkie `/healthz` and `/readyz` endpoints return `ok` and `ready`.
The server and Redis containers are healthy. `selkie-server`, `selkie-redis`
and `selkie-coturn` all belong to Compose project `ops`; Redis retains
`ops_redis_data`. Use `ops/compose-prod.sh`, which discovers that owner. Do not
start a competing `selkie` project, remove volumes, or replace shared Postgres
or Caddy.

The running Selkie image is the immutable Docker image index
`sha256:329bb0684f8a4119e9b5d7780a90432fdd72e5191a3c8a0200d1152fb08496fa`,
started at `2026-10-03T11:27:18.8312537Z`. The last successful deployment workflow
was for `cf8cebf1853ff604e4cce0574ce9161c38891b64`. The current image does not
embed a source revision label; the workflow revision and the running image are
separate evidence. Record the new workflow revision and running image ID at
activation instead of claiming `/readyz` alone proves an exact release.

Production currently has migrations 001–003, one user with a stable UOA subject,
zero devices, zero connection sessions, zero mobile handoffs, and 27 audit events.
The live signed UOA configuration has domain `api.selkie.live`,
`org_features.enabled:false`, and the expected browser/mobile redirects.
Required Selkie UOA signing/client material, session secret and internal service
key are present. This inspection exposed no credential contents.

Coder loads `/app/api/.env` from the protected `/srv/coder/.env` bind mount through
dotenv. Docker `Config.Env` omits these keys and is not a valid configuration
witness. The mounted-file parser and an in-memory comparison verified:

- `UOA_DOMAIN=coder.unlikeotherai.com`.
- `SELKIE_API_BASE_URL=https://api.selkie.live`.
- `API_PUBLIC_URL=https://coder.unlikeotherai.com`.
- `UOA_CONFIG_URL=https://coder.unlikeotherai.com/api/auth/sso/config`.
- `UOA_JWKS_URL=https://coder.unlikeotherai.com/.well-known/jwks.json`.
- The Coder client secret, signing key and service key are present.
- `CODER_SELKIE_SERVICE_KEY` equals Selkie's existing
  `SELKIE_INTERNAL_SERVICE_KEY`.

The file is root-owned, mode 600, with no duplicate definitions. No candidate
configuration or active-environment edit was needed. The exact Coder release
derives its delegated resource from `SELKIE_API_BASE_URL`; it has no separate
transport/audience override. An internal HTTP hostname would fail its required
public-origin check. Preserve the existing public HTTPS origin and all unrelated
settings. The current Coder process predates the file's latest modification;
these checks establish configuration for the next recreated process rather
than its old in-memory settings.

## Recovery artifacts and migration rehearsal

Owner-only recovery artifacts are retained on the deployment host, outside the
rsync-managed checkout:

`/srv/selkie-recovery/debug-login-20261003-precutover/`

The directory is mode 700; files are mode 600. It contains a custom-format
Selkie database dump, the saved previous server image, previous `.env`, private
runtime/image recovery metadata, the existing Compose/wrapper files, migration
input, checksum receipts, and restore/schema/isolation evidence. Private files
contain recovery credentials or historical profile data; never copy them into
Git, display their contents, or attach them to a public build log.

| Artifact | SHA-256 |
| --- | --- |
| `selkie-before.dump` | `368ccec3c33beb25e20a5a9ee59935b68f316787779af41393d0b04669d612ac` |
| `previous-server-image.tar` | `156e641a55f765ab2422aa3dc3e6c58c1eeed92a51dd469b35c83f0c46e931e1` |
| `candidate-migrations.sql` | `3b53f83c4487393aa355e297adee1ceef147f7773a6fd182153f522c60084e3d` |

The dump restored successfully into a task-owned PostgreSQL 17 container with
network `none`, no host ports, no production credentials or running application,
0.5 CPU, 384 MiB memory and 128 PIDs. Migrations 004–007 were then applied, each
inside its own transaction with the migration ledger entry, matching the server's
startup ordering. Counts and fingerprints of stable actor references,
operational flags and audit IDs remained identical. The resulting schema removed
`users.email` and `users.display_name`, retained the stable UUID/subject, and
contained the expected capability-kind, unadmitted-closing and cleanup-window
constraints. No historical device/team assignment was introduced.

Both archive checksums passed. Every saved OCI blob digest was verified, and its
index contains the exact previous running image. The rehearsal container
`selkie-debug-login-restore-20261003` and volume
`selkie-debug-login-restore-20261003-data` were removed. The live database remains
at 001–003, the original image is still running, and readiness remains healthy.

This is a preflight recovery point. Capture a fresh owner-only snapshot after
writers are quiesced at the actual cutover; do not overwrite this verified baseline
or mistake it for a snapshot taken after services stopped.

## Activation sequence

1. Obtain action-time user confirmation for the exact UOA mapping above. Save
   durable enabled-state evidence without exporting tokens. Confirm UOA health,
   both immutable Coder image digests, its reviewed revision/checks, and green
   Selkie checks for the final integration head. Record the cutover owner and
   the Coder migration/revocation runbook.
2. Stop both API services using their existing deployment procedures and verify
   they remain stopped. This prevents old and new broker contracts from
   overlapping. Recheck current counts and capture fresh protected
   database/config/image recovery points for both products. Keep the Selkie
   session-sealing secret unchanged. The existing baseline preserves restore
   proof; the new snapshots preserve the actual cutover point.
3. Keep Coder stopped and merge Selkie's green final PR only after the
   coordinated release owner gives the activation signal. Every push to `main`
   automatically starts `deploy.yml`: it rsyncs into `/srv/selkie`, preserves
   `.env`, and invokes `./ops/compose-prod.sh up -d --build`. The workflow is not
   CI-gated, so merge is an activation action, not a harmless staging step. Do
   not dispatch a duplicate deployment concurrently.
4. Follow Selkie's deployment for the exact merged SHA while Coder remains
   stopped. Startup automatically applies pending migrations before the HTTP
   server becomes ready. Verify ledger filenames 001–007, absence of mirrored
   profile columns, preservation of stable references, and the expected session
   constraints. Record the new server image ID, container start time, Compose
   owner/volume continuity and workflow URL. Public health/readiness must pass;
   their success alone does not prove broker or identity behavior. If deployment
   or verification fails, keep Coder stopped and follow the schema-aware recovery
   procedure below.
5. After Selkie's new schema and readiness are verified, execute Coder's approved
   exact release deploy command with the verified immutable images and
   configuration. That command couples legacy-family revocation, migrations,
   API/admin activation and health verification. Record each result and the
   running release identity; an image recreation alone does not establish
   migration completion. There is no separate established broker-traffic gate,
   so do not start Coder before this step. Broker traffic resumes only with the
   new compatible pair.
6. Test actual UOA login and the new Coder-to-Selkie delegation, independent
   session admission, five-minute expiry and rebroker behavior. Confirm legacy
   profile-bearing broker bodies fail, revoked/expired authority fails, and an
   authority outage is retryable.
7. Verify Selkie's rendered login/authenticated debug control at desktop/mobile
   sizes, JSON with exactly `{url,token}`, bare-code input, thirty-minute expiry,
   single use, renewal invalidation, independent recipient/source families and
   confirmed family-only logout. Record real-provider proof separately from
   fixture screenshots and CI. Personal devices remain owned by their existing
   actor UUID; with `org_features.enabled:false`, source team claims grant no
   target team-resource access.

## Recovery and rollback limits

The old Selkie image cannot run correctly against migration 004 or later: it
queries the dropped profile columns. Migrations commit individually, so inspect
the ledger after any failed boot; do not assume the entire 004–007 sequence rolled
back. The startup ledger is filename-based, not a checksum ledger; retain the
exact reviewed migration inputs and never edit an applied file.

If the image build fails before startup migrations, first prove the live schema
still ends at 003. The previous saved image can then be loaded and selected by
its immutable ID through a server-only Compose override with `--no-build`, using
the existing `ops` ownership and protected configuration. Do not use a moving
`latest` tag, start another Compose project, or change Redis/coturn/shared services.

If any migration has committed, keep both broker sides quiesced. Prefer a reviewed
forward repair. Reverting to the legacy pair requires restoring the appropriate
pre-cutover database recovery points and selecting their matching images/config;
reverting an image alone is unsafe. Restore Selkie's dump into a separate recovery
database first, verify schema/count/reference evidence, and only point the stopped
service at it after the release owner approves the recovery. Do not drop or restore
over the shared PostgreSQL instance or unrelated databases.

Coder's upstream family revocations cannot be undone by restoring database bytes.
New Selkie refresh families admitted after the recovery point also require exact
upstream cleanup before their durable handles can be discarded. Preserve those
handles for confirmed revocation or controlled recovery, and require fresh sign-in
where upstream families have ended. Do not claim that a database restore reverses
UOA actions. Retain backups and release receipts until the coordinated live proof
passes and the release owner explicitly releases the recovery point.
