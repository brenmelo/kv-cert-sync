# Design questions and answers

These are the questions a reviewer asks about this design, answered one by one. Related documents: [REQUIREMENTS-COVERAGE.md](REQUIREMENTS-COVERAGE.md) (what this proof of concept does and does not address), [OPERATIONS.md](OPERATIONS.md) (running and troubleshooting it), [CUSTOMER-RUNBOOK.md](CUSTOMER-RUNBOOK.md) (rolling it out vault by vault) and [TEST-REPORT.md](TEST-REPORT.md) (the evidence).

Each answer is labelled by how well it is backed:

* **Tested** - it ran in the lab and the evidence is in [TEST-REPORT.md](TEST-REPORT.md).
* **Microsoft docs** - documented behaviour with a link; not exercised here.
* **Judgment** - my recommendation. Reasonable people can differ.

## Short answers

| # | Question | Short answer |
|---|---|---|
| 1 | What actually exports the certificate from the source vault into the other vaults? | The **sync function app**. Event Grid only delivers a small notification. Key Vault has no copy operation. See section 1. |
| 2 | Does the function need more than Certificate User on the source vault? | On the **source vault**, no. It needs other roles elsewhere: import rights on every destination vault, its own storage, telemetry. See section 2. |
| 3 | Why a user-assigned managed identity and not system-assigned? | The role assignments, including the ones in other subscriptions, exist **before** the app does and survive a rebuild of the app. It is a trade-off, not a rule. See section 3. |
| 4 | One Key Vault or several to request renewals from the CA? | One authoritative "certificate factory" vault per trust boundary (for example production and non-production). Do not let two vaults issue the same certificate. See section 4. |
| 5 | What makes it resilient? | Idempotent copy, events plus a timer sweep, early renewal, alerts on the *copies* rather than on the source, and replicas that keep serving when the source is down. See section 5. |
| 6 | Security concerns? | Yes, several. The honest list is in section 6, and the README repeats the main ones. |
| 7 | Was a consumer tested, and what was not deployed? | Yes, an Application Gateway: it served the copy from its regional vault and took a rotation when its refresh was forced (about 60 s). That it picks the new version up **on its own** was not observed. Section 7 lists everything that was not deployed. |
| 8 | Would a real DigiCert certificate have been the same? | The vault, event, sync and consumer parts: yes. The CA part: no. See section 8 and [CERTIFICATE-AUTHORITIES.md](CERTIFICATE-AUTHORITIES.md). |
| 9 | Is the design ready for 46/47-day certificates? | The renewal timing is. Domain validation is not solved and is the real work. See section 9. |
| 10 | Does something like this already exist? | Parts of it. Nothing found does the whole job. See [PRIOR-ART.md](PRIOR-ART.md). |
| 11 | Can this be a "Deploy to Azure" button? | Not for Terraform. See section 10 for what the repo offers instead. |
| 12 | Why not simply share one Key Vault entry across subscriptions? | You can, inside one tenant, for some consumers. The costs are identity fan-out, blast radius, regional coupling and uneven consumer support. See section 12. |
| 13 | Which lifecycle events can a serverless function automate? | New version, near expiry, pending-CSR merge, periodic repair and alerting are built and were run. Domain validation, revocation and decommissioning are not. See section 13. |

---

## 1. What exports the certificate?

The function. Here is the path, in order:

1. Key Vault publishes `CertificateNewVersionCreated` and `CertificateNearExpiry` to an Event Grid system topic. **The event is metadata only** (vault name, certificate name, version, timestamps). It carries no key material.
2. Event Grid, using its own system-assigned identity, writes the event into a Storage queue that belongs to the sync function app.
3. The sync function (queue trigger, running as its user-assigned identity) reads the message and then:
   * reads the certificate and its policy from the source vault (`get_certificate`);
   * skips it unless it carries the opt-in tag `kvsync`, is not itself a replica (`kvsync-origin`), and has an exportable policy;
   * reads **exactly that version** as a secret (`get_secret(name, version)`). This is the PFX/PEM with the private key;
   * proves in memory that the private key matches the certificate;
   * for each destination vault: does nothing if it already holds the same thumbprint, refuses to overwrite a certificate it did not create, otherwise calls `import_certificate` and reads it back to check that the DER bytes are identical.
4. A timer (every 15 minutes by default, every 5 in the proof of concept) repeats the comparison for every opted-in certificate, so a lost event only delays the copy.

The key material therefore passes through the memory of the function, over TLS, and is never written to disk or to a log (the log lines hold names, versions and results only). **Tested** (the sync and rotation runs; the log query that looks for key material is in the test report).

Key Vault has no "copy certificate to another vault" call. Backup and restore exist but work only inside one subscription and one geography ([Microsoft docs](https://learn.microsoft.com/azure/key-vault/general/backup)), which is why a function is needed for cross-subscription copies.

## 2. Is Certificate User on the source vault enough? What else does each identity need?

For the **source vault**, yes. The built-in *Key Vault Certificate User* role grants `certificates/read`, `secrets/getSecret/action`, `secrets/readMetadata/action` and `keys/read`. That is exactly "read the certificate, its policy, and its exportable private key" and nothing else. **Tested** (the role definition was read back with `az role definition list`, and the sync ran with it).

The function needs more than that, but not on the source vault. Everything each identity holds in the deployed stack:

| Identity | Scope | Role | What it allows | Why it is needed |
|---|---|---|---|---|
| Sync (user-assigned) | Source vault | Key Vault Certificate User | Read certificates and secrets (so the PFX) | Read the version to copy |
| Sync | **Each destination vault** (any subscription) | *KV Certificate Importer* (custom) | `certificates/read`, `certificates/import/action` | Import a new version. Cannot delete, purge, back up, restore, or touch keys and secrets |
| Sync | Its own storage account | Storage Blob Data Owner, Queue Data Contributor | Host state, the deployment package, the queue it reads | Functions host with identity-based storage |
| Sync | Application Insights | Monitoring Metrics Publisher | Send telemetry with Entra ID (local auth is off) | Logs |
| Event Grid system topic | Sync storage account | Storage Queue Data Message Sender | Add messages only | Write events. It cannot read or delete them |
| Renewal (user-assigned) | Source vault | *KV Certificate Issuer* (custom) | `certificates/read`, `create`, `update` | Create the pending version (CSR) and merge the signed chain. **No** `getSecret`, so it cannot read a private key |
| Renewal | Source vault | Key Vault Secrets User with a condition | `getSecret` only for secrets whose name starts with `ca-` | Read the CA API key (or the test CA bundle) and nothing else |
| Renewal | Its own storage account | Blob Data Owner, Queue and **Table** Data Contributor | As above, plus the order state and a lease | Remember which CA order belongs to which certificate |

**Tested:** the custom roles were enough for request, signing, merge, copy to two vaults in two subscriptions and a forced rotation. I did **not** remove actions one at a time to find the smallest possible set. For example, `create` and `update` may not both be needed for the merge.

**Tested (effective-access audit).** `tests/live/access_audit.py` reads what each identity can *actually* do on each vault, not what a role name suggests, and applies six rules: assignments at resource scope, no administrative role, no wildcard or `NotDataActions` in Key Vault data actions, import-only on destinations (and nothing for the renewal identity), a conditioned private-key read for the sync identity on the source, and the same for the renewal identity. The first run passed **11 of 14** expectations. Two of the three failures were the audit rule being too broad: it also flagged the built-in *Storage Blob Data Owner* on each app's own storage account, which the Functions host needs, so the rule was narrowed to Key Vault data actions. **The third was real:** the sync identity could read every secret in the factory vault, including the CA credential. That was fixed with an ABAC condition on its role assignment (names starting with `ca-` are excluded). A second probe (`abac_probe.py`) shows the vault answering **403** to the sync identity for a `ca-` secret, in the audit log, while an ordinary certificate is still copied. After both changes the audit passes **14 of 14**. Evidence: [TEST-REPORT.md](TEST-REPORT.md), section 3.

If you cannot create custom roles, `destination_role_mode = "builtin"` uses *Key Vault Certificates Officer*. That works too but also allows delete, purge, backup and restore on every destination, which is more than the job needs.

**Access policies instead of RBAC.** If an existing vault still uses access policies, the sync identity needs `Get` and `List` certificate permissions on the source, and `Get`, `List` and `Import` on a destination. The runbook covers this. Nothing in this repo converts a vault from access policies to RBAC, and you should not do that as part of this change.

## 3. Why a user-assigned identity, not system-assigned?

Reasons, in order of weight:

1. **The role assignments can exist before the app.** A system-assigned identity is created with the resource, so its role assignments cannot be created in advance. Microsoft says exactly this: "role assignments can't be created in advance. This sequence can cause failures while deploying infrastructure" ([best practices](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)). Here some of those assignments are in **other subscriptions**, so they are created by a different part of the Terraform plan and can take minutes to replicate.
2. **Flex Consumption needs storage access when the app is created.** Its deployment package and host state live in a storage account reached with the identity, so the identity has to exist and have its role first. This is the same "access required before a resource is deployed" row in the table in the Microsoft article.
3. **It survives a rebuild.** Destroy and recreate the function app and the cross-subscription grants stay in place.
4. **Simpler plan.** One identity, one set of assignments, no replication race at first start.

What it costs:

* The identity is a separate resource to clean up.
* Anything running in the app can use the identity. That is true for a system-assigned one too, which is why the **sync and renewal functions are separate apps with separate identities**. The sync app cannot create certificates or read the CA key, and the renewal app cannot read private keys.
* The code must name the identity (`client_id`) when it asks for a token.
* The audit log shows an identity, not a resource. Because each identity belongs to exactly one app here, that is the same information.

When system-assigned is the better choice: when you need permissions to disappear with the resource, or when audit has to say which *resource* acted. Microsoft lists both of those as the reasons to prefer it. **Judgment:** for this design the user-assigned identity is the better fit; if your standards require system-assigned, the change is small (create the role assignments after the app, accept a first start that fails until they replicate).

## 4. One vault, or two or more, to request renewals?

**Recommendation (judgment):** one authoritative "certificate factory" vault per trust boundary. A trust boundary is, for example, production versus non-production, or one CA account versus another. Do **not** let two vaults issue the same certificate.

| Option | Good | Bad |
|---|---|---|
| **One factory vault per trust boundary (recommended)** | One key lineage, one CA order per renewal (cost, domain validation and DigiCert rate limits are per order). One issuing identity and one CA credential to protect. The copy logic assumes one writer per certificate name | New issuance depends on one region (copies keep working, see section 5) |
| One vault per consuming subscription, each requesting its own certificate (the situation this design replaces) | No central dependency | N orders, N domain validations, N renewals to watch, N CA credentials, and N private keys for what is logically one certificate |
| Two factory vaults for **different** certificates (by environment, business unit, CA, or sovereign cloud) | Separate blast radius and ownership. A compromise or an outage in one does not touch the other | Two issuing identities, two CA credentials, two sets of alerts. Only worth it for a reason you can name |
| Two factory vaults both able to issue the **same** certificate (active-active) | Looks resilient | **Split brain.** Two key pairs, two orders, and whichever writes last wins on the copies, so the thumbprint can flap. It needs leader election to be safe. Not recommended |
| Primary plus a warm-standby factory | A named recovery path if the primary region is lost | Another function app, another CA credential to hold, and a promotion step that someone must practise. Build it as a documented runbook first |

Facts behind the resilience side: Key Vault is zone-redundant by default, replicates asynchronously to the paired region, and Microsoft may fail a vault over to the paired region ([Microsoft docs](https://learn.microsoft.com/azure/reliability/reliability-key-vault)). The same page says that failover is "likely to occur after a significant delay", the vault is **read-only** afterwards, and **West US 3, Brazil South and Brazil Southeast have no managed cross-region failover at all**. A read-only vault can still serve `Get certificate` and `Get secret`, but it cannot take a new certificate version, so renewal pauses.

## 5. What makes the design resilient?

Because the destination vaults are full copies, applications **keep working when the source vault is unreachable**. Only *new issuance* stops. With a renewal window of up to 30 days before expiry, a source outage of days does not cause an expiry. What happens when something fails:

| Failure | Effect | What protects you | Status |
|---|---|---|---|
| An event is lost or Event Grid is down | A copy lags | The timer sweep (every 15 minutes by default, 5 in the proof of concept) compares thumbprints. Events are a speed-up, not the guarantee. The queue holds a message for 7 days | Sweeps **tested**; the queue path **tested** |
| The sync function is down or throttled | Copies lag | Messages wait in the queue. The Functions host retries a message up to 5 times and then moves it to the `-poison` queue. The sweep repairs the rest | Queue **tested**; the poison behaviour is **Microsoft docs** |
| One destination vault fails | That destination is skipped, the others proceed, and the failure is logged with the certificate name | Per-destination isolation. The queue message is retried by the Functions host every 2 minutes (5 attempts), and the timer sweep repeats the work from scratch | **Tested:** one destination's public access was switched off while a rotation was imported. The other destination had the rotation 20 s later, the broken vault kept serving the previous version, and the sweep logged one failure line. The queued message was retried on the Functions host's schedule and succeeded on its fourth attempt, 160 s after access returned, with no manual step. Permanent-failure paths also **tested** (non-exportable certificate, name collision) |
| The CA is slow or down | The renewal stays pending and is retried on every sweep | The renewal window is `min(30 days, one third of the lifetime)`, so there are weeks of slack. A rate limit (3 renewals in 24 hours) stops a runaway loop | Logic and schedule **tested** against the test CA; DigiCert **not tested** |
| Domain validation (DCV) does not complete | The order stays pending, the certificate ages | Alert on days left at the *copy* (the `replica-expiring` alert) | The alert was **tested** with a 3-day certificate. Domain validation itself was **not tested**. See section 9 |
| Renewal fails and nobody notices | Silent expiry | Three stateful alert rules (one e-mail when each fires, one when it clears): any `failed` or `blocked` result line; no completed sweep from an app for an hour; and a **copy** with fewer than `REPLICA_WARN_DAYS` (default 7) days left although the sync is up to date | **Tested live**, all three fired and cleared by themselves. Timings, and why "cleared" takes tens of minutes, are in the alerting subsection below |
| The source region is lost | No new issuance until Microsoft fails the vault over or you recover | Copies keep serving. Renew early. For West US 3 and unpaired regions there is no managed failover, so put the factory in a region that has one | Microsoft docs |
| Someone deletes a vault or certificate | Loss of a key | Soft delete and **purge protection** (on by default in the module and in the production stack; the proof of concept turned it off on the factory vault so that it could be removed), diagnostics to Log Analytics | Configuration **tested**; purge protection cannot be switched off once on |
| A role assignment is removed | Copies stop | The failure alert fires; the role assignments are in Terraform, so a plan shows the drift | By design |

### Alerting: what was built, how long it takes, and what was not proven

A copy that fails silently is the failure that matters most, so the stack includes three alert rules on the function logs (Terraform `modules/hub/alerts.tf`; they exist only when `alert_email_addresses` is not empty). Every function writes one standard line per outcome (`KVSYNC result=...`, `KVRENEW result=...`), which is what the rules query.

| Rule | Fires when | Why this signal |
|---|---|---|
| `failures` (severity 2, evaluated every 5 min over 15 min) | any `failed-transient`, `failed-permanent`, `blocked-rate-limit` line from either app | A copy or a renewal went wrong. One line per failed destination, with the certificate, destination, error type and reason |
| `heartbeat` (severity 2, one per app, evaluated every 15 min over 1 h) | no `reconcile-complete` line in the last hour | The apps are down, stopped, or cannot write logs. This is the only rule that notices a **dead** function |
| `replica-expiring` (severity 1, evaluated every 15 min over 1 h) | a copy has fewer than `REPLICA_WARN_DAYS` (default 7) days left | The renewal chain is broken *somewhere* (CA, domain validation, a stuck pending request) even though every function is healthy. It is measured at the copy, where the consumer lives |

Why there is no alert on Key Vault's own `CertificateNearExpiry` event: it is emitted at a **fixed 30 days** before expiry. With a 47-day certificate that is 17 days after issuance, so it would fire on every certificate in every cycle. Days left at the copy is the signal that stays meaningful as lifetimes shrink.

**Tested live** (three separate runs, `tests/live/alerts_probe.py`, evidence in [TEST-REPORT.md](TEST-REPORT.md), section 6):

| Run | What was done | Detection | Clear |
|---|---|---|---|
| `failure` | Public access on destination A was switched off and a rotation was imported at the source | Destination B had the rotation in 20 s. The sweep logged `failed-transient` for A at 09:00:01Z and the alert fired at 09:00:57Z, **56 s later**. Destination A kept serving the previous version. The queued message was retried by the Functions host and it converged **160 s** after access returned (the 09:05 sweep found nothing left to do), with no manual step | Resolved 25 min after the fix |
| `heartbeat` | The renewal app was stopped | Fired about **69 min** after the stop (a 1 h look-back plus one 15 min evaluation) | Resolved 45 min after the restart, although the first sweep ran 22 s after it |
| `expiring` | A certificate with 3 days left was imported at the source | Copied to both destinations in about 26 s. The first `replica-expiring` line was logged at 15:58:36Z and the alert fired at 15:59:44Z, **68 s later**. The e-mail arrived at 16:00:53Z | Resolved at 17:45:45Z, **1 h 45 min** after the last warning line (the one-hour look-back plus three clean evaluations) |

**Why "resolved" takes tens of minutes.** These are *stateful* alerts, so Azure sends one notification when they fire and one when they clear. Microsoft documents that a stateful log alert resolves only after the condition has been false for several evaluation periods: three for a 5 to 15 minute frequency, two for 15 minutes to 11 hours ([Create or edit a log search alert rule](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-create-log-alert-rule)). The 15-minute rules here cleared after three, so the boundary value follows the first range. Each of the three runs resolved about a minute after the third clean evaluation. The `failures` and `expiring` rules also look back over a window (15 minutes and one hour), so the last matching line has to age out of it first; the `heartbeat` rule does not, because a new sweep line makes its condition false at once. That is why the measured times differ: 25 minutes after the fix, 45 minutes after the restart and 1 h 45 min after the last warning line. From the rule settings, expect "resolved" 26 to 31 minutes after the last failure line for `failures`, 31 to 46 minutes after the restarted app's first sweep for `heartbeat` (however long it was stopped), and 1 h 31 min to 1 h 46 min after the last warning line for `expiring`. Do not treat a late "resolved" as a failure of the fix. The window and frequency are the `window_duration` and `evaluation_frequency` arguments in `alerts.tf`; shorten them if you want faster clearing and can accept more noise.

**What this does not cover.**

* **The e-mails arrived, but to an address that was never verified, and not in the Inbox.** Each fire and each resolve notification of the three runs was delivered, from `azure-noreply@microsoft.com`: `failures` fired 09:01:05Z (8 s after the alert's recorded start) and resolved 09:27:02Z; `heartbeat` fired 10:04:32Z and resolved 10:50:37Z; `expiring` fired 16:00:53Z (69 s after its recorded start) and resolved 17:45:51Z. The receiver had never been verified. When an address is added to an action group Azure Monitor sends a *verification* message with a one-time passcode, and that message arrived at 08:35:53Z and the code was **not** used. Microsoft documents that the address must be verified within 30 minutes and that "an unverified receiver can't receive alert or test notifications after enforcement is active" ([Action groups](https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups#notification-types)); the action group's test-notification call also answered "There are no valid receivers in the request". So delivery to an unverified address worked on the day of the test, and **should not be relied on**. In the test mailbox every one of the first three tests' messages was later found in *Deleted Items*, while three more (from the migration tests) arrived in the Inbox. This project does not move mail and none of the mailbox's rules matches the sender, so the cause was **not established**. In production: verify the address (or a distribution list) once, allow-list the sender, and prefer a receiver that people actually watch, such as a ticket, a pager or a chat webhook, over a mailbox. "Azure Resource Manager role" e-mail receivers need no passcode. See [OPERATIONS.md](OPERATIONS.md).
* **The poison queue is not monitored.** If the event path throws, the Functions host retries the message (default five attempts) and then moves it to `<queue>-poison`. Nothing watches that queue. The timer sweep is the safety net: it repeats the work from scratch, and **its** failure line is what raises the alert.
* **Short outages heal without an alert, on purpose.** The `failures` rule matches `failed-*` and `blocked-*` lines, and only the timer sweep writes those. The event path writes a `retrying` warning and the Functions host retries the message (every 2 minutes, five attempts). So a destination that comes back before the next sweep finds it broken is repaired silently, which is the right outcome for a blip. Anything that lasts across a sweep raises the alert: in the proof of concept the sweep runs every 5 minutes, so the alert follows within roughly 7 minutes plus log ingestion.
* **A silent monitoring path.** If Log Analytics or the action group itself is broken, none of this reaches a person. The heartbeat covers a dead *app*, not a dead *workspace*. A second, independent signal (for example, the days left on the consumer's certificate) is worth having.
* The alert on an unexpected `SecretGet` (section 6) is not built.

Things that would make it more resilient, and are **not built**: a warm-standby factory in a second region with a practised promotion step; zone-redundant storage for the function apps (`storage_replication_type = "ZRS"` is a variable); monitoring of the `-poison` queue; a dead-letter destination on the event subscription (omitted on purpose, because it needs a blob-write role for Event Grid that cannot be limited to one container, and the timer sweep already covers a lost event); an action group that pages a team rather than e-mails a mailbox.

## 6. Security concerns

Yes, and they are worth stating in the proof of concept. The main ones:

| Concern | Why it matters | In this repo | Still your decision |
|---|---|---|---|
| **The private key is copied** | Each copy is another place a key can leak. Anyone with `getSecret` on a destination can read it | Opt-in per certificate with a tag; the import role cannot read; consumers get *Secrets User* on one secret (see the App Gateway module) | Which vaults get a copy. Keys that must be exportable for PFX consumers (Application Gateway needs this) stay exportable |
| **The sync identity can read secrets in the source vault** | *Certificate User* includes `getSecret`, so by default it could also read the CA credential. The first access audit caught exactly that | An ABAC condition on the role assignment denies names that start with `ca-` (**tested**: the vault answered 403 and the audit log shows it). Optionally `sync_secret_name_prefix` limits the key read to certificate names with a prefix. The factory vault is dedicated to this purpose | Keep unrelated secrets out of the factory vault, or set the prefix. A certificate named `ca-...` can never be synced, by design |
| **Who can opt a certificate in?** | Anyone who can write tags on a source certificate can send its key to every destination | Documented in the runbook | Restrict `certificates/update` on the factory vault; consider an Azure Policy that denies tag writes except for the factory team |
| **The CA API key** | It can order certificates for your validated domains | Stored as a secret in the source vault, read only by the renewal identity under a name-prefix condition. `DIGICERT_ALLOW_NEW_ORDER` is false by default, so the function reissues inside an existing order but never buys. A rate limit caps requests | Scope the DigiCert key as narrowly as DigiCert allows and rotate it. **Check** whether your DigiCert plan supports an IP allow-list |
| **Public network access in the proof of concept** | The lab policy forbids it, so four narrow, time-limited policy exemptions were created | Production uses private endpoints, VNet-integrated apps and no public data plane (`terraform/production`, **plan only, not applied**) | |
| **Telemetry endpoints** | The functions send logs to Application Insights and Log Analytics, and the alert rules query the workspace | In **both** variants these two resources keep their public ingestion and query endpoints, with Entra-only authentication (`internet_ingestion_enabled = true`, `internet_query_enabled = true`, `local_authentication_enabled = false` in `terraform/modules/hub/main.tf`). An Azure Monitor private link scope is **not built** | If your policy forbids public monitoring endpoints, add a private link scope and turn those settings off. **Not tested** |
| **Detection** | A key read by an unexpected caller should be noticed | Audit logs from every vault go to Log Analytics | An alert on `SecretGet` by an unexpected principal is **not built**. Microsoft Defender for Key Vault is a subscription-level plan that this project neither enables nor tests. It was already switched on in the test subscriptions, so it was running during the tests, but nothing here relies on it and nothing exercised it |
| **Cross-subscription roles** | The sync identity holds a role in every destination subscription | The roles are Terraform code and are reviewable | Include the identity in your access reviews |
| **Terraform state** | It holds resource IDs, the Application Insights connection string and role details | Local state is git-ignored | Use a remote backend with Entra authentication and restricted access |
| **Supply chain** | The function code runs with the roles above | Dependencies are pinned by version range; the zip is built from the repo | Protect `main`, review changes, build and deploy from a pipeline using OIDC |

## 7. Consumer test: Application Gateway, and what was not deployed

A Standard_v2 Application Gateway (`terraform/modules/app_gateway`, switched on with `enable_app_gateway = true`) was deployed in destination subscription 2, in North Europe, next to destination vault B. It has its own user-assigned identity with *Key Vault Secrets User* on **one secret**: the copy of the certificate in the regional destination vault. Its HTTPS listener is bound to the **versionless** secret ID. The gateway and that vault are in the same subscription, which is the point of the design: each consumer reads a vault next to it. A cross-subscription reference (possible through ARM or the CLI, not the portal) was **not** tested. Evidence: [TEST-REPORT.md](TEST-REPORT.md), section 5.

| Check | Result |
|---|---|
| The listener serves the certificate that is in the destination vault | **Tested, passed.** The thumbprint presented over TLS 1.3 matched the vault's |
| A rotation at the source reaches the gateway **when its refresh is forced** | **Tested, passed.** The rotation reached the destination vault 187 s after it was started. The listener still served the old certificate, as documented. Pointing the listener at the versioned secret ID and back to the versionless ID made it serve the new certificate **60 s** after the refresh started |
| A rotation reaches the gateway **on its own** | **Not observed.** A second rotation (a CSR signed by the test CA and merged at the source by the probe) reached the destination vault 21 s after the merge. The listener was still on the old certificate at 0, 15, 30, 45, 60, 75 and 91 minutes. The run was meant to last up to five hours, but something outside the test **stopped the gateway at 08:50Z** (the activity log shows a "Stop an application gateway" call from an identity that could not be resolved from this tenant, and the lab runs automation that stops costly resources). The documented poll interval of about four hours ([Key Vault certificates for Application Gateway](https://learn.microsoft.com/azure/application-gateway/key-vault-certs)) was therefore neither confirmed nor refuted |
| Cost | Cost Management recorded about US$0.64 for the gateway's resource group by the evening of the test day (US$0.62 for the gateway, US$0.03 for its virtual network). That matches roughly 25 US cents an hour at list price, plus capacity units, for the hours it ran. The figure is partial because usage posts late. The gateway was removed after the test with `enable_app_gateway = false` |

How to read this: only the first two rows are proof. If you cannot wait up to four hours for a gateway to follow a rotation, make the forced refresh a pipeline step that runs after the copy (the test shows it takes about a minute), or schedule renewals so that the wait fits inside the margin. Also note that lab automation can stop resources: if it stopped the function apps instead, the heartbeat alert is the control that would notice.

Not deployed in the proof of concept (so, not proven):

| Service | Why it matters |
|---|---|
| Azure Front Door | Microsoft: Front Door "currently only supports Key Vault in the same subscription", which is one reason a per-subscription copy is needed. Not tested |
| Private endpoints, private DNS, VNet integration | Required for production; written in `terraform/production`, **plan only** |
| Application Gateway WAF, listeners on real hostnames | The test uses one HTTPS listener and a public backend |
| App Service, API Management, AKS and VM extension consumers | App Service re-syncs imported certificates within 24 hours (Microsoft docs); the others were not tried |
| An alert on an unexpected `SecretGet` (not built); **testing** Microsoft Defender for Key Vault (it was already enabled on the test subscriptions, but this project does not configure it and the tests did not exercise it) | Detection, section 6 |
| A second-region standby factory | Section 4 and 5 |
| Managed HSM | Multi-region replication there covers HSM pools only |
| Azure Firewall / forced tunnelling | Not needed for the test |

## 8. Would a real DigiCert certificate have been the same?

The Key Vault merge, the Event Grid event, the copy, and the Application Gateway pickup do not depend on who signed the certificate. They behave the same. What is different is the CA step: DigiCert needs domain validation, returns a public chain, charges per order, and has its own rate limits and response formats. The renewal function contains a DigiCert client written from DigiCert's documentation and a test client. **The DigiCert client has never run against a live DigiCert account.**

Key Vault's own DigiCert integration (fully automatic) only issues OV and EV certificates. A DV or wildcard-DV certificate, which is what a typical wildcard needs, goes through the CSR path with issuer `Unknown`, which Key Vault does not renew. The renewal function exists for that gap. Details, prices and the cheapest way to test are in [CERTIFICATE-AUTHORITIES.md](CERTIFICATE-AUTHORITIES.md).

**Recommendation (judgment):** yes, do a small second phase with a real certificate. The cheapest honest test is a **reissue** inside an order you already own, because a reissue inside the order term is not charged again. Ask your DigiCert account manager for a non-production container or a low-cost DV order.

## 9. What about 46/47-day certificates?

The CA/Browser Forum ballot SC-081v3 lowers the maximum validity in steps. The Baseline Requirements ceiling reaches **47 days** from 15 March 2029, and DigiCert publishes **46 days** (one day under the ceiling). Both numbers are right; they are two different documents. The steps and sources are in [CERTIFICATE-AUTHORITIES.md](CERTIFICATE-AUTHORITIES.md).

* **Renewal timing: covered.** The window is `min(30 days, one third of the lifetime)`. A 365-day simulation shows no certificate lapsing and exactly one CA request per renewal at 199, 99 and 46 days. At 46 days that is 11 renewals a year, each with at least 16 days of margin.
* **Domain validation: not covered, and it is the real issue.** From 2029 a CA may reuse a domain validation for only 10 days, and DigiCert's documentation says public DV certificates do not support validation reuse. Every renewal then needs a fresh validation, which means publishing a DNS record each time. The function records the validation token DigiCert returns but does **not** publish it. The workable options are to host the zone in Azure DNS and give the renewal identity a narrow role on that zone, or to use DigiCert's ACME service with delegated CNAME validation. Neither is built here.

## 10. Can this be a "Deploy to Azure" button?

**Not for Terraform.** Microsoft: the button deploys "remote ARM JSON templates" and "doesn't support deploying remote Bicep files" ([Use a deployment button](https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-to-azure-button)). Terraform is not an ARM template, so there is no button that runs it.

What the repository offers instead:

1. **Azure Cloud Shell.** It includes preconfigured authentication for Terraform ([Cloud Shell features](https://learn.microsoft.com/azure/cloud-shell/features)), so the steps are: open Cloud Shell, clone the repository, copy `terraform.tfvars.example` to `terraform.tfvars`, fill it in, run `terraform init` and `terraform apply`. This is the closest thing to one click. **Not run**: the lab used a workstation. (A public Cloud Shell cannot apply the private production variant, which needs line of sight to private endpoints.)
2. **GitHub Actions.** `.github/workflows/deploy-poc.yml` is a manually triggered workflow (`workflow_dispatch`) that plans, applies or destroys the proof of concept using OIDC federation, so there is no stored secret, and keeps its state in a storage account. It is **written but never run**, because it needs your repository, an Entra application with a federated credential, a state account and your subscriptions. `.github/workflows/ci.yml` only checks formatting, validates the four Terraform roots and runs the offline tests.
3. **Two variants.** `terraform/poc` is the public-endpoint proof of concept and creates its own resource groups, spoke vaults and optionally an Application Gateway. `terraform/production` assumes private networking that already exists and creates nothing public; it is **validated and planned only**.

A "Deploy to Azure" button for the production variant would not suit anyway: it needs existing subnets, DNS zones and decisions that a form cannot capture.

## 11. Prior art

See [PRIOR-ART.md](PRIOR-ART.md). In short: parts exist (cross-region secret replication samples, a timer-only vault sync, ACME bots that issue into one vault). No public project found does CSR-mode public-CA renewal, merge, and copy to vaults in other subscriptions with the guard rails used here. The search could not cover GitHub code search, so that is not proof that none exists.

## 12. Why not simply share one Key Vault entry across subscriptions?

It is a fair question, and for some situations it is the better answer. A vault can be shared by identities in other subscriptions **of the same tenant** with an ordinary role assignment, and Microsoft's own overview of Key Vault lists "centralize application secrets" as a benefit. The reasons this design copies instead are practical, and each can be checked:

| Complication | What happens | Backing |
|---|---|---|
| **Consumers differ in what they support** | Azure Front Door "currently only supports Key Vault in the same subscription". Application Gateway can reference a vault in another subscription, but only through ARM or the CLI, not the portal | Microsoft docs (section 7) |
| **Identity fan-out** | Every consuming identity in every subscription needs its own role on the shared vault, so every new consumer is a change request to the vault's owner, and the vault's access list grows with the estate | Judgment, from how RBAC works |
| **Network reach** | If the vault has no public access, every consumer network needs a private endpoint to it and the DNS to match. Across regions that is a cross-region dependency for each consumer | Judgment |
| **Regional coupling** | A vault is regional. It is zone-redundant and replicated to the paired region, but failover is Microsoft-initiated, "likely to occur after a significant delay", and read-only afterwards. West US 3, Brazil South and Brazil Southeast have no managed cross-region failover | Microsoft docs (section 4) |
| **Blast radius** | One vault is one permission and deletion domain for every consumer. The Cloud Adoption Framework says: "Don't use centralized instances of Key Vault for application keys or secrets, unless utilizing a Managed HSM instance" ([Encryption and key management](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/design-area/encryption-and-keys#design-considerations)) | Microsoft docs |
| **Throttling** | Limits apply per vault and per region: 4,000 transactions in 10 seconds for most operations, and 300 in 10 seconds shared by secret create, certificate import and key import. The subscription-wide cap is five times the per-vault limit ([service limits](https://learn.microsoft.com/azure/key-vault/general/service-limits)). A rotation that makes hundreds of consumers refresh at the same moment spends one budget | Microsoft docs |
| **Tenant boundary** | A managed identity belongs to one tenant, and sovereign clouds are separate environments. Sharing across tenants needs a different identity design. **Neither the shared-vault approach nor this repo's copy was tested across tenants** | Judgment |
| **Backup and restore do not help** | A backup can be restored only into a vault in the same subscription and geography | Microsoft docs (section 1) |

**What the copy trades for this.** The copy puts a key in more places, adds a function you have to run, watch and patch, and makes the copies eventually consistent (seconds to a few minutes in the tests). In return no consumer needs an identity outside its own subscription, no consumer depends on another region's vault, and services that insist on a same-subscription vault work. Sharing one vault does not remove the need for the same care. It moves the cost into role assignments, private networking and a larger blast radius.

**When you should share one vault instead.** One tenant, one or two regions, few consumers, all of them services that can read a vault in another subscription, and a team that will own the vault's access list. In that case this repo adds nothing you need.

## 13. Which lifecycle events can a serverless function automate?

All of them can be triggered by a function. The question is which ones are worth automating and which were actually built and run here.

| Lifecycle event | Automatable? | In this repo | Evidence |
|---|---|---|---|
| A new certificate version appears in the source vault (import, merge, renewal) | Yes: Key Vault emits `CertificateNewVersionCreated`, which a function receives through Event Grid and a queue | Built: copy to every destination, byte-for-byte check, idempotent | **Tested.** Copies appeared 2 to 43 s after a merge, 9 s and 2 s after a rotation, and 19 s after a PFX import |
| The event is lost or the function was down | Yes: a timer sweep compares thumbprints | Built | **Tested.** Opt-in added after the event was picked up in 3.5 min (5-minute sweep); destination outage healed in 160 s |
| A certificate must be renewed | Yes, **when the CA is called by the function**. Key Vault renews only issuers it integrates with, and its DigiCert integration covers OV and EV certificates | Built: order from the CA, merge into the pending request, one order per renewal, rate limit | **Tested** with a test CA (merge in 122 s; forced rotation in 253 s). **The DigiCert client has never run live** |
| A pending certificate request (CSR) must be merged | Yes. Key Vault does not merge a CSR on its own | Built, same function | **Tested**; an untagged pending request stays untouched |
| An operator needs to rotate now (key compromise) | Yes: a one-shot tag | Built (`kvrenew-now`) | **Tested** (no rotation loop afterwards) |
| Domain validation (DNS TXT) before issuance | Yes, with Azure DNS and a narrow role on the zone, or the CA's ACME or "DNS persist" feature | **Not built** | Not tested. It is the work that matters most for short-lived certificates (section 9) |
| A failure, or a silent function | Yes: alert rules on the function logs | Built: three rules | **Tested** (all three fired and e-mailed; the address was unverified and the mails landed in Deleted Items, see section 5) |
| A consumer must pick up the new version | Partly. Some consumers poll (Application Gateway, about every four hours), some need a refresh call | The test script forced the refresh. **No function does it** | **Tested** with a script (about 60 s). Unaided pickup **not observed** |
| Revocation after a compromise | Technically yes (CA API). Wise to automate? Not without a person in the loop | **Not built** | |
| Removing copies when the source is deleted or opted out | Yes, but destructive | **Not built, by design.** The sync never deletes anything | Documented in the runbook |
| Finding certificates that live outside Key Vault (devices, VMs, certificates loaded by hand) | Not with this design | **Not built** | |

Guard rails that apply to anything a function does automatically: it should only act on objects that opted in (a tag), never overwrite what it did not create, rate-limit anything that costs money, and be unable to buy a new certificate by default (`DIGICERT_ALLOW_NEW_ORDER` is false). Those four are built and were exercised.

Platform notes: Azure Functions **Flex Consumption**, which this stack uses, "isn't available there yet" in Azure Government according to Microsoft's migration guidance ([Migrate Consumption plan apps to the Flex Consumption plan](https://learn.microsoft.com/azure/azure-functions/migration/migrate-plan-consumption-to-flex#what-to-expect)), so a Government deployment needs another hosting plan. That was not tested.
