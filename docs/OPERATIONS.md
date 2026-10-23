# Operating the certificate factory

For the team that runs the factory after it is deployed. It lists what runs, every setting and tag, what the log lines mean, what the alerts do, what it costs, the routine jobs, and what to check when something is wrong. Settings are shown by their Terraform variable. The ARM templates differ in a few places, listed in [ARM templates](#arm-templates). The reasoning behind the design is in [DESIGN-QA.md](DESIGN-QA.md). The evidence is in [TEST-REPORT.md](TEST-REPORT.md). The steps to put it into an existing estate are in [CUSTOMER-RUNBOOK.md](CUSTOMER-RUNBOOK.md).

Wherever this page says **tested**, the behaviour was seen in the proof of concept (see the test report). Wherever it says **documented** or **read from the code**, it was not exercised.

1. [What runs](#what-runs)
2. [Settings](#settings)
3. [Tags on certificates](#tags-on-certificates)
4. [Reading the logs](#reading-the-logs)
5. [Alerts](#alerts)
6. [Cost](#cost)
7. [Routine jobs](#routine-jobs)
8. [Troubleshooting](#troubleshooting)
9. [Recovering the factory](#recovering-the-factory)
10. [ARM templates](#arm-templates)

## What runs

| Component | Name (your `suffix` replaces `<suffix>`) | What it does |
|---|---|---|
| Factory vault (the source) | `kv-src-<suffix>` | Holds the certificates that are issued or renewed, and the CA credential (secrets whose names start with `ca-`). Publishes Event Grid events. Purge protection is **on by default** (`source_purge_protection_enabled`; the proof of concept turned it off so that it could be torn down, and it cannot be switched off once on). Soft-delete retention is 7 days |
| Sync function app | `func-kvsync-<suffix>` | Copies a certificate and its private key to every destination vault. Two triggers: a queue message (fast) and a timer sweep (the guarantee). Python 3.12 on Flex Consumption |
| Renewal function app | `func-kvrenew-<suffix>` | For certificates whose issuer is `Unknown` (CSR mode): creates the new pending version, orders it at the CA, polls, checks the chain, merges it. Same two triggers. It never touches a destination vault and never reads a private key |
| Event Grid system topic | `evgt-kv-src-<suffix>` | Sends the source vault's certificate events to one storage queue per app (`kvsync-events`, `kvrenew-events`). A queue message lives 7 days |
| Storage account per app | `stkvsync<suffix>`, `stkvrenew<suffix>` | The queue, the host's own files, and (renewal only) the table `kvrenew` with the order records. Shared-key access is off: the apps use their identity |
| Identities | `uami-kvsync-<suffix>`, `uami-kvrenew-<suffix>` | One user-assigned identity per app. What each may do is in [DESIGN-QA.md](DESIGN-QA.md), section 2 |
| Log Analytics and Application Insights | `log-kvsync-<suffix>` | Function logs, and the audit log of the source vault and of every destination vault |
| Alert rules and action group | `alert-kvsync-*`, `alert-kvrenew-*`, `ag-kvsync-<suffix>` | Created only when `alert_email_addresses` is not empty. Required in the production stack |
| Destination vaults | yours | Not created here. The factory adds a role assignment and a diagnostic setting to each |

The deployed ingest path is *Event Grid, then a storage queue, then the function*. It is used because it works when the function app has no public endpoint. `INGEST_MODE=eventgrid` (a direct Event Grid trigger) exists in the code and was **not** exercised.

## Settings

Settings are shown by their Terraform variable; the ARM templates take the same settings as parameters ([the mapping](#parameters-and-their-terraform-variables)). Change the variable or the parameter and apply or deploy again. Do not edit app settings in the portal: the next apply overwrites them, and a redeployment of an ARM template is expected to do the same (not tested).

### Sync app

| Setting | Default | Meaning |
|---|---|---|
| `SOURCE_VAULT_URI` | set by Terraform | The factory vault |
| `DEST_VAULTS_JSON` | set from `destinations` | A JSON list of `{key, uri}`. The keys are what a `kvsync` tag can name |
| `KVSYNC_CLIENT_ID` | set by Terraform | Client ID of the sync identity |
| `INGEST_MODE` | `queue` | `queue` or `eventgrid` |
| `RECONCILE_SCHEDULE` | `0 */15 * * * *` | The sweep, as a six-field NCRONTAB expression. Variable `reconcile_schedule`. The proof of concept sets `0 */5 * * * *` |
| `SYNC_QUEUE_NAME` | `kvsync-events` | |
| `REPLICA_WARN_DAYS` | `7` | A copy with fewer days left than this logs `replica-expiring`. Set through `sync_settings = { REPLICA_WARN_DAYS = "10" }` |
| `QueueConn__*`, `AzureWebJobsStorage__*` | set by Terraform | Identity-based connection to the app's storage account |
| `APPLICATIONINSIGHTS_CONNECTION_STRING`, `APPLICATIONINSIGHTS_AUTHENTICATION_STRING` | set by Terraform | Telemetry, signed in with the identity |

### Renewal app

Set the ones below through the `renew_settings` map (all values are strings).

| Setting | Default | Meaning |
|---|---|---|
| `CA_PROVIDER` | variable `ca_provider` | `digicert` or `testca` (a throw-away CA kept in the vault, for tests only) |
| `RENEW_SCHEDULE` | `0 */15 * * * *` | The sweep. Variable `renew_schedule` |
| `CA_SECRET_NAME` | `ca-digicert-api-key` | The secret that holds the CA's API key. The prefix is variable `ca_secret_name_prefix` (`ca-`) |
| `TESTCA_SECRET_NAME` | `ca-testca-bundle` | The same, for the test CA |
| `RENEW_DAYS_BEFORE_EXPIRY` | `30` | A certificate is due when it has at most this many days left, but never later than **one third of its lifetime** (plus 0.05 days of slack). A 47-day certificate is therefore due with 15.7 days left |
| `RENEW_MIN_AGE_HOURS` | `24` | A version younger than this is not renewed again (stops a loop). `kvrenew-now` skips this check |
| `RENEW_MAX_PER_24H` | `3` | CA requests per certificate in 24 hours. Past it the result is `blocked-rate-limit`. `kvrenew-now` does **not** skip this |
| `RENEW_POLL_SECONDS` | `90` | How long one run waits for the CA before it returns and tries again on the next sweep |
| `RENEW_POLL_INTERVAL` | `10` | Seconds between polls |
| `RENEW_MAX_WAIT_HOURS` | `72` | After this long, a still-pending order is logged at WARNING instead of INFO (it is **not** cancelled and does **not** raise the failure alert) |

DigiCert-specific settings, all through `renew_settings` (**read from the code; the DigiCert client has never run against a live DigiCert account**):

| Setting | Default | Meaning |
|---|---|---|
| `DIGICERT_PRODUCT` | none, required | The product name ID, for example a DV or wildcard product |
| `DIGICERT_API_BASE` | `https://www.digicert.com/services/v2` | |
| `DIGICERT_ORGANIZATION_ID`, `DIGICERT_CONTAINER_ID` | none | Needed for a new order |
| `DIGICERT_ORDER_YEARS` | `1` | |
| `DIGICERT_CERT_VALIDITY_DAYS` | none | |
| `DIGICERT_DCV_METHOD` | none | Domain validation method |
| `DIGICERT_PAYMENT_METHOD` | none | |
| `DIGICERT_SERVER_PLATFORM_ID` | `2` | |
| `DIGICERT_REISSUE` | `true` | Reissue inside an order you already own |
| `DIGICERT_ALLOW_NEW_ORDER` | `false` | Off by default, so the function never buys a certificate. A reissue needs the order ID in the `kvrenew-order-id` tag the first time |
| `DIGICERT_SKIP_APPROVAL` | `false` | |

Test CA only: `TESTCA_DAYS` (default 90) and `TESTCA_DELAY_SECONDS` (default 0, to simulate a slow CA).

## Tags on certificates

Everything is driven by tags on the certificate **in the factory vault**. A tag change fires no Key Vault event, so the next timer sweep picks it up (up to one sweep period).

| Tag | Value | Meaning |
|---|---|---|
| `kvsync` | `all` or a comma-separated list of destination keys | Copy this certificate. Without it, nothing is copied |
| `kvrenew` | `on`, `true`, `1` or `yes` | The renewal app may renew this certificate (issuer must be `Unknown`) |
| `kvrenew-days` | a number | Renewal window for this certificate, instead of `RENEW_DAYS_BEFORE_EXPIRY`. Still capped at one third of the lifetime |
| `kvrenew-now` | any value | One shot: rotate on the next sweep, even if not due. The app removes it, so the pending request and the merged version never carry it. **Tested** (merged 253 s after the tag in the proof of concept) |
| `kvrenew-order-id` | a CA order ID | The existing CA order to reissue on the first request |

A copy carries `kvsync-origin` (the source vault's name), `kvsync-source-version` and `kvsync-synced-utc`, and **never** `kvsync` or any `kvrenew*` tag, so a copy cannot be copied again or renewed. A certificate that already exists in a destination without `kvsync-origin` is never overwritten. To let the sync take it over, set `kvsync-origin=<source vault name>` on it (**tested**). The next sweep then writes the factory's version into it, and the older version stays as an older version. **Adopting replaces the whole certificate policy** (**tested**: a certificate with issuer `Self` and an auto-renew action became issuer `Unknown` with the lifetime action `EmailContacts` at 80%), so Key Vault stops renewing it there. Adopt only when the factory certificate exists and is renewed. Expect one `failed-permanent` line, and therefore one `failures` alert, between creating the factory certificate and tagging the destination one.

## Reading the logs

Every outcome is one line in `AppTraces`, starting with `KVSYNC` or `KVRENEW`, then `key=value` pairs. Most carry `cert=`; copies carry `dest=`, `thumb=` and `days_left=`.

### `KVSYNC result=...`

| Result | Level | Meaning | What to do |
|---|---|---|---|
| `copied` | info | A new version was imported at the destination and checked byte for byte (`verified=cert-bytes-identical`) | Nothing |
| `converged-noop` | info | The destination already has this version | Nothing |
| `retrying` | warning | The event path failed and the Functions host will retry the message (default 5 attempts) | Nothing yet. A permanent problem shows up as a `failed-*` line from the next sweep |
| `failed-transient` | error | A destination or Key Vault call failed (network, throttling, a role not yet propagated, a thumbprint mismatch during a rotation). One line per failed destination | The sweep repeats the work. Check `error=` and `msg=`. This raises the `failures` alert |
| `failed-permanent` | error | The copy cannot succeed as it is: the policy is **not exportable**, the destination holds an **unmanaged certificate** of that name, or it is a replica of **another** source vault | Fix the cause (see [Troubleshooting](#troubleshooting)). Raises the `failures` alert |
| `replica-expiring` | warning | A copy has fewer than `REPLICA_WARN_DAYS` days left although the sync is up to date | The renewal chain is stuck. Raises the `replica-expiring` alert |
| `near-expiry` | warning | Key Vault's own near-expiry event arrived. It fires a fixed 30 days before expiry and cannot be changed | Informational. No alert is built on it, because on a 47-day certificate it would fire on every certificate in every cycle |
| `skipped-not-opted-in`, `skipped-disabled`, `skipped-loop-guard`, `skipped-pending` | info | The certificate has no `kvsync` tag, is disabled, is itself a copy, or is a pending request that has not been merged | By design |
| `skipped-no-targets`, `skipped-not-found`, `config-warning` | warning | The tag names a destination key that does not exist, the certificate vanished, or the tag selects unknown destinations | Correct the tag or `destinations` |
| `ignored` | info, or warning | An event that is not about a certificate (info), or that does not come from the source vault (warning) | Nothing, unless the warning repeats: then something else publishes to the topic |
| `reconcile-complete` | info | A timer sweep finished (`seen=`, `failures=`). **The heartbeat alert counts these lines** | Nothing |

### `KVRENEW result=...`

| Result | Level | Meaning | What to do |
|---|---|---|---|
| `not-due` | info | Outside the renewal window (`days_left=`, `window_days=`) | Nothing |
| `started` | info | A new pending version with a **new key** was created | Nothing |
| `ordered` | info | The CSR was sent to the CA (`order=`, `kind=`) | Nothing |
| `waiting` | info, then warning | The CA has not issued it yet. The next sweep polls again. After `RENEW_MAX_WAIT_HOURS` the level becomes WARNING | Look at `detail=`, usually domain validation. **No alert fires for this line.** The `replica-expiring` alert is the backstop |
| `merged` | info | The signed chain was checked (it belongs to the key Key Vault made, covers every requested name, is valid now) and merged. The copy follows within seconds | Nothing |
| `busy` | info | Another run holds the lease for this certificate (leases last 10 minutes) | Nothing |
| `not-opted-in`, `skipped-replica`, `nothing-to-renew`, `not-found` | info | No `kvrenew` tag, a copy, nothing to renew, or the certificate is gone | By design |
| `skipped-too-new` | warning | The current version is younger than `RENEW_MIN_AGE_HOURS` | Wait, or use `kvrenew-now` |
| `skipped-managed-issuer` | info | The issuer is not `Unknown`, so Key Vault renews this one itself | By design |
| `blocked-rate-limit` | error | `RENEW_MAX_PER_24H` requests were already started in 24 hours for this certificate | A person must look. Something is looping or the CA keeps rejecting. Raises the `failures` alert |
| `failed-permanent` | error | The CA rejected the order, the chain does not match, or an earlier order for this request failed | Read `msg=`. To start over, delete the pending request (`az keyvault certificate pending delete`); the next sweep creates a new one (it counts toward the 24-hour limit) |
| `failed-transient` | error | A CA outage, a Key Vault `403`, a storage error | Retried on the next sweep. Raises the `failures` alert |
| `reconcile-complete` | info | A sweep finished, with a count per result (`not_due=2 failures=0`). **The renewal heartbeat counts these** | Nothing |

### Queries that were run against the proof of concept

Save these in Log Analytics. All five **ran and returned rows** in the proof of concept.

Last result per certificate:

```kusto
AppTraces
| where Message startswith "KVSYNC " or Message startswith "KVRENEW "
| extend app = tostring(split(Message, " ")[0]),
         result = extract(" result=([a-z-]+)", 1, Message),
         cert = extract(" cert=([^ ]+)", 1, Message)
| where isnotempty(cert) and result !in ("ignored", "config-warning")
| summarize arg_max(TimeGenerated, result) by app, cert
| project TimeGenerated, app, cert, result
| order by TimeGenerated desc
```

A deleted certificate keeps showing its last line until it ages out of the workspace retention. Read the time column.

Failures:

```kusto
AppTraces
| where Message contains "result=failed" or Message contains "result=blocked"
| project TimeGenerated, Message
| order by TimeGenerated desc
```

Are the sweeps running? (This is what the heartbeat rule counts.)

```kusto
AppTraces
| where Message contains "result=reconcile-complete"
| extend app = tostring(split(Message, " ")[0])
| summarize last_sweep = max(TimeGenerated), sweeps = count() by app
```

Days left on every copy, soonest first:

```kusto
AppTraces
| where Message contains "result=copied" or Message contains "result=converged-noop"
| extend cert = extract(" cert=([^ ]+)", 1, Message),
         dest = extract(" dest=([^ ]+)", 1, Message),
         days_left = todouble(extract(" days_left=([0-9.]+)", 1, Message))
| summarize arg_max(TimeGenerated, days_left) by cert, dest
| order by days_left asc
```

Who reads secrets (a certificate's private key is the secret of the same name), and how often it was refused:

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| summarize reads = count(), denied = countif(httpStatusCode_d >= 400)
    by Resource, CallerIPAddress, identity_claim_oid_g
| order by reads desc
```

Expect the sync identity (and only it) on the factory vault. The caller address changes between runs on Flex Consumption. In private mode it is a private address.

`scripts/la_query.py --workspace <workspace id> --timespan PT12H --query "<KQL>"` runs a query from a terminal. The workspace ID is the Terraform output `log_analytics_customer_id` (the proof-of-concept ARM template has an output of the same name; the production one calls it `logAnalyticsCustomerId`). Column names such as `first` and `last` are reserved: use `t0` and `t1`.

## Alerts

Three rules, all on the function logs, all **stateful** (one message when the rule fires, one when it clears). Terraform: `modules/hub/alerts.tf`. ARM: the alerting section of `deploy/modules/hub.bicep`. On the two live proof-of-concept stacks the rules matched in frequency, window, severity and query text (the line endings aside).

| Rule | Severity | Look-back and frequency | Fires when |
|---|---|---|---|
| `failures` | 2 | 15 min, every 5 min | Any `failed-transient`, `failed-permanent` or `blocked-rate-limit` line from either app |
| `heartbeat` (one per app) | 2 | 1 h, every 15 min | No `result=reconcile-complete` line in the look-back: the app is stopped, throttled, or cannot write logs |
| `replica-expiring` | 1 | 1 h, every 15 min | Any `replica-expiring` line: a copy has fewer than `REPLICA_WARN_DAYS` days left |

Measured in the proof of concept (full timings in [TEST-REPORT.md](TEST-REPORT.md), section 6):

| | Time to fire | Time to clear |
|---|---|---|
| `failures`, after breaking a destination | **56 s** after the first failed sweep line | 25 min after the fix |
| `heartbeat`, after stopping the renewal app | about 69 min after the stop | 45 min after the restart |
| `replica-expiring`, after copying a 3-day certificate | **68 s** after the first warning line | **1 h 45 min** after the last warning line |

**Why clearing is slow.** Microsoft documents that a stateful log alert resolves only after the condition has been false for several evaluation periods. In all three runs the alert resolved about one minute after the **third** clean evaluation. The `failures` and `replica-expiring` rules first have to wait for the last matching line to leave the look-back; `heartbeat` does not, because a new sweep line makes its condition false at once. From the rule settings that gives **26 to 31 minutes after the last failure line** for `failures` (measured: 27), **31 to 46 minutes after the restarted app's first sweep** for `heartbeat` (measured: 44) and **1 h 31 min to 1 h 46 min after the last warning line** for `replica-expiring` (measured: 1 h 45 min, the long end). The spread is where the evaluation grid happens to fall. The count of three is documented: for a log search alert with a frequency of 5 to 15 minutes, Azure Monitor resolves it when the condition has not been met for three frequency periods (two periods for 15 minutes to 11 hours, and the rules here, at exactly 15 minutes, behaved like the first row; [What are Azure Monitor alerts?](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview#alerts-and-state)). The one-minute offset is what was observed. A late "resolved" does not mean the fix failed. To change it, edit `window_duration` and `evaluation_frequency` in `alerts.tf`. To make a rule less twitchy, raise `number_of_evaluation_periods` and `minimum_failing_periods_to_trigger_alert` in its `failing_periods` block. In the ARM templates the same four settings are `windowSize`, `evaluationFrequency`, `numberOfEvaluationPeriods` and `minFailingPeriodsToAlert` in `hub.bicep`; recompile after editing (see [ARM templates](#arm-templates)).

**What is not covered.**

* **A stuck order raises no alert until the copy is nearly dead.** `waiting` is not a failure line. The `replica-expiring` alert is the backstop, and it fires at `REPLICA_WARN_DAYS` (7 by default). With 47-day certificates the renewal window is 15.7 days, so a validation that never completes is noticed about 8 days into it. Raise `REPLICA_WARN_DAYS` if you want it sooner.
* **A short outage heals without an alert, on purpose.** Only the timer sweep writes `failed-*` lines. The event path retries by itself.
* **The poison queue is not monitored.** If the event path keeps failing, the message moves to `kvsync-events-poison` or `kvrenew-events-poison` and nothing watches it. The sweep repeats the work, and its failure line raises the alert.
* **A dead workspace or action group is silent.** The heartbeat covers a dead app, not a dead monitor.

**First-run noise.** Expect a Sev 2 heartbeat message in the first hour after a deployment: the rules are created before the apps have logged a first sweep. **Seen** on the production ARM stack, where both heartbeats fired before any sweep had run. On the proof of concept the sync app's alert fired 7 minutes after its rule was created, 77 s after the first sweep line had reached the workspace, and the cause was **not established**. All four heartbeat alerts of the two stacks stayed open for 46 minutes (three 15-minute periods, plus a minute), the clearing rule described above. The `failures` rule also matches `failed-permanent`, so the deliberate failures of the edge-case test raise it, and it cleared about 31 minutes after the last failure line (15 minutes in its window plus three 5-minute periods; seen twice). Read the `KVSYNC` and `KVRENEW` lines before you treat either as an outage ([TEST-REPORT.md](TEST-REPORT.md), sections 10 and 11).

### E-mail receivers

* **Verify the address.** When an address is added to an action group Azure Monitor sends a verification message with a one-time passcode. Microsoft: it "must be verified through a one-time passcode (OTP) within 30 minutes of saving the action group", the verification "persists across all past and future action groups within the same tenant", and "an unverified receiver can't receive alert or test notifications after enforcement is active" ([Action groups](https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups#notification-types)). If the passcode expires, open the action group and select **Resend**. "Azure Resource Manager role" receivers need no passcode.
* **In the proof of concept the address was never verified, and the notifications were still delivered**, so enforcement was not active on that tenant that day. The action group's test-notification call refused with "There are no valid receivers in the request". Do not rely on it.
* **Allow-list the senders** `azure-noreply@microsoft.com`, `azureemail-noreply@microsoft.com` and `alerts-noreply@mail.windowsazure.com`, and check mailbox rules ([Troubleshooting Azure Monitor alerts](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-troubleshoot)). In the proof of concept the notifications of the first three tests, and the other Azure Monitor messages of that day, were later found in *Deleted Items*; three sent hours afterwards were in the Inbox. The cause was not established (no mailbox rule matched the sender). Do not assume where a notification lands: raise a harmless alert on purpose after you set the receiver up and see where it arrives.
* **Prefer a receiver that people watch**: an ITSM connector, a webhook or Logic App into a chat or ticket queue, an SMS or voice receiver, or the on-call tool. Add individual addresses to a group instead of a distribution list: one "unsubscribe" removes everyone.

## Cost

**Measured in the proof of concept** (Cost Management, actual cost in US dollars, the three resource groups of the test, as read on the evening of the test day; usage posts late, so the final numbers are a little higher). The stack was about 14 hours old and included heavy test runs:

| Resource group | Total | Largest items |
|---|---|---|
| Factory hub (vault, two function apps, storage, Event Grid, Log Analytics, alerts) | **US$0.21** | Log Analytics 0.145 (53 MB ingested), Functions 0.021 (810 GB-seconds), Defender for Cloud 0.014, storage 0.017, alert rules 0.009, Key Vault 0.005, Event Grid 0.000 |
| Each destination vault | US$0.004 | Defender for Cloud and Key Vault operations |
| Application Gateway test (removed afterwards) | US$0.64 | The gateway 0.62, its virtual network 0.03 |

Two things the numbers show. First, **neither free grant was applied in the test subscription**: Log Analytics was charged for all 53 MB (about US$2.74 per GB) and Functions for all 810 GB-seconds (US$0.000026 each). Price it without the grants. Second, Defender for Cloud plans that were already on in the subscription (they are not set by this project) added a small charge.

**Estimate for a month at list price** (an estimate, not a bill). Assumptions: 5-minute sweeps as in the proof of concept, about 1.4 MB of logs an hour (measured over the quiet hours), the eight private endpoints of `terraform/production`, and no CA charges.

| Item | Proof of concept (public) | Production (private, 15-minute sweeps) |
|---|---|---|
| Log Analytics ingestion | about US$3 | about US$1.50 (assumes half the volume) |
| Function executions | about US$1 to 2 | under US$1 |
| Storage operations | under US$1 | under US$0.50 |
| Key Vault operations | about US$0.25 | about US$0.10 |
| Alert rules (US$0.50 a month at 15 min, US$1.50 at 5 min) | about US$3 | about US$3 |
| **Eight private endpoints** (US$0.01 per hour each) | none | **about US$58** |
| **Total** | **about US$8** | **about US$64** |

Production is dominated by the private endpoints: one for the factory vault, two for each app's storage (blob, queue), one for the renewal table, one for each app's management endpoint. Data processing through them is extra and was not priced. A firewall or NAT gateway for the renewal app's outbound call to the CA is not included. Reuse the private DNS zones you already have.

**The ARM templates** build the same resources, without the optional Application Gateway, so this estimate is expected to apply. **No cost was measured on an ARM deployment.** Their defaults match Terraform's: 30 days of logs and LRS storage in the proof of concept, 90 days and ZRS in the production template.

**Not known.** Key Vault bills a "Certificate Renewal Request" meter at US$3.00 each. Whether it applies to a renewal that goes through the CSR path, as this factory's does, is **unconfirmed**; ask Key Vault billing before you count on it either way. And the certificates themselves cost whatever your CA charges.

## Routine jobs

Where a job below says *apply*, the ARM route deploys the template again. The jobs that differ are in [ARM templates](#changing-settings-and-code).

**Opt a certificate in.** Add `kvsync=all` (or `kvsync=<key>,<key>`). Add `kvrenew=on` if the factory should renew it. The copy appears at the next event, or at the next sweep.

**Opt a certificate out.** Remove the tag. Copies already made stay where they are. Delete them yourself if they should go.

**Force a rotation** (key compromise, a drill). Set `kvrenew-now=1` on the certificate. The next renewal sweep rotates it. The rate limit still applies.

**Add a destination vault.** Add it to `destinations` in your `terraform.tfvars` and apply. Terraform adds the role assignment and the audit diagnostic setting; the next sweep copies every opted-in certificate there. Key Vault allows 300 certificate imports per 10 seconds per vault and region ([service limits](https://learn.microsoft.com/azure/key-vault/general/service-limits)), so onboard a large estate in waves. Not tested beyond three vaults.

**Remove a destination vault.** Remove it from `destinations` and apply. The roles go; the copies stay.

**Rotate the CA credential.** Write a new version of the `ca-...` secret in the factory vault. The renewal app reads the latest version on every use, so no restart is needed (**read from the code**).

**Change a schedule or a threshold.** Change `reconcile_schedule`, `renew_schedule`, `sync_settings` or `renew_settings` and apply.

**Change the code.** Edit `src/`. The next plan shows the `deploy` step as a replacement (it is triggered by the hash of the zip) and applies a remote build.

**Check on a certificate.** Run the "last result per certificate" and "days left on every copy" queries. Compare the thumbprints:

```bash
az keyvault certificate show --vault-name <source> --name <cert> --query x509ThumbprintHex -o tsv
az keyvault certificate show --vault-name <destination> --name <cert> --query x509ThumbprintHex -o tsv
```

## Troubleshooting

| Symptom | Likely cause | What to check, and the fix |
|---|---|---|
| A tagged certificate is not in a destination | Not yet swept, still pending, disabled, or the tag names a key that does not exist | Look for `skipped-*`, `config-warning` and `failed-*` lines for the certificate. A tag change waits for the next sweep |
| `failed-permanent`: "policy is not exportable" | The certificate was created with a non-exportable key, so the key cannot be read from the vault | **Tested.** Create or import the certificate with an exportable key, or remove `kvsync` |
| `failed-permanent`: "destination already holds an unmanaged certificate" | A certificate of that name already exists in the destination and was not made by this factory | **Tested.** It is never overwritten. Rename one, or adopt it with `kvsync-origin=<source vault name>`. Adopting replaces its policy and Key Vault stops renewing it there (see [Tags on certificates](#tags-on-certificates)) |
| `failed-permanent`: "is a replica of ..." | Two factories copy the same name into one destination | Give each certificate one owning factory |
| A certificate named `ca-...` is never copied | By design: the sync identity is refused every secret that starts with `ca-` (the vault answered `403`, **tested**) | Rename the certificate |
| `failed-transient` for one destination, the rest are fine | The destination's firewall or private endpoint, a role not yet propagated (allow about 10 minutes), or throttling | **Tested** (public access switched off at one destination: the others were unaffected and it converged by itself 160 s after access returned). Check `error=` and `msg=` |
| A copy fails with `409 Conflict` ("is currently in a deleted but recoverable state") | A certificate of that name was deleted from the destination. Key Vault keeps a soft-deleted object reserved, whether purge protection is on or not, until it is recovered or purged ([Soft-delete](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)). With purge protection on it cannot be purged before the retention period ends | **Tested twice** (`ResourceExistsError`, inner code `ObjectIsDeletedButRecoverable`; the other destination was unaffected). The event path logs `retrying` (WARNING). The timer sweep logs `failed-transient` (ERROR) every sweep for as long as the copy stays deleted, and the `failures` alert fired 56 s after the first such line. After a recovery the copy converged by itself, 157 s later in one run and 15 s in the other (the host's retry of the queue message). After five failed attempts, about 10 minutes, that message goes to the `-poison` queue, which nothing watches, and only the sweep still tries. Recover it: `az keyvault certificate recover --vault-name <destination> --name <cert>`. The identities of this factory cannot purge. If nobody wants a copy there any more, take that destination out of the `kvsync` tag at the factory, or the sync keeps trying and the `failures` alert keeps firing |
| `429` from Key Vault during a large first sync | The limit of 300 certificate imports per 10 seconds per vault | The sweep retries (`failed-transient`). Add destinations or certificates in waves |
| `blocked-rate-limit` | Three requests were started for one certificate in 24 hours | Find out why (a CA that keeps rejecting, a loop). The counter clears as entries age out of the 24 hours. `kvrenew-now` does not bypass it |
| Order stuck at `waiting` | Domain validation is not complete, the CA needs an approval, or the order is paid for another way | Read `detail=`. Complete it at the CA. Not tested against DigiCert |
| `failed-permanent` again on every sweep for the same order | An order that failed earlier is not retried for the same request | Delete the pending request in the factory vault. The next sweep makes a new one |
| Renewal never starts | No `kvrenew` tag, outside the window, the issuer is not `Unknown`, or the version is younger than `RENEW_MIN_AGE_HOURS` | Read the `KVRENEW` result for the certificate |
| No log lines at all | The app is stopped, or it cannot reach Application Insights | The heartbeat alert fires about an hour later. Read the app's state from Azure Resource Manager: `az functionapp show` shows an empty `state` for Flex Consumption apps. Use `az rest --method get --url "https://management.azure.com/<app id>?api-version=2024-04-01"` and read `properties.state` |
| An alert fired but no mail came | Address not verified, sender filtered, or a mailbox rule | See [E-mail receivers](#e-mail-receivers) |
| `terraform destroy` of a resource group refuses to delete | A policy created resources inside it (the test lab added alert rules) and the provider's `prevent_deletion_if_contains_resources` safeguard is on | Remove those resources, then destroy. **Leave the safeguard on** |
| A command with `&` in a URL is cut short | `&` ends a command in `cmd.exe`, and PowerShell hands `az.cmd` an unquoted argument, so quotes do not help (seen in the lab) | Do not put `&` in the URL: `az rest --method get --url "<url without the query>" --url-parameters api-version=2019-05-05-preview timeRange=1d` (**tested**), or call the API from a script |
| An ARM production deployment runs for about 12 minutes and fails with `ServiceAssociationLink ... Please check if 'Microsoft.App' is registered` | The `Microsoft.App` resource provider is not registered in the subscription, and the VNet integration of the function apps needs it | **Seen** on the first production attempt. `az provider register --namespace Microsoft.App --wait`, then deploy again (**tested**: 186 s). The message names the cause only at its end |
| A destination holds one more version of a certificate than the factory | Two instances of the sync app imported the same version at the same moment. The lock that prevents it works inside one instance | **Not seen**; reasoned from the code ([TEST-REPORT.md](TEST-REPORT.md), section 10.1). The extra version is identical and valid, and the next sweep finds the destination current. It does not raise an alert |
| A heartbeat alert fires soon after a deployment | Usually the rule was evaluated before the first sweep had written its line, or the app had not started | **Seen** after both ARM deployments, and it cleared by itself about 46 minutes later (three evaluation periods of 15 minutes). If `reconcile-complete` lines are arriving, nothing is wrong. See *First-run noise* under [Alerts](#alerts) |

## Recovering the factory

**Described, not practised.**

* The certificates are in Key Vault. Copies keep serving while the factory is down. Only *new issuance* stops.
* The factory is code. `terraform apply`, or a deployment of the ARM template again, rebuilds the apps, queues, roles and alerts. For Terraform, keep the state in a remote backend with Entra authentication. ARM keeps no state of its own.
* The renewal app's **state table** (`kvrenew`) records the order of each in-flight renewal, so that a restart resumes the order instead of placing a new one. If the table is lost, an order that was in flight is not known any more and the next sweep would place a new request. Protect the storage account, and look at any renewal that was in flight when it was lost.
* The CA credential is a secret in the factory vault. Keep it where you keep your other CA credentials, so that it can be put back.
* If the factory vault's region is lost, Microsoft may fail the vault over to its paired region, where it is read-only. Renewal pauses until it is writable ([DESIGN-QA.md](DESIGN-QA.md), section 4). West US 3 and a few other regions have no managed failover.

## ARM templates

`deploy/poc` and `deploy/production` build the same factory as `terraform/poc` and `terraform/production`. The file to edit is the Bicep source (`main.bicep` and `deploy/modules`). `azuredeploy.json` is compiled from it (`bicep build`) and is the file the Deploy to Azure buttons open; CI fails when the two differ. Everything above applies to both routes: tags, log lines, queries, alerts and troubleshooting. This section lists what is different. The evidence is in [TEST-REPORT.md](TEST-REPORT.md), sections 10 and 11. On the two live proof-of-concept stacks the alert rules, event subscriptions, custom roles, diagnostic settings, role assignments (with their ABAC conditions) and app settings came out the same.

### Before you deploy

* **Register `Microsoft.App` (production template).** In the subscription of the factory: `az provider register --namespace Microsoft.App --wait`. The VNet integration of the function apps needs it. Without it the deployment retries for about 12 minutes and then fails with `ServiceAssociationLink ... Please check if 'Microsoft.App' is registered`. **Seen** on the first attempt in the lab; after registering, the same deployment took 186 s.
* **Create policy exemptions first, if your policies need them.** The Terraform proof of concept creates its exemptions and waits for them (`policy_exemptions`, `policy_propagation_wait`). An ARM deployment cannot wait for an exemption to take effect, so create the three resource groups yourself, in the regions the template will use (a group's region cannot change), put a time-boxed exemption on each, wait a few minutes, and then deploy. The template accepts groups that already exist. In the lab the groups and the exemptions were created about 5 minutes ahead and the deployment worked at the first attempt. Creating them at the moment of the deployment, or not at all, was **not tested**, and the error that a policy produces was not captured. When the assignment is an initiative, add `--policy-definition-reference-ids` to limit the waiver to the policies that block you.

  ```bash
  az policy exemption create --name <name> --scope <resource group id> --policy-assignment <assignment id> \
      --exemption-category Waiver --expires-on <date and time>
  ```

* **Deployer rights.** Proof of concept: Owner on every subscription it touches (it creates resource groups, role assignments and two custom roles). Production, as listed in the header of `deploy/production/main.bicep`: Owner, or Contributor plus User Access Administrator, on the resource group; Owner or User Access Administrator on every destination vault; Contributor on every destination vault while `enableDestinationAudit` is true (it adds a diagnostic setting); and the right to create custom roles at subscription scope.

### Parameters and their Terraform variables

The ARM parameter is the camelCase form of the Terraform variable (`reconcile_schedule` is `reconcileSchedule`, `destination_vault_ids` is `destinationVaultIds`). The exceptions, found by comparing the two sets of names:

| Terraform | ARM | Difference |
|---|---|---|
| `hub_subscription_id`, `tenant_id` | none | The subscription you deploy to, and its tenant |
| `spoke_a_subscription_id`, `spoke_b_subscription_id` | `spokeASubscriptionId`, `spokeBSubscriptionId` | Required in Terraform. Empty in ARM means the hub subscription |
| `hub_location`, `spoke_a_location`, `spoke_b_location` | `hubLocation`, `spokeALocation`, `spokeBLocation` | Terraform defaults to three regions (`eastus2`, `westus3`, `northeurope`). In ARM an empty `hubLocation` means the region you pick for the deployment, and an empty spoke location means the hub's region, so by default all three vaults sit in one region |
| `resource_group_name` (production) | none | The resource group you deploy to. The production template deploys at resource-group scope, so the group must exist |
| `suffix` (proof of concept) | `suffix` | Required in Terraform. Empty in ARM: five characters derived from the subscription id, the same every time for that subscription |
| `name_prefix` | `namePrefix` | The defaults are `kvsync-tf` and `kvsync-arm`, so that both stacks can exist side by side |
| `owner_tag`, `delete_after` | `ownerTag`, `deleteAfter` | Required in Terraform, optional in ARM |
| `operator_object_id` | `operatorObjectId`, `operatorPrincipalType` | Required in Terraform. Empty in ARM means whoever starts the deployment. Set both when a service principal or a pipeline deploys |
| `policy_exemptions`, `policy_propagation_wait` | none | See above |
| `enable_app_gateway`, `app_gateway_certificate_name` | none | The Application Gateway test consumer is Terraform only |
| `function_subnet_ids` | `syncFunctionSubnetId`, `renewFunctionSubnetId` | One parameter per app |
| `private_dns_zone_ids` | `vaultPrivateDnsZoneId`, `blobPrivateDnsZoneId`, `queuePrivateDnsZoneId`, `tablePrivateDnsZoneId`, `sitesPrivateDnsZoneId` | One parameter per zone. Leave one empty when a central policy registers the records |
| `digicert_settings` | `renewSettings` | The same settings |
| `storage_replication_type` | `storageSkuName` | `ZRS` in Terraform, `Standard_ZRS` in ARM |
| none | `spokeAPurgeProtection`, `spokeBPurgeProtection` | Terraform fixes them in `terraform/poc/main.tf` (on for A, off for B). The ARM defaults are the same |
| none | `packageBaseUri`, `deployCode` | Where the function code comes from, and whether to deploy it. See below |
| none | `enableDestinationAudit` (production) | Turns off the diagnostic setting on each destination vault, for a deployer who has no Contributor there. Terraform always adds it |

### Changing settings and code

* **A setting or a schedule.** Change the parameter and deploy again with the same `suffix`. ARM updates the resources in place (**tested**: two redeployments over the live proof of concept, 2 min 8 s and 2 min 10 s). A redeployment is expected to rewrite the app settings the template declares, so do not edit them in the portal (not tested).
* **The code.** `scripts/build_packages.py` builds `deploy/packages/sync/released-package.zip` and `deploy/packages/renew/released-package.zip` from `src/`. The zips are the same bytes every time, and `--check` proves it (CI runs it). Commit the new zips, then deploy with `packageBaseUri` pinned to the new commit or tag. **Tested twice**: the lock fix reached the running apps this way, and a live probe showed the new behaviour. Whether the apps fetch a zip again when the file behind an unchanged address changes was not tested, so use a new address.
* **The Bicep.** Edit the `.bicep` files, then recompile with the Bicep version pinned in `.github/workflows/ci.yml` (`BICEP_VERSION`): `bicep build deploy/poc/main.bicep --outfile deploy/poc/azuredeploy.json`, and the same for `deploy/production`. Commit the `azuredeploy.json`. The compiled file records the compiler version, and CI recompiles and compares.
* **Add a destination vault** (production). Add a key and a resource id to `destinationVaultIds` and deploy again, with the rights above on the new vault. Not tested on an existing stack. The proof of concept has two destinations, fixed in the template.
* **Remove a destination vault** (production). Take it out of `destinationVaultIds` and deploy again: the sync app stops copying there. An ARM deployment in the default incremental mode does not delete what the template no longer lists (documented ARM behaviour), so the sync identity's role assignment on that vault and the diagnostic setting stay until you delete them. Terraform removes both. Not tested.
* **Look for drift.** There is no state file. `az deployment sub what-if` (proof of concept) or `az deployment group what-if` (production) compares the template with the live resources. It was run before the first deployment of the proof of concept, where it listed 66 resources. **Not tested** against a changed stack.

### Removing the ARM proof of concept

There is no `destroy`. **Described, not run as one procedure on an ARM stack.**

1. Delete the three resource groups (`rg-<namePrefix>-hub`, `rg-<namePrefix>-spoke-a` and `rg-<namePrefix>-spoke-b`). That removes the vaults, the apps, the monitoring, and the role assignments inside them.
2. Delete the policy exemptions you created.
3. Delete the two custom roles. They belong to the subscription, not to a group, and a role cannot be deleted while a role assignment still uses it, hence this step comes after step 1: `az role definition delete --name "KV Certificate Importer <suffix>"` and the same for `"KV Certificate Issuer <suffix>"`. List what is left with `az role definition list --custom-role-only true --name "KV Certificate Importer <suffix>"`.
4. The vaults are soft-deleted, and their names stay reserved for the 7-day retention period. To deploy again with the same `suffix` at once, purge the vaults that have no purge protection: the factory vault and destination B (`az keyvault purge --name <vault> --location <region>`). Destination A has purge protection and cannot be purged: wait out the retention, or use a different `suffix`.

### Not tested on ARM

The Deploy to Azure button and its portal form (the lab deployed from a raw URL with the CLI), deployment by a service principal or a pipeline, deployment from the `main` branch's URL, private endpoints to destination vaults, a DigiCert-backed deployment, `deployCode` set to false, and the cost of an ARM stack. The full list is in [TEST-REPORT.md](TEST-REPORT.md), section 9.
