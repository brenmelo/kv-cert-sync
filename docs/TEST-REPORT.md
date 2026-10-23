# Test report

What was run against the proof of concept, what happened, what went wrong on the way, and what was **not** tested. Everything here ran in a lab on 20, 21 and 22 October 2026: sections 2 to 9 against the Terraform deployment, sections 10 and 11 against the two ARM templates. All times are UTC.

Read it with [DESIGN-QA.md](DESIGN-QA.md) (why the design is the way it is) and [REQUIREMENTS-COVERAGE.md](REQUIREMENTS-COVERAGE.md) (how these results map to what a customer asked for).

**Two limits apply to every result below.**

1. **No real CA was used.** Every certificate was issued by a private test CA that the renewal function includes for this purpose (`CA_PROVIDER=testca`). It signs the certificate request the same way a public CA would, but its root is not trusted anywhere. The DigiCert client (`CA_PROVIDER=digicert`) is code that has **never been run against the live service**. Nothing here proves that DigiCert accepts what the client sends. See section 9.
2. **Each test ran once** unless a section says that it was repeated. The times are single observations, not distributions. Treat them as the order of magnitude, not as a service level.

## Summary

| Section | What was tested | Result |
|---|---|---|
| 2 | A certificate request in the factory vault is ordered, merged and copied to vaults in two other subscriptions and regions. A forced rotation. Idempotence. A request that is not opted in. A wildcard issued through the documented CLI route | **Pass**, 11 of 11 assertions, plus the CLI route |
| 3 | What each identity can actually do on each vault, and the 403 on the CA credential | **14 of 14** after two fixes (11 of 14 on the first run). ABAC probe **4 of 4** |
| 4 | Eight edge cases: non-exportable key, tag selection, name collision, loop guard, late opt-in, disabled certificate, imported PFX, adoption of an existing certificate | **Pass**, 11 of 11 assertions |
| 4.1 | Two migration cases: a destination that already holds a certificate Key Vault renews by itself (adoption), and a copy deleted in a destination | **Pass**, 15 of 15 assertions in two runs. Adopting replaces the destination's policy, so Key Vault stops renewing it there. A deleted copy blocks only its own destination, raises the `failures` alert while it stays deleted, and healed by itself 157 s and 15 s after it was recovered (two runs) |
| 5 | Application Gateway reading a copy from a vault next to it | The listener served the vault's certificate. After a rotation it did **not** follow within 91 minutes, and a forced refresh fixed it in about a minute. Unaided pickup was **not concluded** |
| 6 | Three alert rules, and one destination outage | All three **fired and cleared by themselves**. The outage healed by itself in 160 s. One probe check failed because of a bug in the probe |
| 7 | 113 offline tests, `terraform fmt` and `validate`, plan drift, and the Bicep and package checks of the ARM templates | **Pass**, and no drift. The 49 tests added for the ARM work read the templates as JSON and never deploy anything: sections 10 and 11 are what show that the templates deploy |
| 10 | The proof of concept deployed from its **ARM template** (the Deploy to Azure route): deployment, equality with the Terraform stack, end to end, access audit, edge cases, alerts, redeploying over the live stack | Deployed in 3 min 35 s. **End to end 11 of 11, 11 of 11, then 12 of 12** (a check was added after the second run). **Access audit 14 of 14** and **edge cases 11 of 11**, each twice. Six comparisons with the Terraform stack, **all identical** on the final state: alert rules, event subscriptions, role definitions, role assignments with their conditions, diagnostic settings and app settings. Deployed from a branch URL with the CLI: the button and the portal form were **not** used |
| 10.1 | A race found by the ARM runs: two events for one certificate imported it twice | A **real defect**. Reproduced live and by an offline test (which failed 8 times out of 8 without the fix and passed 8 out of 8 with it), fixed with a lock per certificate, and seen fixed live (one run). The Terraform stack still runs the code without the fix and was not redeployed; its own end-to-end run did not show the duplicate |
| 11 | The **private-network ARM template** (`deploy/production`): deployment, end to end, access audit, a closed vault | Deployed in a lab after a first attempt failed for a missing resource provider registration. **End to end 11 of 11 (once), access audit 14 of 14 (twice)**, and a closed vault refused a caller who held a role. **Not captured**: the vault's network settings during the end-to-end run, which were opened by hand for the operator's address. No private endpoint to a destination vault was tested |

## 1. Environment and method

| Item | Value |
|---|---|
| Stack | `terraform/poc`, applied. One factory (hub) in East US 2, one destination vault in West US 3 and one in North Europe. **Three subscriptions in one tenant**, so every copy crossed a subscription boundary and two crossed a region |
| Vaults | One source (factory) vault and two destination vaults, RBAC mode. The first destination has purge protection on; the source and the second destination do not (so the test could be torn down) |
| Compute | Two Flex Consumption function apps on Python 3.12: **sync** (copies) and **renew** (orders and merges). Event Grid system topic on the source vault, then a Storage queue, then the sync function. Both apps also run a timer sweep, set to **5 minutes** here (default 15) to keep the tests short |
| Logging | Application Insights into a Log Analytics workspace. Every outcome is one `KVSYNC result=...` or `KVRENEW result=...` line |
| Tooling | Terraform 1.16.6, `azurerm` 5.10, `azapi` 2.8, Python 3.13 for the test scripts |
| Policy | The lab's Azure Policy forbids public network access, so four narrow, time-limited policy exemptions were created. The proof of concept therefore runs with a public data plane. The private-network Terraform variant (`terraform/production`) was **only planned**. The private-network **ARM** variant was deployed and tested end to end once (section 11) |
| ARM stacks | `deploy/poc` and `deploy/production`, deployed with the Azure CLI on 22 October (sections 10 and 11). The proof-of-concept template was fetched from its raw GitHub address on a branch (the Deploy to Azure button opens the same kind of address, for `main`); for the production template the address was not recorded. The code packages of both came from raw GitHub addresses. The same test scripts ran against them: save the deployment's outputs (`az deployment sub show --name <deployment> --query properties.outputs > outputs.json`, or `az deployment group show --resource-group <group> --name <deployment> --query properties.outputs > outputs.json` for the production template) instead of `terraform output -json` |
| CA | The private test CA (see the limit above). It signs for 30 days after a simulated 20-second validation delay, which is what the end-to-end tests and the CLI route used. Certificates that a test script made itself were valid for 3 days (expiry alert), 60 days (failure alert) or 90 days (gateway rotation) |

Each live test is a script in `tests/live/`. It creates its own certificates (with a prefix so it cannot touch anything else), asserts, logs every step with a UTC time, and cleans up (the vault soft-deletes, so names can stay reserved). To re-run one, save `terraform output -json` of the stack to `outputs.json` and run:

| Test | Command |
|---|---|
| End to end (section 2) | `python tests/live/e2e.py --outputs outputs.json --evidence evidence.json` |
| Edge cases (section 4) | `python tests/live/edge.py --outputs outputs.json --run r1` |
| Access audit (section 3) | `python tests/live/access_audit.py --outputs outputs.json` |
| ABAC probe (section 3) | `python tests/live/abac_probe.py --outputs outputs.json --wait-until HH:MM` |
| Migration cases (section 4.1) | `python tests/live/migration_probe.py --outputs outputs.json --evidence .scratch/migration.json` (`--run <id>` names the test certificates, `--only adopt` or `--only deleted` runs one case) |
| Application Gateway (section 5) | `python tests/live/agw.py --outputs outputs.json --cert <name> probe` (then `rotate` or `follow --max-hours 5`) |
| Alerts (section 6) | `python tests/live/alerts_probe.py --outputs outputs.json --scenario failure` (or `expiring`, `heartbeat`, `list`) |
| Two events for one certificate (section 10.1) | `python tests/live/race_probe.py --outputs outputs.json --evidence .scratch/race.json --grant-send-role` (needs `pip install azure-storage-queue`; the destination it uses must not have purge protection) |
| Offline (section 7) | `python -m unittest discover -s tests -p "test_*.py"` |

## 2. End to end: request, renew, copy

**What was done.** A certificate request (CSR mode, issuer `Unknown`, exportable key) was created in the source vault with the tags `kvsync=all` and `kvrenew=on`. Nothing else was done by hand.

| Step | Result |
|---|---|
| **R1** The renewal function orders the certificate and merges it | Merged **122 s** after the request. The signature chain is the test CA |
| **R1** The sync function copies it | In the first destination **43 s** after the merge and in the second **2 s** after. Same certificate, **same private key** (same public modulus), tags `kvsync-origin` and `kvsync-source-version` on the copy and **no** `kvsync` or `kvrenew` tag, so a copy can never be renewed or copied again |
| **R2** Forced rotation: tag `kvrenew-now=1` on a certificate that was not due | A new certificate with a **new key** was merged **253 s** after the tag (it waits for a sweep, because a tag change fires no event). Both destinations followed in **9 s** and **2 s**. They still held the previous version, so a rollback is possible. The one-shot tag was **not** on the new version, so there is no rotation loop |
| **R3** Idempotence | After 11 minutes (two sweeps of each function) with nothing changed, the version counts were identical in all three vaults (2, 2, 2) |
| **R4** A pending request **without** `kvrenew` | Stayed pending. Nothing ordered it and nothing was copied |

**The documented CLI route.** The runbook's first certificate is created with the Azure CLI and the policy in `examples/policy-csr-wildcard.json`. A wildcard created that way was picked up by the next sweep: ordered at 07:50:00Z, merged at 07:50:21Z (21 s), and copied to both destinations at 07:50:30Z and 07:50:31Z (9 s and 10 s after the merge). Both copies logged `verified=cert-bytes-identical` and the same thumbprint. This was checked by hand against the logs rather than by a script.

**Renewal windows, offline.** A unit test runs a year of daily sweeps against a fake vault and a fake clock for the three validity periods of the CA/Browser Forum schedule:

| Validity | Renewals in a year | Closest the certificate came to expiry |
|---|---|---|
| 199 days (since 2026) | 2 | 31 days left |
| 99 days (from March 2027) | 5 | 31 days left |
| 46 days (from March 2029) | 11 | 16 days left |

Exactly one CA request per renewal in every case. This is a simulation of the logic, not a test of a CA.

## 3. Effective access: the audit and the ABAC probe

**The audit** (`access_audit.py`) does not read role names. It asks Azure for the **effective data actions** of each of the two function identities on each of the three vaults, and checks 14 expectations. Final result (`yes*` means only under an ABAC condition):

| Ability | Sync, source | Renew, source | Sync, each destination | Renew, each destination |
|---|---|---|---|---|
| Read a certificate (public part) | yes | yes | yes | no |
| Read the private key (secret value) | yes* | yes* | no | no |
| Create a new certificate version (CSR) | no | yes | no | no |
| Merge a signed certificate | no | yes | no | no |
| Import a certificate | no | no | **yes** | no |
| Delete, purge, back up, restore a certificate | no | no | no | no |
| Write a secret | no | no | no | no |
| Read key properties | yes | no | no | no |

**First run: 11 of 14. Final run: 14 of 14.** The three that failed first:

| Failed expectation | Cause | Fix |
|---|---|---|
| Renew identity has "no wildcard or `NotDataActions`" | The audit rule was too broad. It also flagged the built-in *Storage Blob Data Owner* role that each function app holds on **its own** storage account, which the Functions host needs | The rule now checks Key Vault data actions only. Not a defect in the design |
| The same, for the sync identity | The same | The same |
| The sync identity's private-key read is limited | **A real finding.** The *Key Vault Certificate User* role includes `secrets/getSecret`, so the sync identity could read **every secret in the factory vault, including the CA credential** | An ABAC condition on the role assignment excludes names that start with `ca-` |

**The ABAC probe** (`abac_probe.py`) proves the fix against the real vault rather than the role definition. It created a normal certificate and one named `ca-...` in the source vault, waited 13 minutes for the role assignment to propagate, and then opted both in.

| Check | Result |
|---|---|
| A1 The normal certificate reached both destinations under the condition | Pass |
| A2 The `ca-` certificate was copied nowhere (the vault refused the private key) | Pass |
| A3 The function logged a failure that names the refusal | Pass |
| A4 The vault's audit log shows `SecretGet` on the `ca-` secret answered **403** for the sync identity | Pass |

## 4. Edge cases

One run, 07:13 to 07:21. Every negative assertion was checked **after** the matching event had time to arrive (the script waits 80 seconds more), so "nothing happened" means nothing happened and not that the check was early.

| Case | Expected | Observed | Result |
|---|---|---|---|
| **T2** Non-exportable key, `kvsync=all` | Nothing copied (the key cannot be read) | Not copied to either destination. Logged as a permanent failure | Pass |
| **T3** `kvsync=<one destination>` | Only that destination receives it | The named destination had it after 108 s, the other never | Pass |
| **T4** An **unmanaged** certificate of the same name already in a destination | It is **not overwritten** | The destination without a conflict received it (98 s). The other kept its certificate | Pass |
| **T5** A copy is changed or re-imported in a destination | It is never replicated again | `skipped-loop-guard` | Pass |
| **T6** Opt-in tag added **after** the event was processed (a tag change fires no event) | The timer sweep picks it up | Copied 3.5 minutes after tagging. The untagged certificate was not copied before that | Pass (2 assertions) |
| **T7** A **disabled** certificate | Not copied | Not copied | Pass |
| **T8** A PFX that was **imported** into the source (no CSR) | Copied like any other | Both destinations had it after 19 s. The copy carries `kvsync-origin` and not the opt-in tag | Pass (2 assertions) |
| **T9** Adoption: tag the unmanaged certificate from T4 with `kvsync-origin=<source vault>` | The next sweep takes it over, and the unmanaged version stays as an older version | Taken over 3.4 minutes after tagging. The old version remained | Pass (2 assertions) |

**The event path was not quick or steady in this run.** The copies in T8 took 19 s, in T4 98 s and in T3 108 s. The cause was not investigated (a cold start or the queue's polling back-off are both possible). The sweep is the guarantee, the event is the speed-up, and in the lab the event path arrived somewhere between 2 s and about 2 minutes.

### 4.1 Two migration cases: adopting a certificate that Key Vault renews, and a deleted copy

An estate that already has vaults and certificates meets these cases, so each was run once on 21 October (`tests/live/migration_probe.py`; adoption and a deleted copy 19:29 to 19:34, a copy left deleted 19:58 to 20:02; **15 of 15 assertions passed**). Times below are UTC. The sync log lines come from the Log Analytics workspace.

**Case 1: a destination already holds a certificate that Key Vault renews by itself.** Destination B was given a certificate with issuer `Self` and an explicit *auto-renew* lifetime action at 80% of its lifetime. That is the same shape as a certificate that came from a Key Vault integrated CA, but the integrated-CA case itself was **not** run. A certificate of the same name was then imported at the factory with `kvsync=all`.

| Time | Event |
|---|---|
| 19:29:37 | The same-name certificate is created at the factory |
| 19:29:44 | Destination A: `copied`. Destination B: **`failed-permanent`** (ERROR, "destination already holds an unmanaged certificate ... to let this sync own it, tag that certificate `kvsync-origin=<source vault>`"). B kept its own certificate, so nothing was overwritten |
| 19:29:57 | B's certificate is tagged `kvsync-origin=kv-src-tf4k9` (the adoption) |
| 19:30:02 | `copied` to B by the timer sweep. The sweep happened to run 3 s after the tag, so this is the best case. The earlier edge test (T9) took 3.4 minutes. The worst case is one sweep period: 5 minutes here, 15 by default |
| 19:30:57 | The `failures` alert fired (severity 2) on the 19:29:44 `failed-permanent` line |

| Check | Result |
|---|---|
| A0 Before the adoption B's policy is issuer `Self` with auto-renew at 80%, and B keeps its own certificate | Pass |
| A1 The sweep writes the factory's certificate into B after the tag | Pass |
| **A2 Afterwards Key Vault no longer renews B's certificate by itself** | **Pass.** The policy went from `Self` with *auto-renew* at 80% to issuer **`Unknown`** with the lifetime action **`EmailContacts`** at 80%. The import replaced the whole policy |
| A3 The previous version is still in the vault and the new one is tagged as a copy | Pass, two versions |

Two lessons. **Adopting hands the certificate over for good**: the destination certificate is no longer renewed there, so adopt it only when the factory certificate exists and will be renewed. And **expect one alert** while you do it: the `failed-permanent` line is what the `failures` rule looks for, so it fires once, as designed, until the adoption is done and the line has left its look-back. The `EmailContacts` action is what Key Vault adds to a policy that has none, which is what the sync imports with. If a destination vault has certificate contacts configured, Key Vault would mail them at 80% of the copy's lifetime. Whether it does was not tested, because no contacts were configured.

**Case 2: someone deletes a copy in a destination.**

| Time | Event |
|---|---|
| 19:30:34 | Version 1 is in both destinations |
| 19:30:47 | The copy in destination B is deleted. It is soft-deleted: not readable, but its name is still reserved |
| 19:30:48 | Version 2 is imported at the factory |
| 19:30:58 | Destination A has version 2 (**10 s**). One broken destination does not stop the other |
| 19:30:59 | Destination B: `result=retrying` (WARNING) with `error=ResourceExistsError`: *"(Conflict) Certificate ... is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the certificate can only be recovered or purged"*, inner code `ObjectIsDeletedButRecoverable` |
| 19:31:14 | B's copy is **recovered** |
| 19:33:51 | B has version 2, **157 s** after the recovery (the function's own log line, `trigger=CertificateNewVersionCreated`: the Functions host retried the queue message, no other step). The probe polls every 15 seconds and noticed at 19:34:01, so its own message says 168 s. The host's visibility timeout is 2 minutes, which is why a retry arrives two to three minutes after a failure |

Destination B has purge protection **off**, and the deleted copy still blocked the write, so purge protection is not what causes this: a soft-deleted object reserves its name either way. Purging it instead of recovering it was **not** tested. In this run the copy was recovered before the next timer sweep, so no sweep saw the conflict. The next case leaves it deleted.

**Case 2b: the copy stays deleted until a sweep has seen it.** A separate run (`--only stays`, run `s2`, 19:58 to 20:02, **5 of 5 assertions passed**) repeated the steps and waited.

| Time | Event |
|---|---|
| 19:58:47 | Version 1 is in both destinations |
| 19:59:07 | B's copy is deleted, and version 2 is imported at the factory in the same second |
| 19:59:13 | A has version 2 (**6 s**). B: the event-path attempt logs `result=retrying` (WARNING) with the same Conflict error. That is attempt 1 of the 5 the host makes before the message goes to the `-poison` queue, which nothing watches |
| 20:00:01 | The **timer sweep** logs `KVSYNC result=failed-transient cert=... dest=b error=ResourceExistsError msg="(Conflict) Certificate ... is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the certificate can only be recovered or purged ..."` at **ERROR**. Destination A: `converged-noop` |
| 20:00:58 | The `failures` alert fires (Sev2), **56 s** after that line. It **resolved at 20:26:59**, 27 minutes after the last failure line: the recovery at 20:01:42 ended the failures, and the alert then needed the 15-minute look-back and three clean evaluations to clear |
| 20:01:42 | The owner recovers B's copy |
| 20:01:56 | B has version 2, **15 s** after the recovery. The log line says `trigger=CertificateNewVersionCreated`: it was the host's retry of the queue message (2 min 42 s after the first attempt), not a sweep. The next sweep would have run at 20:05:01 |

So a copy that nobody wants in a vault raises the `failures` alert every time a sweep sees it, for as long as it stays that way, and the fix is the owner's: recover the copy, or take that destination out of the `kvsync` tag. If the copy had stayed deleted for the host's five attempts (about 10 minutes), the queue message would be in the poison queue and **only the sweep** would still try, every sweep period.

## 5. Application Gateway

An Application Gateway (Standard_v2, `terraform/modules/app_gateway`) was deployed in the same subscription as one destination vault, with its own user-assigned identity holding *Key Vault Secrets User* on **one secret**, and an HTTPS listener bound to the **versionless** secret ID. The aim was to see what a consumer does when the copy in its vault changes.

| Step | Result |
|---|---|
| The listener serves the vault's certificate | Pass. A TLS 1.3 handshake from outside returned a certificate with the same thumbprint as the one in the vault |
| Rotation 1, started with the one-shot tag | The new version was in the vault **187 s** after the tag. The listener **kept serving the old one**, which is the documented behaviour (the gateway polls Key Vault about every four hours) |
| Forced refresh: point the listener at the **versioned** secret ID, then back to the **versionless** one | Two updates of 29 s and 31 s. The listener served the **new** certificate **60 s** after the refresh began, and the versionless binding was restored |
| Rotation 2, as an operator would do it: a new CSR in the source vault, signed by the test CA and merged | The new version was in the destination vault **21 s** after the merge. The listener stayed on the old certificate at 0, 15, 30, 45, 60, 75 and 91 minutes |

**The unattended pickup was not concluded.** The check was meant to run for up to five hours. At 08:50 an action in the subscription's activity log **stopped the gateway**. This project did not issue it, and the caller could not be identified (the lab runs policy automation that stops costly resources). The result is therefore "not by 91 minutes", **neither a confirmation nor a refutation** of Microsoft's four-hour figure. What the test did establish is that a gateway does **not** follow immediately, so make a forced refresh a step of your pipeline if the gateway matters.

Two more limits. The gateway and the vault were in the **same** subscription; a reference to a vault in another subscription (possible through ARM or the CLI, not the portal) was **not** tested. And the gateway costs about US$0.25 an hour at list price, which is why it was destroyed afterwards (`terraform apply -var enable_app_gateway=false`).

## 6. Alerting and failure handling

Three alert rules exist on the function logs (see [DESIGN-QA.md](DESIGN-QA.md), section 5, for what each one is for). Each was fired on purpose with `alerts_probe.py`.

### 6.1 `failure`: a destination is unreachable

| Time | Event |
|---|---|
| 08:56:08 | Baseline: version 1 is in every destination |
| 08:56:12 | **Public network access on destination A is switched off.** The probe's own calls are refused too |
| 08:56:13 | Version 2 is imported at the source |
| 08:56:33 | Destination B has version 2 (**20 s**), although A is unreachable. One broken destination does not stop the others |
| 09:00:01 | The timer sweep logs `KVSYNC result=failed-transient` for A, one standard line with the certificate, destination, trigger, error type and reason. The event path had already logged two `retrying` warnings |
| 09:00:57 | **The alert fires** (severity 2), **56 s** after the first failure line |
| 09:01:38 | Public access on A is switched back on. A had **kept serving version 1** all along, so nothing was half-written |
| 09:04:19 | A has version 2, **160 s** after access returned, with no manual step. This was the Functions host's fourth attempt to process the queue message. The timer sweep did not need to do anything |
| 09:26:57 | **The alert resolves**, 25 minutes after the fix |

### 6.2 `heartbeat`: a function app stops

| Time | Event |
|---|---|
| 08:55:02 | The last completed renewal sweep before the test |
| 08:55:50 | The renewal function app is **stopped** |
| 10:04:24 | **The alert fires** (severity 2), about **69 minutes** later: the rule looks back one hour and evaluates every 15 minutes |
| 10:05:41 | The app is started again. The first sweep is logged at 10:06:03 |
| 10:50:24 | **The alert resolves**, 45 minutes after the restart |

**This run is recorded as FAILED, and the failure is a probe bug.** The first check (`H0`) asks whether the app is stopped and answered "no", although the app was stopped (the alert proves it, and the Azure Resource Manager state read `Stopped`). The probe read `state` from `az functionapp show`, which is empty for Flex Consumption apps. It now reads `properties.state` from the Resource Manager API. The heartbeat itself behaved correctly. The evidence file keeps the original wording.

### 6.3 `expiring`: a copy is close to expiry

| Time | Event |
|---|---|
| 15:58:24 | A certificate with **3 days left** is imported at the source |
| 15:58:50 | It is in both destinations (**26 s**) |
| 15:58:36 and 16:00:02 | The sync function logs `KVSYNC result=replica-expiring days_left=3 warn_days=7` as a warning, once per destination from the event path (15:58:36) and once more from the 16:00 timer sweep |
| 15:59:44 | **The alert fires** (severity 1), **68 s** after the first line |
| 16:01:19 | The test certificate is deleted. The 16:00:02 sweep was the last to log `replica-expiring` (no line was written after it) |
| 17:00:02 | The last warning line ages out of the rule's one-hour look-back |
| 17:45:45 | **The alert resolves**, **1 h 45 min** after the last warning line. That is the look-back plus three clean 15-minute evaluations |

The probe stopped waiting at 17:41:58, 3 min 47 s before the alert resolved, so its evidence file records `E3` as failed. That is the probe's patience (100 minutes), not a failure of the alert: the resolution time above was read from the alerts API afterwards, and the resolve mail arrived at 17:45:51. The probe's default wait is now 120 minutes.

### 6.4 What this showed about timing

* **Detection is quick.** About one minute after the first failure or expiry line, plus the time until the next sweep (5 minutes here, 15 by default).
* **Clearing is slow, on purpose.** These are *stateful* rules, so one message is sent when the rule fires and one when it clears. Microsoft documents that a stateful log alert resolves only after the condition has been unmet for a number of frequency periods that depends on the rule's frequency: three for 5 to 15 minutes, two for 15 minutes to 11 hours ([What are Azure Monitor alerts?](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview#alerts-and-state)). The 15-minute rules here sit on the boundary of both rows and behaved like the first. Measured: **25 minutes** (`failures`, after the fix), **45 minutes** (`heartbeat`, after the restart) and **1 h 45 min** (`expiring`, after the last warning line). In all three the alert resolved about one minute after the **third** clean evaluation. For `failures` and `expiring` the last matching line first had to age out of the look-back (15 minutes and one hour); for `heartbeat` it did not, because a new sweep line made the condition false at once. From the rule settings, expect "resolved" **26 to 31 minutes after the last failure line** (`failures`; measured 27), **31 to 46 minutes after the restarted app's first sweep** (`heartbeat`; measured 44) and **1 h 31 min to 1 h 46 min after the last warning line** (`expiring`; measured 1 h 45 min, the long end). The spread is where the evaluation grid falls. Do not read a late "resolved" as a failed fix.
* **A short outage heals without an alert.** The `failures` rule only sees lines the timer sweep writes. The event path retries silently (a warning line only), so a destination that comes back within a few minutes is repaired without anyone being paged. That is intended.

### 6.5 The e-mails

The action group's address was **never verified**. Azure Monitor sends a one-time verification message when an address is added, and the code was not used. The notifications were delivered anyway. The ones from the first three runs (the table's first three rows) were found in the mailbox's *Deleted Items* folder when it was checked later that day, together with every other Azure Monitor message of that day. The four from the migration tests (rows four and five, section 4.1) arrived in the **Inbox**, and so did messages from the same sender the day before. This project does not move mail, none of the mailbox's rules matches the sender, so **what moved the first ones was not established** (a person clearing the folder is possible). What it shows is that delivery works without verification here, and that you cannot tell from the outside where a notification will end up.

| Alert | Fired (alert time, mail time) | Resolved (alert time, mail time) |
|---|---|---|
| `failures` | 09:00:57, 09:01:05 | 09:26:57, 09:27:02 |
| `heartbeat` | 10:04:24, 10:04:32 | 10:50:24, 10:50:37 |
| `expiring` | 15:59:44, 16:00:53 | 17:45:45, 17:45:51 |
| `failures`, adoption test (section 4.1) | 19:30:57, 19:31:04 | 19:57:00, 19:57:06 (27 min after the last failure line) |
| `failures`, copy left deleted (section 4.1) | 20:00:58, 20:01:08 | 20:26:59, 20:27:09 (27 min after the last failure line) |

Microsoft documents that an unverified receiver "can't receive alert or test notifications after enforcement is active", and the action group's test notification answered "There are no valid receivers in the request". **Do not rely on a mailbox you have not verified.** Verify the address once, allow-list the sender, and prefer a receiver that people watch (a ticket, a pager, a chat webhook). See [OPERATIONS.md](OPERATIONS.md).

## 7. Offline tests, Terraform checks and drift

| Check | Result |
|---|---|
| `python -m unittest discover -s tests -p "test_*.py"` | **113 tests pass** in under 10 seconds (64 before the ARM work). Two of them check that every relative Markdown link and `#anchor` in the repository's documents resolves. 49 are new and cover the ARM templates (next row). The rest cover the renewal logic (window, rate limit, forced tag, replica and managed-issuer skips, a sweep that continues after one certificate fails with any exception, the year-long renewal simulation), the copy logic (idempotence, collisions, loop guard, `replica-expiring`, `report_failure`, and, since section 10.1, exactly one import when two threads sync one certificate), the Event Grid message format and the inventory script's grouping of certificates that cover the same names |
| The 49 ARM tests (`tests/test_deploy_arm.py`) | **Pass.** They are offline: they read the compiled templates as JSON and never deploy anything. They check that the two function packages are reproducible and laid out as Azure expects. For the proof-of-concept template: the scope, that every parameter has a description and none is a secret, that the outputs are the ones the Terraform stack writes, that no vault uses an access policy and no storage account a key, that each app uses a user-assigned identity and HTTPS only, that the custom roles equal Terraform's, and that the alert queries match the log lines the code writes. For the production template: the scope, private mode, purge protection, which inputs have no default, that every Terraform production input has an ARM counterpart with the same default, and that it creates no network and no destination vault. And that each README button opens a committed template through a correctly encoded address, and the test CA script |
| `az bicep lint` of the three templates, `bicep build` compared with the committed `azuredeploy.json`, `python scripts/build_packages.py --check` | **Pass**, run locally. The `arm` job in `.github/workflows/ci.yml` runs the same checks on every push: the compiler is pinned to v0.46.1 because the compiled JSON records its version, any lint diagnostic fails the job, the recompiled templates must equal the committed ones, and the packages must equal what `src/` builds to |
| `terraform fmt -check -recursive` | Clean |
| `terraform validate`, `terraform/poc` and `terraform/production` | Valid |
| `terraform plan` of the applied stack after all tests and after the gateway was destroyed | **No changes**. The infrastructure matches the configuration |
| `terraform/production` | Validated and planned only, **never applied**. Its ARM twin, `deploy/production`, was deployed (section 11) |

## 8. What went wrong while testing

These are listed because they would happen to a customer too.

1. **The audit flagged a role it should not have.** The first audit rule was too broad (section 3). Fixed in the audit, not in the design.
2. **The audit found a real exposure.** The sync identity could read the CA credential. Fixed with an ABAC condition, and proven with a probe (section 3).
3. **The alerting was reviewed before it was tested and had five defects.** The rules existed in the module but were not deployed in the proof of concept, because they are created only when `alert_email_addresses` is set. An expiry alert on Key Vault's own near-expiry event was considered and rejected: it fires at a fixed 30 days, which on a 47-day certificate is 17 days after issuance, so it would fire on every certificate in every cycle. The rules were stateless and would have mailed on every evaluation. The event path logged no standard failure line. And **one certificate that failed with an unexpected exception aborted the whole renewal sweep**, hiding every certificate after it. The sweep now catches each certificate, carries on, and raises at the end so that the run still counts as failed.
4. **A probe bug.** `H0` reported a stopped app as running (section 6.2).
5. **An earlier version of these notes credited the wrong mechanism.** The 160-second self-heal in section 6.1 was first described as the timer sweep. The logs show it was the Functions host's retry of the queue message (fourth attempt). Corrected here and in [DESIGN-QA.md](DESIGN-QA.md).
6. **The gateway was stopped by something else** (section 5). A lab with cost-control automation can also stop the function apps. The heartbeat alert is what would catch that.
7. **Azure Policy blocked the cleanup.** The lab policy added three metric alert rules inside the gateway's resource group. Terraform refused to delete the group while they existed (its `prevent_deletion_if_contains_resources` safeguard). They were removed and the group was then deleted in 30 s. **Leave that safeguard on.**
8. **The e-mail address was never verified** (section 6.5).
9. **Role assignments took time.** The ABAC probe waited 13 minutes before acting. After any role or condition change, wait before you test.
10. **The Terraform provider's Flex Consumption resource did not fit.** `azurerm` 5.10's resource for Flex Consumption function apps added a shared-key storage setting, which this design avoids on purpose (the apps use managed identity to reach storage). The two function apps are therefore created with `azapi` (`Microsoft.Web/sites`).
11. **Two events for one certificate imported it twice.** The ARM runs found it: a destination held 3 versions of a certificate that the factory vault held twice. It is a real defect in the sync code, not a test artefact, and it is why the code has a lock per certificate now (section 10.1). The Terraform stack runs the code without the lock.
12. **A weak check let it through.** The second ARM end-to-end run printed 11 of 11 while a destination held three versions, because the assertion was "at least two". It is now "exactly as many as the factory vault" and it passed in the third run (12 of 12). The log line "versions kept there: 3" was the only sign. Read the log, not only the verdict.
13. **The production template failed after 12 minutes, and the cause is in the last words of the message.** The `Microsoft.App` resource provider was not registered in the subscription, and the VNet integration of Flex Consumption apps needs it. The function apps retried for about 12 minutes (731 s) and the deployment then ended with `ServiceAssociationLink ... Please check if 'Microsoft.App' is registered`. After `az provider register --namespace Microsoft.App --wait` the same template deployed in 186 s. Register it first ([OPERATIONS.md](OPERATIONS.md#before-you-deploy)).
14. **The first closed-vault check proved nothing.** It waited 9 minutes and never read the error code, so a failure could have been anything. The second one read **HTTP 403 `ForbiddenByConnection`** ("Public network access is disabled and request is not from a trusted service nor via an approved private link") for a caller who held *Key Vault Certificate User* on the vault. The role assignment was removed afterwards.
15. **A policy exemption cannot be waited for in an ARM template.** The Terraform module pauses for it. An ARM template has no sleep, so the exemptions had to exist a few minutes before the deployment (about 5 minutes in the lab). What happens when they are created at the same moment was **not tested**, and the error text was not captured.
16. **Heartbeat alerts fired before the first sweep, and once without a confirmed cause.** The production stack's two heartbeat alerts fired at 16:33 and 16:43: the first while the failing first attempt was still running (item 13), the second 97 s after the second attempt had finished and before its first sweep (they run every 5 minutes in the lab). The alert rules are created in the first minutes of a deployment, so the alert did what it is for. Expect it after any first deployment, and read the log before you treat it as an outage. Each cleared 46 minutes after it fired, the pattern of section 6. The proof of concept's sync heartbeat is the one **without** a confirmed cause: it fired at 16:12:13, 77 s after its first `reconcile-complete` line had reached the workspace (16:10:56, section 10).

## 9. What was **not** tested

| Not tested | Why it matters |
|---|---|
| **A real DigiCert order**, the DigiCert client, a DV or wildcard order through the Key Vault integration, reissue inside an existing order, `DIGICERT_ALLOW_NEW_ORDER` | The largest gap. The client is written from DigiCert's documentation and has never talked to the service |
| **Domain validation (DCV)** | Not built. At 47 days it is the step most likely to need automation (DigiCert's persistent DNS validation is the likely route) |
| **GlobalSign or any other CA** | `CA_PROVIDER` accepts `digicert` and `testca` only |
| **The Terraform production stack** (`terraform/production`: private endpoints, VNet-integrated apps, no public data plane) | Validated and planned only, **never applied**. Its ARM twin was deployed (section 11), with the gaps listed in the rows below |
| **Azure Government and other clouds, and copies between tenants** | One factory per cloud is the design; none was deployed. Flex Consumption is not available in Azure Government at the time of writing |
| **Consumers other than Application Gateway**: App Service, AKS, API Management, Front Door, virtual machines, appliances | How fast each one picks up a new version is a property of that service, not of this project |
| **An Application Gateway reading a vault in another subscription**, and **its unattended pickup** | See section 5 |
| **An Application Gateway next to the ARM stacks** | The ARM templates deploy none, and none was tested with them. Section 5 is a Terraform result |
| **Adopting a certificate that came from a Key Vault integrated CA**, **purging a deleted copy** instead of recovering it, and **tagging a destination certificate before the factory certificate exists** | Section 4.1 used issuer `Self` with auto-renew, which has the same lifetime action. Only the recovery path was run, and only the tag-after order |
| **Scale** | At most three vaults and about ten certificates. The Key Vault limit of 300 certificate imports per 10 seconds per vault and region could throttle a very large first sync |
| **Cost of the factory at its real size** | Measured only for the test: **US$0.22 in the first 14 hours** of heavy testing (factory US$0.21, each destination vault US$0.004), two thirds of it Log Analytics. Usage posts late, so the final figure is a little higher, and it excludes private endpoints, which production adds. A monthly estimate at list price is in [OPERATIONS.md](OPERATIONS.md#cost): about **US$8** for the public proof of concept and about **US$64** for production, US$58 of it private endpoints. That is an estimate, not a bill. Whether Key Vault's per-renewal charge applies to the CSR path is unconfirmed |
| **Recovering the factory itself** (a lost region, a deleted vault) | Described, not practised |
| **Notification channels other than e-mail**, and a verified address | Section 6.5 |
| **An alert on an unexpected `SecretGet`, monitoring of the poison queue** | Not built |
| **Microsoft Defender for Key Vault** | A subscription-level plan. It was already enabled on the test subscriptions, so it was running, but this project does not configure it and no test exercised it |
| **The Deploy to Azure button and the portal form** | Both ARM templates were deployed with the Azure CLI, not with the button. The proof-of-concept template was fetched from its raw GitHub address on a branch (the button opens the same kind of address, for `main`); for the production template the address was not recorded. Nobody pressed a button, so the portal's form and how it handles the array and object parameters were not exercised |
| **Deploying from `main`** | The tests deployed from a branch. The buttons and the default `packageBaseUri` point at `main`, which did not have the ARM files when these tests ran |
| **Deployment by a service principal or a pipeline** | `operatorObjectId` and `operatorPrincipalType` exist for it. A signed-in user made every deployment |
| **The `replica-expiring` alert on the ARM stack, and the delivery of any alert e-mail** | The heartbeat and failure rules fired on the ARM stack (section 10). The expiring rule was not triggered there, and no e-mail was sent or checked on any ARM stack |
| **Why the proof of concept's sync heartbeat fired at 16:12** | The first `reconcile-complete` line was written at 16:10:00 and reached the workspace at 16:10:56, 77 s before the alert. If the rule's first evaluation ran just before the line arrived, the alert is the rule working as it did on the production stack, but the evaluation time is not visible, so this was **not established**. The production stack's two heartbeats have a plain explanation: no app had run yet (section 11) |
| **Two instances of one app, and the lock** | The lock in section 10.1 is per process and the apps may scale out (`maxInstanceCount` is 40). Two instances could still import one version twice. That costs one extra identical version, not a failure or a wrong certificate, but it was not tested and never seen |
| **The Terraform stack with the lock** | Terraform's apps run the code from before the fix. It was not redeployed |
| **Certificates at production lifetimes on the ARM stacks** | Every test certificate was valid for 30 days, which is also what set off the race. A sequence at 199, 99 and 46 days was only simulated (section 7 and the README) |
| **The ABAC probe on the ARM stacks** | Only the access audit (14 of 14) ran there. The probe ran on the Terraform stack |
| **Private endpoints to the destination vaults, and `deployCode=false`** | The production deployment used two public destination vaults, and the code was deployed by the template |
| **An ARM deployment with DigiCert** (`caProvider=digicert`) | Every ARM run used the test CA |
| **Cost of an ARM deployment** | Nothing was measured on the ARM stacks. The estimate in [OPERATIONS.md](OPERATIONS.md#cost) is for the same resources, not a measurement of these |
| **Policy exemptions created at the moment of the deployment** | They were created about 5 minutes before. An ARM template cannot wait for them |
| **Whether an ARM redeployment overwrites an app setting edited by hand**, and **whether the same `packageBaseUri` fetches the packages again** | Expected from how ARM works, not tested. The one time a redeployment changed the code, `packageBaseUri` was pinned to a new commit, and the race probe then showed the new code running |
| **Removing an ARM stack in the documented order** | Resource groups first, then the two custom roles ([OPERATIONS.md](OPERATIONS.md#removing-the-arm-proof-of-concept)). The order was not run as one procedure on an ARM stack |

## 10. The ARM template: proof of concept

The proof of concept was deployed from `deploy/poc/azuredeploy.json`, the file behind the **Deploy to Azure** button, to see whether it builds the same factory as Terraform and passes the same tests. It was deployed with `az deployment sub create` on 22 October, from the raw GitHub address of the file on a branch (the button opens the same kind of address, for `main`), with the lab's three subscriptions and regions, an owner tag, an expiry tag and an alert receiver set. The button and the portal form were **not** used.

| Item | Result |
|---|---|
| First deployment | **Succeeded in 3 min 35 s.** The what-if listed 66 resources |
| Redeployment over the live stack | **Succeeded**, twice: the final template in 2 min 8 s, and the version with the fix of section 10.1 in 2 min 10 s (`packageBaseUri` pinned to that commit) |
| Policy | Time-boxed exemptions were created on the three resource groups about 5 minutes **before** the deployment, because an ARM template cannot wait for them. Creating them at the same moment was not tried |
| After the deployment | The test CA was loaded into the factory vault with `scripts/make_testca.py`, because an ARM template cannot generate a key pair |

### Is it the same factory as the Terraform stack?

After the last test both stacks were read back from Azure and compared with a script (not committed). **All six comparisons were identical:**

| Compared | Result |
|---|---|
| Alert rules: query, frequency, window, severity, action group | Identical |
| Event subscriptions | Identical |
| Custom role definitions | Identical |
| Role assignments with their ABAC conditions: the renewal identity 6, the sync identity 5 | Identical |
| Diagnostic settings on the vaults | Identical |
| App settings: **14** keys on the sync app and **22** on the renewal app, in each stack | Identical in keys and values, after the stack names and ids were normalised |

Three differences are not differences in effect: the alert query text differs in line endings (Terraform's has Windows line endings and a trailing newline), a scope string differs in letter case (`resourceGroups` against `resourcegroups`), and an empty list is `null` on one side and `[]` on the other. The Terraform stack also runs the older sync code, without the lock of section 10.1.

### End to end, and the other live tests

The end-to-end script of section 2 ran three times against the ARM stack.

| Run | R1: request to merge | R1: copies after the merge | R2: tag to merge | R2: copies after the merge | Versions: factory, destination A, destination B | Result |
|---|---|---|---|---|---|---|
| 1 | 81 s | 9 s and 0 s | 294 s | 1 s and 1 s | 2, 2, 2 | **11 of 11** |
| 2 | 304 s | 5 s and 1 s | 287 s | 11 s and 2 s | 2, **3, 3** | 11 of 11, but the check was "at least two" (section 8, item 12) |
| 3 | 324 s | 14 s and 1 s | 284 s | 1 s and 1 s | 2, 2, 2 | **12 of 12**, with the new check "exactly as many versions as the factory vault" |

The merge waits for the renewal app's next sweep, which runs every 5 minutes here, so 81 to 324 s is the sweep and not the CA. **R3** (idempotence over 11 minutes) and **R4** (a pending request without `kvrenew` stays untouched) passed in all three runs. Run 2 is why section 10.1 exists.

| Test | Result |
|---|---|
| Access audit (section 3) | **14 of 14** rules, run twice |
| Edge cases (section 4) | **11 of 11**, run twice: before and after the fix of section 10.1 |
| Two events for one certificate (section 10.1) | Failed before the fix, **passed after it** |

### Alerts on the ARM stack

| Alert | What happened |
|---|---|
| `failures` | Fired at 16:35:24 and at 20:40:24, about 20 s after the last failure line, and cleared 31 minutes later each time. Both match the edge-case runs. The rule's query matches `KVSYNC result=failed`, which also matches `failed-permanent`, so the **deliberate** failures of the edge-case certificates trigger it |
| `heartbeat`, sync app | **Fired at 16:12:13 and cleared at 16:58:14.** The rule was created at 16:05:05. The first `reconcile-complete` line was written at 16:10:00 and reached Log Analytics at 16:10:56, 77 s before the alert. The time of the rule's evaluation is not visible, so it is **not established** whether the first evaluation ran just before that line arrived (the rule working as on the production stack) or whether something else kept the line out of its count. The 46 minutes to clear are three further 15-minute evaluations plus about a minute, the pattern of section 6. The heartbeat of the renewal app did not fire |
| `replica-expiring` | Not triggered on this stack |

The rules evaluate the heartbeat every 15 minutes over 1 hour and the failures every 5 minutes over 15 minutes. **No e-mail was sent or checked** on any ARM stack: do not read these results as proof of delivery.

### What the logs show over 7 h 45 min

Log Analytics, 16:00 to 23:45 UTC, table `AppTraces`:

| | Sync app | Renewal app |
|---|---|---|
| `reconcile-complete` | 92 | 92 |
| Outcomes | `converged-noop` 402, `copied` 33, `failed-permanent` 10, `near-expiry` 6, `ignored` 2, `skipped-disabled` 2, `skipped-not-opted-in` 2 | `not-due` 189, `ordered` 6, `merged` 6, `started` 3, `busy` 1 |
| `failed-transient` | **None** | None |

All 10 `failed-permanent` lines belong to the edge-case certificates that were made to fail. A line reached the workspace mostly 8 to 56 s after it was written; the very first line of the renewal app took 199 s. Four error lines are not ours: "Exception encountered while listening to EventStream". Each falls in the same second as a `Stopping JobHost` line, and the host started 52 and 44 times in these hours because of redeployments and tests, so they look like host shutdown noise. That is the timing only, **not proven**. The one `busy` line (18:50:00, on the timer) is the renewal app's lease declining to run twice at once, which is what it is for.

### 10.1 Two events for one certificate imported it twice

**What happened.** In run 2 a destination held three versions of a certificate that the factory vault held twice. The log line "versions kept there: 3" was the only sign, because the check was too weak (section 8, item 12).

**Why.** The test certificates are valid for 30 days. Key Vault raises *CertificateNearExpiry* 30 days before expiry (the documentation says "triggered 30 days before the expiration date"), so a new 30-day certificate raises a new-version event and a near-expiry event together. Both land on the sync queue and the Functions host (`batchSize` 4) runs them on two threads. Both threads found the destination without the version, and both imported it.

With production lifetimes (199 days now, 99 and 46 days later) the two events are weeks apart. But the timer sweep and an event can still meet on one certificate, and `sync_certificate` is the single entry point for the event path, the sweep and the command line, so the lock covers all three.

**The fix.** `sync_certificate` takes a lock per certificate name (`_cert_lock` in `src/sync/kvsync/sync.py`). The second thread waits, finds the version in place and logs `converged-noop`.

| | Before the fix | After the fix |
|---|---|---|
| Live probe: lines in the log | two `copied`, 54 ms apart | one `copied` and one `converged-noop` |
| Live probe: the copy arrived after | 21 s | 13 s |
| Live probe: versions in the destination | **2** (expected 1) | **1** |
| Live probe: checks C0 to C4 | C3 and C4 failed | all passed |
| Offline test, 8 runs: "imports exactly once" | **Failed 8 of 8** | **Passed 8 of 8** |

Before the fix the host picked up the two queue messages 7 ms apart (20:21:17.674 and 20:21:17.681).

The live probe (`tests/live/race_probe.py`) deletes and purges one copy, waits for a moment between two sweeps, puts the two events on the queue at the same moment, and counts the versions. Each live result is **one run**. The offline test is the deterministic one: it replaces the vault with a fake that tracks versions and runs two threads at once. It was also run with the lock replaced by a function that does nothing, which is how the 8 of 8 above was obtained.

**What is still open.** The lock is per process. Flex Consumption can run several instances of an app, and two instances could still import one version twice. That would cost one extra identical version, never a failure or a wrong certificate, but it was **not tested and never seen**. The renewal function already had a lease in table storage that works across instances. The two `ignored` lines in the logs are the probe's own access-check event, which is not a certificate event.

## 11. The ARM template: production (private network)

`deploy/production/azuredeploy.json` deploys at resource-group scope into a network that already exists. It was tested on a sample landing zone (`deploy/production/examples/landing-zone.bicep`): a virtual network with a private-endpoint subnet and two subnets delegated to `Microsoft.App/environments`, five private DNS zones, and a second resource group for the factory. The destinations were the proof of concept's two **public** vaults, so no private endpoint to a destination vault was tested. The certificate authority was the private test CA. The stack was deleted after the tests.

| Item | Result |
|---|---|
| First attempt | **Failed after 731 s** with `ServiceAssociationLink ... Please check if 'Microsoft.App' is registered` (section 8, item 13) |
| After `az provider register --namespace Microsoft.App --wait` | **Succeeded in 186 s** |
| Redeploying the final template over the live stack | Succeeded in 2 min 8 s |
| End to end (section 2) | **11 of 11**, once. R1 merged 233 s after the request and was copied 9 s and 2 s later. R2 merged 285 s after the tag and was copied 5 s and 1 s later. Versions 2, 2, 2 |
| Access audit (section 3) | **14 of 14**, run twice |
| A closed vault | A read of the factory vault from outside the network returned **HTTP 403 `ForbiddenByConnection`** for a caller who held *Key Vault Certificate User* on it. The first check of this kind proved nothing (section 8, item 14) |
| Alerts | Both heartbeats fired before any sweep had run: the sync one at 16:33, seven minutes into the first attempt, and the renewal one at 16:43, 97 s after the second attempt had finished and before its first sweep. Each cleared 46 minutes after it fired, the pattern of section 6. That is the rule doing its job, and a first deployment will raise it. No other rule of the factory fired. (Two Sev 4 alerts from the lab's own monitoring baseline fired when the stack's workspace was deleted: they are not ours) |

**What this does not prove.** The factory vault's network settings were opened by hand to the operator's address for the end-to-end run, and the state was **not recorded**. The run therefore does not show that the factory works with the data plane closed to everything but private endpoints. The Terraform twin (`terraform/production`) was planned and never applied. Nothing was tested with DigiCert.
