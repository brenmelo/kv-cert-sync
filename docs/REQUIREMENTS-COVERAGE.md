# Requirements coverage: what this design addresses, and what it does not

This page maps a typical set of requirements to what the repository delivers, and says how well each is backed.
The requirements come from a real scenario: a software provider with an Azure Key Vault and an Application Gateway in each of several
regions and subscriptions, one public wildcard certificate for customer-facing endpoints, and a certificate authority (CA) that
charges per order. Details that could identify anyone are left out.

Status key:

* **Addressed**: built and run in the lab. Evidence is in [TEST-REPORT.md](TEST-REPORT.md).
* **Addressed in design**: built, but only the parts that do not depend on the CA were run. The lab used a private test CA.
* **Partial**: some of it is covered. The gap is stated.
* **Not addressed**: not built or not tried.
* **Out of reach**: depends on a Microsoft product decision, not on code in a repository.

## The short version

| | |
|---|---|
| **Addressed** | Buying one certificate instead of one per vault. One CA order and one private key are copied, automatically, to vaults in other subscriptions and regions, and renewed on a schedule with no manual loading. Reference architecture, templates and best practices are in this repository. |
| **Addressed in part** | The worry that a copy can fail and break the lifecycle: failures are visible, alerted on, and repaired automatically (queue retry, then the timer sweep), but the design **does add moving parts**. Inventory. Consumers other than Application Gateway. Total cost, which falls but is not zero. |
| **Not addressed** | A free, Microsoft-native public CA comparable to AWS Certificate Manager. Azure Government. Copies between tenants. Automated domain validation, which is the real work for 46 and 47-day certificates. A live run against DigiCert, because no order was placed. |

**How far to trust the evidence.** Everything ran against a private test CA. The vault, Event Grid, copy and Application Gateway
behaviour does not depend on who signs the certificate, so it carries over. The DigiCert client **has never run against a live
DigiCert account**.

## Requirement by requirement

| # | Requirement | Status | What the lab shows | Gap, or what to do next |
|---|---|---|---|---|
| 1 | One certificate usable in every region and subscription, without one CA order per vault | **Addressed in design** | One CSR and one order; the signed certificate was copied to vaults in two subscriptions and two regions with the same thumbprint. A wildcard issued through the CLI route replicated to both | Run a live reissue against the CA. A reissue inside an existing DigiCert order is not charged again (CA's documentation) |
| 2 | Automatic renewal; no manual loading; ready for 46/47-day certificates | **Addressed** for renewal timing | The renewal function started, signed and merged on its own (122 s); a forced rotation merged in 253 s and both copies followed in about 10 s. A 365-day simulation shows 2, 5 and 11 renewals a year at 199, 99 and 46 days with at least 16 days of margin | **Domain validation is not built.** From 2029 a CA may reuse a validation for only 10 days. See [CERTIFICATE-AUTHORITIES.md](CERTIFICATE-AUTHORITIES.md) |
| 3 | Lower cost than one order per vault | **Partial** | N orders become one. A wildcard replaces many single-name certificates, which is a larger saving than the copy | The certificate still costs money, and the factory has a small run cost: about US$0.22 in the first 14 hours of heavy testing, partial and before private endpoints, and about US$8 a month for the public proof of concept and US$64 for the private production stack at list price, an estimate, not a bill (see [OPERATIONS.md](OPERATIONS.md#cost)). Whether Key Vault's per-renewal meter applies to the CSR path is unconfirmed |
| 4 | A failed copy must not silently break the lifecycle | **Partial: mitigated, not removed** | A failed destination does not stop the others. The queue retries every 2 minutes and the sweep repairs what is left (in the test the destination converged 160 s after it came back). Each failure is one log line. The failure and expiry alert rules fired about a minute after the first failing or warning line. The "no sweep for an hour" rule fired about 69 minutes after an app was stopped, because it looks back an hour. All three then cleared by themselves, 25 minutes, 45 minutes and 1 h 45 min later (see the alerting section of [TEST-REPORT.md](TEST-REPORT.md)). An end-to-end alert fires when a **copy** is close to expiry. Two migration cases were also run: a destination certificate that Key Vault already renews can be adopted (its policy is replaced, so Key Vault stops renewing it there), and a copy deleted in a destination blocks only that destination, raises the failure alert while it stays deleted, and heals by itself after it is recovered | More components means more things that can fail. The mitigation is monitoring and idempotence. A deleted copy is not repaired by the sync: its owner recovers it, or the destination leaves the tag |
| 5 | No complicated cross-subscription IAM for the applications | **Addressed, differently** | Applications read their own regional vault. One function identity holds a narrow import role on each destination; an audit of 14 expectations passed after an ABAC condition was added | One central identity must be reviewed. Role-definition writes are needed in each destination subscription (or use the built-in role). Each existing vault needs a decision; see the runbook |
| 6 | Why not simply share one vault across subscriptions? | **Answered** | [DESIGN-QA.md](DESIGN-QA.md) section 12 | None |
| 7 | Which lifecycle events can be automated with serverless functions? | **Answered; mostly demonstrated** | [DESIGN-QA.md](DESIGN-QA.md) section 13. Copy, forced rotation, pending-request merge, sweep and alerting ran live. Renewal when a certificate comes due was simulated, not waited for | Domain-validation publishing, revocation and decommissioning are not built |
| 8 | Reference architecture and best practices | **Addressed** | Diagram, two Terraform stacks, [DESIGN-QA.md](DESIGN-QA.md), [CUSTOMER-RUNBOOK.md](CUSTOMER-RUNBOOK.md), [OPERATIONS.md](OPERATIONS.md) | The production stack (private networking) is validated and planned, **not applied** |
| 9 | Free public certificates built into Azure, like AWS Certificate Manager | **Out of reach** | The CA step is pluggable (DigiCert and a test CA today), so an ACME CA could be added | Depends on Microsoft product decisions, which code in a repository cannot change. Check Microsoft Learn for the current Key Vault certificate capabilities before planning around it |
| 10 | Azure Commercial and Azure Government | **Not addressed** | The design is one factory per cloud (`key_vault_dns_suffix`) | Not tested in Government. Flex Consumption function apps are not available there at the time of writing (Microsoft Learn), so the apps need another plan. No copy across clouds or tenants |
| 11 | Discovery, inventory, visibility | **Partial** | A read-only script lists vaults (permission model, purge protection, network exposure, diagnostic settings) and certificates, and reports certificates that cover the same names in more than one vault. Its CSV feeds the runbook's per-vault worksheet. Every copied certificate carries tags and one log schema | Certificates outside Key Vault (devices, VMs, App Service uploads) are not found. The script was run only on the lab's three vaults |
| 12 | Consumers: Application Gateway, Front Door, App Service, API Management, AKS, VMs | **Partial** | Application Gateway served the copy from its regional vault. A forced refresh was picked up in about 60 s. It had not picked up the new version unaided after 91 minutes (the documented poll is about four hours); the gateway was then stopped by something outside the test | Front Door reads only a vault in its own subscription (Microsoft Learn). App Service re-syncs within 24 hours (Microsoft Learn). API Management, AKS and VMs were not tried |
| 13 | Customer-facing certificates only; DV is acceptable | **Addressed** | Opt-in is per certificate with a tag, so scope is exactly the certificates chosen. The CSR path issues DV and wildcard certificates | Key Vault's own DigiCert integration issues OV and EV only (Microsoft Learn) |

## What this design will not do

1. It does **not** make certificates free. It reduces how many you buy.
2. It does **not** prove the CA client. It proves everything around it.
3. It does **not** validate domains. At 46 or 47 days that is the main engineering item left.
4. It does **not** cover Azure Government or copies between tenants.
5. It does **not** remove the possibility of a failed copy. It makes a failure visible and repairs it on its own.
6. It does **not** manage certificates that are outside Key Vault.
7. It has **not** been run in production private-network mode.

## Questions that change the design

1. How many certificates, how many wildcards, and how many distinct names?
2. Regions, subscriptions and **tenants**. Is everything in one tenant? Is Government in scope?
3. Which CA and which product? Is there an existing order a reissue could use?
4. **How are domains validated today?** Who owns the DNS zones, and could they be in Azure DNS? This decides the answer for 46 and 47-day certificates.
5. Which consumers other than Application Gateway?
6. Do the existing vaults use Azure RBAC or access policies, and are they behind private endpoints or firewalls?
7. Who owns the factory vault, the alerts and the on-call rota?
8. Would an ACME CA such as Let's Encrypt be acceptable for some environments, non-production first?
