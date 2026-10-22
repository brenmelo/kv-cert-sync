# Prior art

Checked on 2026-10-20. The question was: *has someone already published a way to issue a certificate once in a Key Vault and copy it to Key Vaults in other subscriptions, with renewal?*

**Short answer: parts of it exist; I found no public project that does all of it.** GitHub code search and some blog searches were not available to me, so this is **not proof that none exists**. Every row below was opened and read (README and repository metadata), not taken from a search snippet.

## What exists

| Project | What it does | Overlap with this repository | What it does not do |
|---|---|---|---|
| [Azure-Samples/keyvault-cross-region-replication-sample](https://github.com/Azure-Samples/keyvault-cross-region-replication-sample) (PowerShell, Bicep, no licence file, created 2026-06) | Event Grid `Secret/CertificateNewVersionCreated` to a function, plus a 6-hour timer sweep. Copies secrets **and** certificates. README says the managed identity approach works across subscriptions. Pester tests, alerts, health endpoint | Same trigger pattern (event plus timer). Certificates are copied | No opt-in tag, no loop guard, no thumbprint idempotency, no protection for a certificate someone created by hand in the destination, no CA ordering or renewal, no Terraform. System-assigned identity |
| [amgdy/keyvault-sync](https://github.com/amgdy/keyvault-sync) (C#, Bicep/azd, MIT, created 2026-09) | Timer-driven, mapping-driven sync. The *target* vault opts in with the tag `sync-source-keyvault-id`. HMAC integrity checks, blob lease and ETag state, durable write intent, soft-delete only, never purges, never adopts an unmanaged target | The best guard rails I found. Cross-subscription (same tenant only) | Timer only, no events. No CA ordering or renewal. No Terraform. Broad role assignments |
| [Azure/certlc](https://github.com/Azure/certlc) and the Architecture Center article [Certificate lifecycle on Azure](https://learn.microsoft.com/azure/architecture/example-scenario/certificate-lifecycle/) | Event Grid near-expiry event to an Automation runbook that renews from an **internal** (AD CS) CA | The "renew on the near-expiry event" idea | Internal or non-integrated CA scenario in one vault. No cross-subscription copy |
| [jclem2000/KeyVault-MultiRegion-Replication-Public](https://github.com/jclem2000/KeyVault-MultiRegion-Replication-Public) and [-Private](https://github.com/jclem2000/KeyVault-MultiRegion-Replication-Private) (Terraform) | Asynchronous two-region **secret** replication with Event Grid and Functions | Terraform, private networking variant | Secrets only (the word "certificate" does not appear in either README) |
| [bmkinney/KeyVault-MultiRegion-Replication-Private-Bicep](https://github.com/bmkinney/KeyVault-MultiRegion-Replication-Private-Bicep) (Python, Bicep) | Private two-region **secret** convergence | Python function, private design | Secrets only. States it is sample code, not for production |
| [polymind-inc/acmebot](https://github.com/polymind-inc/acmebot) (C#, Apache-2.0, about 1,100 stars) | Issues and renews ACME certificates **into one vault** | Mature issuance and renewal into Key Vault | Issues into one vault. No copy to other subscriptions |

## What Microsoft says

* **There is no vault-to-vault copy.** Backup and restore work only "within the same Azure subscription and Azure geography" ([Back up a Key Vault object](https://learn.microsoft.com/azure/key-vault/general/backup)).
* **Why a copy per subscription at all.** Front Door "currently only supports Key Vault in the same subscription" ([Front Door custom HTTPS](https://learn.microsoft.com/azure/frontdoor/standard-premium/how-to-configure-https-custom-domain)). Application Gateway can reach a vault in another subscription, but only when you configure it with ARM, CLI or PowerShell, not in the portal ([Application Gateway Key Vault certificates](https://learn.microsoft.com/azure/application-gateway/key-vault-certs)).
* **Why renewal is not automatic for a CSR.** For a CA that is not integrated "IssuerName is set to Unknown and Key Vault doesn't enroll or renew the certificate" ([Create and merge a CSR](https://learn.microsoft.com/azure/key-vault/certificates/create-certificate-signing-request)).

## Where this repository goes beyond what I found

* **CSR-mode renewal with a public CA**, including ordering at the CA and merging the returned chain, built so that a restart never orders twice.
* **Opt-in by tag** on the source certificate and a **loop guard** on the copies, so a copy can never be copied again.
* **Thumbprint idempotency and "never overwrite what you did not write".** A destination certificate without the origin tag is refused, not replaced.
* **Separate identities for the two jobs**: the sync function can read a private key but cannot create certificates; the renewal function can create and merge but cannot read a certificate's private key. That is how the role definitions are written. The positive paths are tested; I did not test the negative case (an attempt by the renewal identity to read a private key).
* Python on Flex Consumption with user-assigned identities, **in Terraform**.

## What is worth borrowing

* From `amgdy/keyvault-sync`: the durable intent record before each write, and soft-delete-only behaviour. Not built here.
* From the Azure sample: the retry helper, the alert rules and the health endpoint. The alert rules are built here; the health endpoint is not.
