# Customer runbook: putting the certificate factory into an existing estate

For the platform and security teams that own the Key Vaults and certificates you already have. It goes from the decisions you take first, through the inventory and the deployment, to the first certificate, the vault-by-vault onboarding, the consumer cut-over, and how to back out. Related documents: [DESIGN-QA.md](DESIGN-QA.md) (why it is built this way), [OPERATIONS.md](OPERATIONS.md) (running it afterwards), [TEST-REPORT.md](TEST-REPORT.md) (the evidence) and [REQUIREMENTS-COVERAGE.md](REQUIREMENTS-COVERAGE.md) (what it does and does not address).

Every statement carries one of these labels, so that you know how far to trust it:

| Label | Meaning |
|---|---|
| **Tested** | It ran in the lab proof of concept, as Terraform or as the ARM template. The evidence is in the test report |
| **Tested once** | The ARM template for the private network ran **once** in the lab, on a sample landing zone (section 5.8) |
| **Planned only** | A `terraform plan` of the Terraform production stack. It was **never applied** |
| **Not tested** | Written, but never run, or no result exists |
| **Microsoft docs** | Documented behaviour, with a link. Not exercised here |
| **Judgment** | A recommendation. Reasonable people can differ |

**The one thing to know before you start:** the lab used a private test CA and three vaults. The DigiCert client has **never run**. The private-network variant was deployed **once**, as an ARM template on a sample landing zone (section 5.8); its Terraform twin was only planned. Plan a rehearsal (section 5.0) before you touch a production vault.

| Phase | What | Section |
|---|---|---|
| 0 | Decide | 1 |
| 1 | Prepare the people, tools, network and permissions | 2 |
| 2 | Inventory every vault, and decide what happens to each | 3 |
| 3 | Inventory the consumers | 4 |
| 4 | Deploy the factory | 5 |
| 5 | Issue the first certificate | 6 |
| 6 | Onboard the existing vaults, in waves | 7 |
| 7 | Cut the consumers over | 8 |
| 8 | Operate, roll back, decommission | 9, 10 |

## 0. What you are building, and what you are not

The **factory** is one new vault (the *factory vault*) in a hub subscription, with two function apps next to it. Certificates are issued or renewed in the factory vault. The **sync** app copies each certificate, with its private key, into every *destination vault* you name. The **renewal** app, for certificates that Key Vault cannot renew by itself, orders the new certificate at the CA and merges it. An event on the factory vault wakes the sync within seconds, and a timer sweep repairs anything an event missed. Three alert rules watch it.

Your **existing vaults are not replaced, moved or recreated.** Each becomes a destination: the factory adds one role assignment and one diagnostic setting to it and writes certificates into it. The applications keep reading their own vault in the way they do today.

It does **not**:

* find certificates that live outside Key Vault (devices, virtual machines, files);
* complete domain validation at the CA (not built; the real work for 47-day certificates, see [DESIGN-QA.md](DESIGN-QA.md), section 9);
* revoke a certificate, or delete a copy (it never deletes anything);
* make a consumer pick up a new version (some poll, some need a refresh, section 4);
* copy between tenants, or run in a sovereign cloud (one factory per tenant and cloud; none built outside the lab tenant);
* copy a certificate whose key is not exportable.

## 1. Decisions to take before you start

| # | Decision | Recommendation | Label |
|---|---|---|---|
| 1 | **How many factories** | One per trust boundary: per tenant, per cloud, and, only for a reason you can name, per environment tier or CA account. Never two that can issue the same certificate (split brain). Azure Commercial and Azure Government are two factories | Judgment ([DESIGN-QA.md](DESIGN-QA.md), section 4) |
| 2 | **Region of the factory** | A region with availability zones **and** managed cross-region failover for Key Vault. West US 3 and the two Brazil regions have none. Copies keep serving if the factory is down, but renewal pauses | Microsoft docs |
| 3 | **Which certificates first** | Three to five that are exportable, have one owner who can answer, and are read through a versionless URI. Start with the ones ordered once per vault today (section 3, the duplicates report): that is where the saving is | Judgment |
| 4 | **Which CA path** | See the table below | See below |
| 5 | **Network mode** | `terraform/poc` is public endpoints with RBAC, for a rehearsal. `terraform/production` is private endpoints, VNet-integrated apps and no public data plane | Production: Terraform **Planned only**, ARM **Tested once** (section 5.8) |
| 6 | **Role mode** | `destination_role_mode = custom` creates a role that can only read and import certificates, and needs role-definition rights in every destination subscription. `builtin` uses *Key Vault Certificates Officer*, which can also delete, purge, back up and restore | Custom **Tested** (14 of 14 access expectations); built-in **Not tested** |
| 7 | **Who may opt a certificate in** | Writing the `kvsync` tag on a factory certificate sends its private key to the named vaults. Restrict `certificates/update` on the factory vault to the factory team. Prefer **named destination keys** (`kvsync=app_eu,app_us`) over `kvsync=all` for production, so that a certificate reaches only the vaults that need it | Judgment ([DESIGN-QA.md](DESIGN-QA.md), section 6) |
| 8 | **Alert receivers** | A mailbox that your ticketing or paging tool ingests. The module supports **e-mail receivers only**. Verify the address (one-time code), and allow-list the Azure sender addresses ([OPERATIONS.md](OPERATIONS.md#e-mail-receivers)) | **Tested**: the lab's address was never verified, and most of the notifications were later found in Deleted Items |
| 9 | **Ownership** | One team owns the factory, its alerts and the CA credential. Each destination vault keeps its owner, who agrees to what is written into it | Judgment |
| 10 | **Names** | `suffix` (3 to 8 lower-case letters or digits) and **destination keys** (short, lower-case, stable). A key is what a `kvsync` tag refers to, and in Terraform it is the address of the vault's role assignment, so renaming a key replaces them (in the ARM template a key is only a label, section 5.8). Treat keys as permanent | Read from the code |
| 11 | **Deployment route** | Terraform (sections 5.1 to 5.7) or the ARM template (section 5.8). Both build the same factory from the same inputs, so pick the one your pipelines already run. The ARM route keeps no state file, and Azure itself pulls the function code, so no machine inside the network is needed for the code. Only Terraform has the Application Gateway test consumer | Terraform production **Planned only**. ARM production **Tested once** (test CA, public destination vaults, code deployed from outside the network) |

**Decision 4, the CA path**

| Certificate | Path | Label |
|---|---|---|
| OV or EV from DigiCert (or another CA that Key Vault integrates) | Create it in the factory vault with the integrated issuer. Key Vault renews it by itself. The factory only copies it: set `kvsync`, and do **not** set `kvrenew`. Microsoft: [Integrate a certificate authority](https://learn.microsoft.com/azure/key-vault/certificates/how-to-integrate-certificate-authority) | Copy of such a certificate **Not tested** (the copy only reads the certificate and its key, whoever signed it, from the code) |
| DV or wildcard-DV from DigiCert | CSR mode: issuer `Unknown`, tag `kvrenew=on`. The renewal app creates the request, orders it, merges the chain. Key Vault's own DigiCert integration does not issue DV, which is the gap this app fills | Logic **Tested** against a test CA. The DigiCert client has **never run** against DigiCert |
| A PFX you already own | Import it into the factory vault (section 6, route B) | **Tested** (T8, copied in 19 s) |
| Another CA | The renewal app supports `digicert` and the test CA only. Import the PFX each time, or write a client | **Not built** |

## 2. Prepare

### 2.1 People and permissions

Terraform is run by one person or one pipeline identity, called the *deployer* below.

| Who | Where | Needs | Why |
|---|---|---|---|
| Deployer | Hub resource group | Contributor and User Access Administrator, or Owner | Creates the resources and the role assignments on them |
| Deployer | **Each destination vault** | `Microsoft.Authorization/roleAssignments/write` (User Access Administrator or Owner on the vault, its resource group or its subscription) | Gives the sync identity its role on that vault |
| Deployer | **Each destination vault** | The right to write a diagnostic setting (Monitoring Contributor, Contributor or Owner) | The factory adds `audit-to-log-analytics` to every destination so that its log reaches the factory workspace. In the lab the deployer was Owner on both sides of the cross-subscription setting. **Narrower combinations were not tested** |
| Deployer | The hub and **every destination subscription**, only for `destination_role_mode = custom` | `Microsoft.Authorization/roleDefinitions/write` (User Access Administrator or Owner) | The custom role lists the hub and each destination subscription as assignable scopes. Without the right on all of them the apply fails with "does not have permission ... on the linked scope(s)". At most 2,000 scopes ([Custom roles](https://learn.microsoft.com/azure/role-based-access-control/custom-roles)) |
| Person who stores the CA credential | Factory vault | *Key Vault Secrets Officer*, **temporarily** | The production stack leaves no human with standing data access to the factory vault (`operator_object_id` is empty) |
| People who read the logs | The factory's Log Analytics workspace | Log Analytics Reader | [OPERATIONS.md](OPERATIONS.md#reading-the-logs) |

No Microsoft Entra roles and no app registrations are needed: the stack creates two managed identities and role assignments only.

### 2.2 Tools on the machine that runs `terraform apply`

* Terraform 1.9 or later (the lab used 1.16.6), with providers `azurerm` 5.10 or later and below 6, `azapi` 2.8 or later and below 3, `archive` and `time` (all pinned in `versions.tf`).
* **Azure CLI, signed in** to the right tenant. The module deploys the function code with `az functionapp deployment source config-zip --build-remote true` from a `local-exec` step, so the CLI must be present and authorised wherever Terraform runs.
* For the inventory and the tests: Python 3 and `pip install azure-identity azure-keyvault-certificates requests`.

### 2.3 Where the apply host runs (production only)

With private endpoints and public network access off, **the function apps' deployment endpoint is not reachable from the internet**. Microsoft: "the computer, runner, or agent that performs the deployment must have network connectivity to and DNS resolution for the private deployment endpoint" ([Deploy a package](https://learn.microsoft.com/azure/azure-functions/deployment-zip-push#deploy-a-package)). So run `terraform apply` from a self-hosted pipeline agent or a jump host inside, or connected to, the network that holds the private endpoints. **A public Cloud Shell or a GitHub-hosted runner cannot do it.** The same host is needed to store the CA credential (section 5.7). Whether the remote build succeeds through the private path was **not tested** (the Terraform production stack was never applied). Label: Microsoft docs. **With the ARM template** (section 5.8) Azure itself pulls the code, so the host is needed only for the CA credential: in the lab the code of a private-mode stack was deployed from a machine outside its network, and the apps then ran (**Tested once**).

### 2.4 Network inputs (production only)

The module creates **no** virtual network, subnet, DNS zone or resource group. Have these ready:

| Input | Detail | Label |
|---|---|---|
| Resource group | An **existing** group in the hub subscription | Read from the code |
| `function_subnet_ids.sync` and `.renew` | Two subnets, each delegated to `Microsoft.App/environments`, **at least /27** ([Flex Consumption networking](https://learn.microsoft.com/azure/azure-functions/flex-consumption-how-to#configure-virtual-network-integration)). The module takes one subnet per app. Whether the two apps may share one was not tested | Microsoft docs |
| `private_endpoint_subnet_id` | A subnet for the private endpoints: one for the factory vault, `blob` and `queue` for each app's storage, `table` for the renewal app's state, and `sites` for each app | Terraform **Planned only**; ARM **Tested once** (section 5.8) |
| `private_dns_zone_ids` | Existing zones: `privatelink.vaultcore.azure.net`, `privatelink.blob.core.windows.net`, `privatelink.queue.core.windows.net`, `privatelink.table.core.windows.net`, `privatelink.azurewebsites.net`. Leave one `null` when a central Azure Policy registers the DNS records for you | Terraform **Planned only**; ARM **Tested once** (section 5.8) |
| **A route and DNS from the sync app to every destination vault** | The module creates **no private endpoint for a destination vault**. If a destination has public access off or a firewall, the network team must provide a path: a private endpoint to that vault that the function's network resolves, or a virtual-network rule for the function subnet ([Key Vault network security](https://learn.microsoft.com/azure/key-vault/general/network-security)). A private endpoint to a vault in another subscription needs its connection approved on that side | Not tested. Only the **failure** case was run (section 3.3, row 3) |
| **Outbound HTTPS to the CA** | The renewal app calls `www.digicert.com` (`DIGICERT_API_BASE`). A VNet-integrated app needs an allowed route out (firewall rule or NAT). Not included in the cost estimate | Read from the code |
| Azure Monitor | Application Insights and Log Analytics keep **public ingestion and query endpoints** in both variants, with Entra-only sign-in (no instrumentation key). An Azure Monitor private link scope is **not built** | Read from the code |

### 2.5 Resource providers

Terraform is told not to register providers (`resource_provider_registrations = "none"`). Register these before the apply, or confirm they are registered:

* **Hub subscription:** `Microsoft.KeyVault`, `Microsoft.Storage`, `Microsoft.Web`, `Microsoft.App`, `Microsoft.EventGrid`, `Microsoft.ManagedIdentity`, `Microsoft.OperationalInsights`, `Microsoft.Insights`, `Microsoft.Authorization`, `Microsoft.Network`.
* **Every destination subscription:** `Microsoft.Insights`, because the factory writes a diagnostic setting there.

```bash
az provider show --namespace Microsoft.Insights --subscription <destination-subscription-id> --query registrationState -o tsv
az provider register --namespace Microsoft.Insights --subscription <destination-subscription-id>
```

### 2.6 Azure Policy

Read the policies that apply to the hub and to every destination before you plan. In the lab, the landing-zone policy:

* denied public network access, so four narrow, time-limited exemptions were needed for the public rehearsal (the production stack has no public data plane and should not need them);
* had already created a diagnostic setting called `setbypolicy` on every vault (section 3.3, row 9);
* added alert rules inside a resource group the test created, which made `terraform destroy` refuse to delete it until they were removed. Leave the provider's `prevent_deletion_if_contains_resources` safeguard on.

Look for anything that denies role definitions, role assignments, private endpoints without DNS, shared-key storage access (the design already turns it off), SKU `FC1` (Flex Consumption) or required tags.

### 2.7 State, the CA account, and the CA secret

* **State.** The production root declares an `azurerm` backend with `use_azuread_auth = true`. State holds resource IDs, the Application Insights connection string and role details: keep it in a storage account with Entra authentication and restricted access. A remote backend was **never tested** (the plan was made against a local backend).
* **CA account (DigiCert CertCentral).** An API key, the organisation ID, and the product's `name_id` that **your** account returns from its product list (`DIGICERT_PRODUCT` in the example is a placeholder). Know the payment method and whether your plan allows a reissue inside an existing order. `DIGICERT_ALLOW_NEW_ORDER` is `false` by default, so the app reissues inside an order you own and never buys one. All **Not tested** against DigiCert.

## 3. Inventory every vault

### 3.1 Run the inventory

The script is read-only. It uses `az login` (or any credential `DefaultAzureCredential` finds). Run it from a machine that can reach the vaults: a vault that is private-only can be read only from inside its network, and the script reports a vault it cannot read instead of skipping it.

```bash
# one row per vault: permission model, purge protection, network exposure, diagnostic settings
python scripts/inventory_vaults.py --diag --csv vaults.csv

# the certificates in every vault, and which names appear in more than one vault
python scripts/inventory_vaults.py --subscription <id> --subscription <id> --certs --json inventory.json
python scripts/inventory_vaults.py --certs --csv certificates.csv

# one wave only
python scripts/inventory_vaults.py --vault kv-orders-prod --vault kv-web-prod --certs --diag
```

**Tested** against the three lab vaults (it reads the certificates, counts diagnostic settings, excludes the factory's own copies, and reports an unknown vault name). The duplicates report has offline tests; it has not run against a large estate.

What each column means, and what to do with it, is in 3.3. The most useful output for the business case is the last block of the certificate run:

```
Same names in more than one vault. Each line is one certificate the factory could issue once and copy:
  *.example.com,example.com: 3 certificates in 3 vaults (kv-a, kv-b, kv-c)
```

Each such line is a CA order you pay for several times today. Copies that the factory made (tag `kvsync-origin`), disabled certificates and unreadable vaults are left out of that count.

### 3.2 Fill in the worksheet

Copy `examples/vault-worksheet.csv` and add one row per vault. The inventory fills the first half. The owner fills in the second half: the decision, the destination key, the wave, the consumers, how each consumer picks up a new version, the cut-over date, and the rollback.

### 3.3 Decide what happens to each vault

| # | What the inventory shows | What to do | Label |
|---|---|---|---|
| 1 | RBAC vault, reachable, exportable certificates | Add it to `destination_vault_ids`, opt the certificates in with its key | **Tested** (two subscriptions, two regions, public access) |
| 2 | **Access-policy vault** | The module's role assignment is ignored there. Either add an access policy for the sync identity with certificate permissions `get`, `list` and `import` (`az keyvault set-policy --name <vault> --object-id <sync principal id> --certificate-permissions get list import`, using the `principal_id` from the `identities` output), or migrate the vault to RBAC as its **own change**: inventory the policies, create the role assignments first, then switch, validate and monitor ([RBAC migration](https://learn.microsoft.com/azure/key-vault/general/rbac-migration)). Do not bundle the migration with this rollout. The role assignment the module creates is harmless in the meantime and is in place when the vault switches. A role with `Microsoft.KeyVault/vaults/write` can grant itself access to an access-policy vault ([Assign an access policy](https://learn.microsoft.com/azure/key-vault/general/assign-access-policy)) | Policy by hand **Not tested**. Migration steps: Microsoft docs |
| 3 | **Firewall on, or public access off** | Provide a network path from the sync function to it (section 2.4) | Failure **Tested**: public access off at one destination, the other destination had the rotation in 20 s, the broken one kept serving the old version and converged 160 s after access returned. The success path through a private endpoint is **Not tested** |
| 4 | Vault in **another tenant** | Not covered. A managed identity belongs to one tenant. Run a separate factory there | **Not tested** |
| 5 | Vault in a **sovereign cloud** | A separate factory in that cloud, with `key_vault_dns_suffix` set. Flex Consumption is not available in Azure Government at the time of writing, so the hosting plan would change | **Not built** |
| 6 | A certificate with the **same name** as one you will create in the factory | Never overwritten: the sync logs `failed-permanent` and leaves it. Rename one, or **adopt** it (section 7.4) | **Tested** (T4, T9, [section 4.1](TEST-REPORT.md#41-two-migration-cases-adopting-a-certificate-that-key-vault-renews-and-a-deleted-copy)) |
| 7 | A certificate issued **in that vault** by a Key Vault integrated CA, with auto-renew | Leave it running until the factory certificate is live and the consumer is cut over. Then adopt it (same name) or retire it (new name). **Adopting replaces its policy and Key Vault stops renewing it there.** Do not leave two things renewing one name | Adoption **Tested** with issuer `Self` and an auto-renew action; the integrated issuer itself **Not tested** |
| 8 | **Non-exportable** key | Cannot be copied. Reissue it in the factory vault with an exportable key | **Tested** (T2) |
| 9 | The vault already has **5 diagnostic settings** | Remove one before you apply. The factory adds `audit-to-log-analytics` to every destination (and to the factory vault). The limit is five per resource ([Diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/platform/diagnostic-settings)). In the lab every vault already had one from policy (`setbypolicy`) | Limit: Microsoft docs. Policy-made setting: seen in the lab |
| 10 | `Microsoft.Insights` not registered in the vault's subscription | Register it (section 2.5) | Microsoft docs |
| 11 | A certificate **named `ca-...`** | Never copied: the sync identity is refused every secret whose name starts with `ca-` (the CA credential's prefix) | **Tested** (HTTP 403 in the audit log) |
| 12 | A **soft-deleted** certificate of the same name sits in the destination | It blocks the write: *"is currently in a deleted but recoverable state, and its name cannot be reused"*. Recover it, or purge it if purge protection is off and you hold the right | Recover **Tested** (section 4.1); purge **Not tested** |
| 13 | The vault has certificate **contacts** | A copy's policy carries Key Vault's default lifetime action `EmailContacts` at 80% of its lifetime. Decide whether those contacts should hear about copies | Policy **Tested**; whether Key Vault then mails them was **Not tested** |
| 14 | A **large** vault, or many destinations | Onboard in waves. Key Vault allows 300 certificate imports per 10 seconds per vault and region ([service limits](https://learn.microsoft.com/azure/key-vault/general/service-limits)). The lab had three vaults and about ten certificates | Microsoft docs |
| 15 | The vault may be **recovered** from soft delete one day | Role assignments are **not preserved** when a vault is recovered. Run `terraform apply` again | Microsoft docs |
| 16 | **Purge protection off** | Works. Your own policy may require it | **Tested** (one lab destination has it off) |
| 17 | A vault **someone else owns** | The factory writes private keys into it and adds a role assignment and a diagnostic setting. Treat it as a change to their vault, and get their consent | Judgment |

## 4. Inventory the consumers

For every vault you onboard, list what reads it. The copy only helps once the consumer reads the new version.

| Consumer | How it reads the certificate | How fast it picks up a new version | Label |
|---|---|---|---|
| **Application Gateway** | A Key Vault secret ID, through a user-assigned identity with *Key Vault Secrets User* on that one secret. Bind the listener to the **versionless** secret ID | Polls about every four hours ([Microsoft docs](https://learn.microsoft.com/azure/application-gateway/key-vault-certs)). A forced refresh (update `--key-vault-secret-id` to the versioned ID, then back to the versionless ID with `az network application-gateway ssl-cert update`) served the new certificate **60 s** after it began | Forced refresh **Tested**. Unattended pickup **not observed**. A vault in another subscription **not tested** |
| **App Service** | Imported Key Vault certificate | Synchronised within 24 hours | Microsoft docs. **Not tested** |
| **Azure Front Door** | A Key Vault certificate. "Currently only supports Key Vault in the same subscription" | Not tested | Microsoft docs. Needs a destination vault in the Front Door's own subscription |
| API Management, AKS (CSI driver), virtual machines (Key Vault extension), appliances | Not studied | A property of that service, not of this project | **Not tested** |
| Your own code | Reads the secret with a managed identity | When it re-reads: at start-up, on a timer, or when you restart it | Judgment |

Record each consumer's pickup time in the worksheet. If a consumer cannot wait for its own refresh, add the forced refresh as a step after the copy.

## 5. Deploy the factory

Sections 5.1 to 5.7 use Terraform. Section 5.8 is the same deployment as an ARM template; read it first if your estate deploys ARM or Bicep.

### 5.0 Rehearse first

Run `terraform/poc` in a sandbox before the production stack. It creates its own spoke vaults and, if you ask, an Application Gateway, and runs with public endpoints. If your policy forbids public network access, you need the same exemptions the lab needed (four narrow, time-limited ones), or you rehearse the private mode in a sandbox that has the network. The rehearsal is where you meet your own policies before they stop the real change. **Tested** in the lab (`terraform/poc`). The ARM proof of concept (`deploy/poc`, behind the first Deploy to Azure button) is the same rehearsal without Terraform. **Tested** in the lab too, from a raw template address with the Azure CLI; the button itself was not pressed ([test report, section 10](TEST-REPORT.md#10-the-arm-template-proof-of-concept)).

### 5.1 Get the code

```bash
git clone <your copy of this repository>
cd kv-cert-sync/terraform/production
```

### 5.2 Configure

```bash
cp terraform.tfvars.example terraform.tfvars
```

| Variable | Set it to |
|---|---|
| `tenant_id`, `hub_subscription_id`, `location`, `resource_group_name`, `suffix` | The hub. The resource group must already exist |
| `destination_vault_ids` | A map of key to the full resource ID of each destination vault, in any subscription of the tenant. Start with the vaults of your first wave only |
| `private_endpoint_subnet_id`, `function_subnet_ids`, `private_dns_zone_ids` | Section 2.4 |
| `alert_email_addresses` | At least one (the plan refuses an empty list) |
| `digicert_settings` | The non-secret DigiCert settings (the API key is **not** a setting, see 5.7) |
| `destination_role_mode` | `custom` (default) or `builtin` |
| `sync_secret_name_prefix` | Optional. Limits which certificate names the sync identity can read in the factory vault, so a vault that holds other things stays out of reach |
| `reconcile_schedule`, `renew_schedule` | Default `0 */15 * * * *`. The lab used five minutes |
| `enable_renew_app` | `false` if every certificate comes from a Key Vault integrated CA or a PFX, and you do not need the renewal app |

Keep unrelated secrets out of the factory vault. It is dedicated to this purpose.

### 5.3 Initialise

```bash
terraform init \
  -backend-config="resource_group_name=<state resource group>" \
  -backend-config="storage_account_name=<state storage account>" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=kv-cert-sync.tfstate"
```

Add `-backend-config="subscription_id=<state subscription id>"` if the state account is not in your CLI's current subscription. **Not tested** (remote backend).

### 5.4 Plan

```bash
terraform plan -out=factory.tfplan
```

For the two-destination example the plan was **60 to add, 0 to change, 0 to destroy** (**Planned only**: made with placeholder IDs against a local backend):

| Resources | Count |
|---|---|
| Private endpoints | 8 |
| Role assignments | 15 |
| Role definitions | 2 |
| Alert rules, one action group | 4, 1 |
| Diagnostic settings (the factory vault and each destination) | 3 |
| Function apps (`azapi`), their service plans, storage accounts, containers, queues, one table | 2, 2, 2, 2, 2, 1 |
| User-assigned identities | 2 |
| Event Grid topic, subscriptions | 1, 2 |
| Key Vault, Log Analytics workspace, Application Insights | 1, 1, 1 |
| Code deployment steps, short waits for role propagation | 2, 2 |
| App setting updates (`azapi_update_resource`) | 4 |

Read it for what it must **not** contain: no resource group, virtual network, subnet, DNS zone or destination vault is created, and nothing in a destination vault changes except one role assignment and one diagnostic setting. Each extra destination adds those two, an update of the sync app's destination list, and an update of the custom role definition if the vault is in a subscription that is not yet listed.

### 5.5 Apply, from the connected host

```bash
terraform apply factory.tfplan
```

What the lab showed, and a customer should expect too:

* Role assignments take time. The ABAC probe waited 13 minutes before the first proof. A first failure about a permission in the first minutes is usually propagation. The module also waits 60 seconds after the assignments.
* If `az` is not signed in on the apply host, the code deployment step fails.
* If a policy denies something, the error names the policy. Resolve it and apply again. The apply is idempotent.

### 5.6 Verify

```bash
terraform output
python scripts/la_query.py --workspace <log_analytics_customer_id> --timespan PT1H \
  --query 'AppTraces | where Message has "result=reconcile-complete" | project TimeGenerated, Message | order by TimeGenerated desc'
```

* Within one `reconcile_schedule` period (15 minutes by default) **each app** logs a `result=reconcile-complete` line. If it does not, read the app's state from Azure Resource Manager (`properties.state`, not `az functionapp show`, which is empty for Flex Consumption apps; see [OPERATIONS.md](OPERATIONS.md#troubleshooting)).
* `terraform plan` again must say **No changes**.
* The three alert rules exist, and the action group's address is verified (open the mail with the one-time code, or select **Resend** on the action group).

### 5.7 Put the CA credential in the factory vault

Terraform does not create it, on purpose. From the connected host, with a temporary *Key Vault Secrets Officer* role on the factory vault:

```bash
az keyvault secret set --vault-name <factory vault> --name ca-digicert-api-key --file <key file>
```

The name must start with `ca-`: the renewal identity can read only secrets with that prefix, and the sync identity can read none of them (both enforced by an ABAC condition on the role assignment, **Tested**: HTTP 403). Never put the key on a command line or in a variable file. Delete the file and **remove the temporary role** afterwards. Rotating the key later means writing a new version of the same secret ([OPERATIONS.md](OPERATIONS.md#routine-jobs)).

### 5.8 The same deployment as an ARM template

`deploy/production` builds the same factory as `terraform/production`, as an ARM template compiled from Bicep. Use it when your pipelines already deploy ARM or Bicep, when you would rather not keep a Terraform state file, or when a platform team wants a template that it can review and start from the portal. The parameter for each Terraform variable is listed in [OPERATIONS.md](OPERATIONS.md#parameters-and-their-terraform-variables).

**Tested once:** a deployment on a sample landing zone (`deploy/production/examples/landing-zone.bicep`), with the test CA and two public destination vaults, started from the command line with a parameters file. It passed the end-to-end test (11 of 11) and the access audit (14 of 14), and a closed vault refused a caller who held a role ([test report, section 11](TEST-REPORT.md#11-the-arm-template-production-private-network)). **Not tested:** the portal form behind the Deploy to Azure button, a deployment started by a pipeline's service principal, a private endpoint to a destination vault, a DigiCert-backed deployment, and the factory vault's network settings during the end-to-end run (they were opened by hand and not recorded).

1. **Register `Microsoft.App`** in the factory's subscription: `az provider register --namespace Microsoft.App --wait`. Without it the deployment retries for about 12 minutes and then fails with `ServiceAssociationLink ... Please check if 'Microsoft.App' is registered`. **Seen** on the first attempt in the lab. The other providers of section 2.5 apply as well.
2. **Check the deployer's rights** (section 2.1 lists them and the header of `deploy/production/main.bicep` repeats them): Owner, or Contributor plus User Access Administrator, on the resource group; Owner or User Access Administrator on every destination vault; Contributor on every destination vault while `enableDestinationAudit` is `true` (the default); and the right to create custom roles at subscription scope.
3. **Create the resource group**, in the region of the factory. The template deploys into a group that exists, and the region of a group cannot change later.
4. **Fill in the parameters.** Six have no default: `suffix`, `destinationVaultIds`, `privateEndpointSubnetId`, `syncFunctionSubnetId`, `renewFunctionSubnetId` and `alertEmailAddresses`.
   * `destinationVaultIds` is an object, `{ "<key>": "<destination vault resource id>" }`, with vaults from any subscription of the tenant. A key is only a label (the app's destination list and the `kvsync` tag use it). The template names each role assignment from the vault, the identity and the role, so renaming a key replaces nothing. **Read from the template**, not tested.
   * `renewSettings` takes the non-secret DigiCert settings. The five `*PrivateDnsZoneId` parameters take the zones of section 2.4; leave one empty when a central policy registers the records.
   * **Pin `packageBaseUri`** to a commit or tag of this repository's `deploy/packages`, or host the two zips yourself. Its default is the `main` branch, which changes whenever the repository does. `deployCode` set to `false` skips the code.
5. **Deploy.**

   ```bash
   az deployment group create --resource-group <factory resource group> \
     --template-file deploy/production/azuredeploy.json --parameters @factory.parameters.json
   ```

   The lab deployment took **186 s** once the provider was registered. The Deploy to Azure button in the README opens the same template and asks for the resource group (**not tested**).
6. **Read the outputs**, above all `nextSteps`, and then do section 5.7 (the CA credential) **from a host that reaches the factory vault's private endpoint**: the template cannot put the key into a private vault for you. A heartbeat alert a few minutes after the deployment is normal, because no sweep has run yet. Read the log before you treat it as an outage ([test report](TEST-REPORT.md#8-what-went-wrong-while-testing), item 16).
7. **Verify** as in section 5.6. There is no `terraform plan`; `az deployment group what-if` compares the template with the live resources (**not tested** against a changed stack).

**Afterwards, the routes differ in two ways.** There is no state to protect, and there is no `destroy`: you remove the stack by deleting the resource group, then the policy exemptions you made, then the two custom roles (`KV Certificate Importer <suffix>` and `KV Certificate Issuer <suffix>`), which belong to the subscription. And an ARM deployment does not undo what the template no longer lists, so a destination vault that you take out of `destinationVaultIds` keeps its role assignment and its diagnostic setting until you delete them. See [OPERATIONS.md](OPERATIONS.md#changing-settings-and-code) (**not tested** on the production template).

## 6. Issue the first certificate

Do the first one with a **test or low-risk name** before a production one.

**Route A, a certificate request in the factory vault (CSR mode).** **Tested** with the test CA: a wildcard created this way was ordered at 07:50:00Z, merged 21 s later, and copied to two destinations 9 s and 10 s after that ([TEST-REPORT.md](TEST-REPORT.md), section 2). With DigiCert it is **Not tested**.

```bash
# edit the subject and names in the example first
az keyvault certificate create --vault-name <factory vault> --name <certificate name> \
  --policy @examples/policy-csr-wildcard.json \
  --tags kvsync=app_eu,app_us kvrenew=on kvrenew-order-id=<existing DigiCert order id>
```

The policy's issuer is `Unknown`, which is what makes it CSR mode. The key must be **exportable** and a new key must be generated on each renewal (`reuseKey: false`). `kvrenew-order-id` is the DigiCert order to reissue inside. Without it, and with `DIGICERT_ALLOW_NEW_ORDER` left `false`, the app will not buy anything.

**Route B, a PFX you already own.** **Tested** through the SDK (T8: copied in 19 s). The CLI form is **Not tested**.

```bash
az keyvault certificate import --vault-name <factory vault> --name <certificate name> --file <cert.pfx> --tags kvsync=app_eu,app_us
```

Supply the PFX password from a protected prompt or variable, not typed into the command.

**Route C, a Key Vault integrated issuer** (OV or EV). Create the certificate in the factory vault with the issuer you configured there, add `kvsync=<keys>` and no `kvrenew`. **Not tested.**

**Check it, whichever route:**

```bash
az keyvault certificate show --vault-name <factory vault> --name <certificate name> --query x509ThumbprintHex -o tsv
az keyvault certificate show --vault-name <destination vault> --name <certificate name> --query x509ThumbprintHex -o tsv
```

The two must be equal. The log carries `result=copied ... verified=cert-bytes-identical` for each destination. Copies appeared 2 to 108 seconds after an event in the lab, and the timer sweep is the guarantee. A copy carries the tags `kvsync-origin`, `kvsync-source-version` and `kvsync-synced-utc`, and never `kvsync` or any `kvrenew*` tag.

## 7. Onboard the existing vaults, in waves

### 7.1 Plan the waves

| Wave | Which vaults | Why |
|---|---|---|
| 0 | A non-production vault, with test certificates | Proves the network path, the roles, and the alert mail before a real name is involved |
| 1 | Two or three low-risk vaults with one certificate each | Proves adoption (7.4), a consumer cut-over (section 8), and the alert noise |
| 2 and later | The rest, sized so that one wave imports far fewer than 300 certificates in 10 seconds per vault | Throughput limit. Not tested beyond three vaults |

**Exit a wave** only when: every opted-in certificate has the factory's thumbprint in every named vault, the heartbeat alert is quiet, the consumer serves the new certificate, and the owner has signed off.

### 7.2 The change, per vault

Copy this into the change record.

```text
Before
[ ] Owner agrees, and knows a private key will be written into their vault
[ ] Worksheet row complete: decision, key, wave, consumers, pickup, rollback
[ ] Permission model handled (RBAC, or access policy get/list/import added by hand)
[ ] Network path to the vault exists from the sync function (private mode)
[ ] Fewer than 5 diagnostic settings; Microsoft.Insights registered in the subscription
[ ] No certificate named ca-*; same-name certificates handled (7.4); soft-deleted names recovered
[ ] Certificate contacts reviewed (the copy carries EmailContacts at 80%)

Change
[ ] Add the vault under its key to destination_vault_ids; terraform plan shows only the role assignment,
    the diagnostic setting, and the app-setting update (plus a role-definition scope for a new subscription)
[ ] terraform apply from the connected host
[ ] Wait for role propagation (allow about 10 minutes)
[ ] Tag the chosen certificates in the factory vault: kvsync=<key>   (prefer keys over "all")

Verify
[ ] Next event or sweep: the log shows result=copied (then converged-noop) with dest=<key>
[ ] Thumbprints equal (section 6)
[ ] The vault's audit log reaches the factory workspace (SecretGet by the sync identity)
[ ] The consumer is cut over (section 8) and serves the new thumbprint

After
[ ] The failures alert for this change has cleared, or is explained
[ ] The worksheet row is closed with the date
```

### 7.3 Opt certificates in and out

Everything is driven by tags on the certificate in the **factory** vault ([OPERATIONS.md](OPERATIONS.md#tags-on-certificates)). A tag change fires no Key Vault event, so the next timer sweep picks it up, up to one sweep period later (a new opt-in was copied 3.5 minutes after tagging with a five-minute sweep, **Tested**, T6). `kvsync=app_eu` reaches only that destination (**Tested**, T3). `kvsync=all` reaches every destination: do not use it where it was not meant.

### 7.4 Adopt an existing certificate of the same name

Use this when the destination already holds a certificate with the name you will give the factory certificate, and you want the consumer's URI to stay the same. **The whole sequence was tested** with a destination certificate that Key Vault renewed by itself ([TEST-REPORT.md](TEST-REPORT.md), section 4.1), using issuer `Self`. A certificate from a real integrated CA has the same lifetime action, but that exact case was not run.

1. Create the factory certificate under the **same name** and give it `kvsync=<key>` (section 6). The sync reaches the destination, finds an unmanaged certificate and logs **`failed-permanent`** ("destination already holds an unmanaged certificate ... tag that certificate `kvsync-origin=<factory vault name>`"). It **does not overwrite it.** Expect the severity-2 `failures` alert, once. Tell the on-call team beforehand.
2. In the destination, tag the existing certificate: `kvsync-origin=<factory vault name>` (for example `az keyvault certificate set-attributes --vault-name <destination> --name <name> --tags kvsync-origin=<factory vault name>`; the lab used the SDK).
3. The next sweep writes the factory's certificate into it, as a new version. In the lab this took 5 s once (the sweep happened to run right after the tag) and 3.4 minutes in another test. **The worst case is one sweep period.** The older version stays in the vault.
4. **Check the policy.** The destination certificate's policy was **replaced**: issuer `Self` with an auto-renew action became issuer `Unknown` with the lifetime action `EmailContacts` at 80%. Key Vault does not renew it there any more, which is what you want. The consumer's URI did not change.
5. The alert clears 26 to 31 minutes after the `failed-permanent` line, 27 in the lab (the timings are in the test report).

**Not tested:** tagging the destination certificate **before** the factory certificate exists. From the code, the first pass would then import without logging an error, which would avoid the alert. The risk is a certificate that renews itself in between. Try it in wave 0 first.

**Rollback of an adoption:** the previous version is still in the destination vault. Point the consumer at that version's ID, or import the old certificate again as a new version. Disabling the new version was **not tested**. The sync would write it again at the next sweep unless you opt the certificate out first (section 10.1).

### 7.5 If someone deletes a copy

A deleted copy blocks that destination, and only that destination. The others carry on (**Tested**: 6 and 10 s in two runs). While the copy stays deleted, every sweep logs `failed-transient` at ERROR and the `failures` alert fires (**Tested**: 56 s after the first such line). Recover it:

```bash
az keyvault certificate recover --vault-name <destination> --name <certificate name>
```

The destination then converged to the new version by itself, **157 s** after the recovery in one run and **15 s** in another (the host's retry of the queue message; **Tested**; the CLI command itself was not run, the lab used the SDK). After five failed attempts, about 10 minutes, that message goes to the `-poison` queue, which nothing watches, and only the sweep still tries. Purging instead of recovering was **not tested**. If nobody wants the certificate in that vault any more, take that key out of the `kvsync` tag, or the sync keeps trying and the `failures` alert keeps firing.

## 8. Cut the consumers over

1. Point the consumer at the **versionless** secret or certificate URI in **its own** vault. A versionless URI follows rotations; a versioned one never changes.
2. Confirm the consumer serves the factory certificate's thumbprint (for a web front end, read it from a TLS handshake).
3. Keep the old certificate, or the old version, until after the next rotation has reached the consumer. That is the rollback.
4. For an Application Gateway, make the forced refresh (section 4) a step in the pipeline that runs after the copy, unless a four-hour wait is acceptable.
5. When adopting (7.4) the URI does not change, so there is nothing to re-point: the only change is the new version.
6. **Rollback:** re-point the consumer to the old certificate or version. Nothing in the factory has to change.

## 9. Operate

[OPERATIONS.md](OPERATIONS.md) has the settings, tags, log lines, alerts, cost and troubleshooting. The routine, in short:

| When | What |
|---|---|
| Every alert | Read the log line named in the alert. A `failures` alert clears 26 to 31 minutes after the last failure line (27 measured), and a late "resolved" is not a failed fix |
| Weekly | Run the "last result per certificate" and "days left on every copy" queries ([OPERATIONS.md](OPERATIONS.md#queries-that-were-run-against-the-proof-of-concept)). Compare thumbprints for one certificate per destination |
| Monthly | Review who can write tags on factory certificates, and the factory's role assignments. Rehearse the alert path (send a test, check the mailbox rule) |
| Before the CA credential expires | Write a new version of the `ca-` secret. No restart is needed |
| When a certificate is renewed by hand | Check that its issuer is still `Unknown` or an integrated one, and that `kvrenew` is set only where intended |
| After a change to the CA or its API | Rerun a renewal on a test name |
| When a destination changes owner or subscription | Update `destination_vault_ids`, apply, and confirm the new role assignment |

## 10. Roll back and decommission

The sync **never deletes anything.** Every step below is yours to take.

| Goal | Steps |
|---|---|
| **Stop copying one certificate** | Remove the `kvsync` tag in the factory vault. The copies stay where they are. Delete them yourself if they should go |
| **Stop copying to one vault** | Remove its key from `destination_vault_ids` and apply. The role assignment and the diagnostic setting go; the copies stay. With the ARM template, deleting the key from `destinationVaultIds` does **not** remove them: delete the sync identity's role assignment and the `kvsync-audit-<suffix>` diagnostic setting on that vault yourself |
| **Give a consumer its own certificate back** | Re-point it at its old certificate or version (section 8), then stop copying (above) |
| **Pause the factory** | Stop the two function apps. The heartbeat alert fires about an hour later, so tell the on-call team. Copies keep serving |
| **Remove the factory** | Terraform: `terraform destroy` from the connected host. ARM: delete the resource group, then the two custom roles (section 5.8). The factory vault has purge protection, so its name stays reserved for the retention period (7 days). Destination vaults and their copies are untouched. Move the CA credential to wherever your other CA credentials live first |
| **Recover the factory** | Rebuild it with `terraform apply`; see [OPERATIONS.md](OPERATIONS.md#recovering-the-factory). **Described, not practised** |

## 11. What was tested, and what was not

| Step in this runbook | Status |
|---|---|
| The sync, the renewal logic with a test CA, the CLI route, a PFX import, forced rotation | **Tested** (public stack, three vaults) |
| Copy across two subscriptions and two regions, no overwrite of an unmanaged certificate, the `ca-` refusal | **Tested** |
| Adoption of a self-renewing destination certificate, and a deleted copy | **Tested** (section 4.1 of the test report) |
| Three alerts fired and cleared; a destination outage healed by itself | **Tested** |
| Application Gateway reads a copy; a forced refresh | **Tested** |
| The inventory script | **Tested** on three vaults; the duplicates report has offline tests |
| Everything in private mode, as the **ARM template**: private endpoints, VNet-integrated apps, code deployed by Azure, on a sample landing zone with a test CA and public destination vaults | **Tested once** (section 5.8, test report section 11) |
| Private mode as **Terraform**, a private endpoint to a destination vault, the factory with its data plane closed for the whole run | **Planned only / Not tested** |
| The DigiCert client, domain validation, DigiCert DNS-based validation | **Not tested / not built** |
| A remote Terraform backend; running Terraform from a pipeline; the Deploy to Azure button; an ARM deployment from a pipeline | **Not tested** |
| Access-policy vaults; vaults behind a firewall or private endpoint (success path); other tenants; sovereign clouds | **Not tested** |
| Consumers other than Application Gateway; an Application Gateway reading a vault in another subscription; unattended pickup | **Not tested** |
| Purging a deleted copy; tagging a destination certificate first; adopting a real integrated-CA certificate | **Not tested** |
| More than three vaults, more than ten certificates | **Not tested** |

## 12. Questions to settle before the pilot

1. How many regions, products and tenants does the first wave cover? Is Azure Government in scope, and is it a separate tenant?
2. Which CA account and product, and who approves a purchase? Is domain validation reusable, and for how long?
3. Which vaults use access policies, and who owns them?
4. Which vaults have a firewall or a private endpoint, and who owns the network path to them?
5. Which consumers read each vault, and how fast does each pick up a new version?
6. Who may write tags on a factory certificate, and who is paged by an alert?
7. Can the apply host reach the private endpoints? Is there a self-hosted agent? (With the ARM template the code deploys itself, but the CA credential still needs a host that reaches the factory vault.)
8. Which policies deny public access, role definitions or diagnostic settings, and who can grant an exemption?
9. Which certificates are non-exportable, and what depends on them?
10. Who owns the decision to rotate a certificate in an emergency, and is that the same person who can set `kvrenew-now`?
