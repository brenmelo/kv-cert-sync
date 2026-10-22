# Certificate authorities: DigiCert, GlobalSign, cost and the shrinking validity period

Researched 20 October 2026 from public pages only (no account created, no order placed, no form submitted).
Everything marked **unverified** could not be confirmed from a primary source. Re-check prices before you buy.

## 1. How a real DigiCert certificate differs from the test CA used in the proof of concept

| Step | Test CA (what was run) | Real DigiCert (what is different) |
|---|---|---|
| Key Vault creates a pending version and a CSR | Same | Same |
| Who signs | A private CA whose key sits in a Key Vault secret | DigiCert CertCentral, through its Services API |
| Domain control validation (DCV) | None | **Required.** DNS TXT, DNS CNAME, HTTP file or email, and it is repeated, see section 4 |
| Chain | Two certificates (leaf + test root) | Leaf + intermediate + root; DigiCert can return them as `pem_all` (root, intermediate, end entity) |
| Cost | None | Per order; **a reissue inside the order term is not charged again** |
| Key Vault's own issuer integration | Not used (issuer `Unknown`) | Key Vault's DigiCert integration only issues **OV and EV**. A DV or wildcard-DV certificate therefore also uses CSR mode with issuer `Unknown` |
| Renewal | The renewal function signs, merges, the sync function copies | The renewal function calls DigiCert (`reissue`), waits for DCV, downloads, merges. **This path has not been run against a live DigiCert account** |

The Key Vault merge, the Event Grid event, the sync to the other vaults and the App Gateway pickup are independent of the CA, so they behave the same.
What the proof of concept could not show is DigiCert's own behaviour: order approval, DCV timing, rate limits, and the exact shape of its responses.

## 2. What is the cheapest real DigiCert certificate for a test?

* **No DigiCert free trial or CertCentral sandbox could be verified.** The marketing pages block scripted access, and the `demo` hosts on dev.digicert.com are for DigiCert ONE, not CertCentral.
* **Cheapest verified list price:** GeoTrust DV, one domain (www and non-www), **USD 192 per year**, with "Reissue your SSL certificate as many times as needed with no extra cost" and a 30-day money-back guarantee (geotrust.com, a DigiCert brand site). Refund terms were not verified.
* GeoTrust DV wildcard: USD 816 per year. GeoTrust OV: USD 372 per year (wildcard USD 1,164). OV takes about a day because the organization is vetted.
* Resellers advertise RapidSSL/GeoTrust DV at about USD 14 per year. **Unverified**, and a reseller certificate is not managed through your own CertCentral account, so it would not test the CertCentral API.
* **The cheapest way to test the real path is a reissue.** If the customer already owns a DigiCert order for the certificate, reissuing it inside the order term is not charged again. Point the function at that order (tag `kvrenew-order-id`) and the marginal cost is zero. Ask the DigiCert account manager for a non-production container or a low-cost DV order for the first test.

## 3. Is GlobalSign cheaper?

**Not confirmed.** GlobalSign's shop prices are injected by JavaScript and could not be read, and its API (Atlas) is quote-based: sign-up ends with "your account manager will send you a quote".
What is known: GlobalSign has a REST API (login, validation policy, order, trust chain), a CNAME-based DCV delegation, free unlimited reissues, and the Key Vault integration supports it for OV and EV, the same as DigiCert.
The renewal function ships a DigiCert client and a test client. A GlobalSign client would be a third implementation of the same three-method interface (`submit`, `status`, `fetch_chain`).

## 4. Validity is shrinking: what does that change?

The CA/Browser Forum ballot SC-081v3 sets a schedule. The maximum validity and the period for which a CA may reuse a domain validation both fall:

| Certificates issued on or after | Baseline Requirements: must not exceed | Baseline Requirements: should not exceed | DigiCert publishes | Domain validation reuse (BR) |
|---|---|---|---|---|
| before 2026-03-15 | 398 days | | 397 days | 398 days |
| 2026-03-15 | 200 days | 199 days | **199 days** (already live since 2026-02-24) | 200 days |
| 2027-03-15 | 100 days | 99 days | 99 days | 100 days |
| 2029-03-15 | **47 days** | 46 days | **46 days** | **10 days** (DigiCert: 9) |

So "46 days by 2029" (DigiCert) and "47 days" (the Baseline Requirements ceiling) are both right: DigiCert issues one day under the ceiling.
Sources: CA/Browser Forum ballot SC-081v3 and Baseline Requirements section 6.3.2; DigiCert's change log and its 199-day knowledge-base article.

**What the proof of concept covers.** The renewal schedule. The window is `min(30 days, one third of the lifetime)`, a 365-day simulation shows no certificate lapsing, exactly one CA request per renewal, and a minimum remaining margin of 31 days at 199 days, 31 days at 99 days and 16 days at 46 days:

| Certificate lifetime | Renewals per year | Smallest margin before expiry |
|---|---|---|
| 199 days | 2 | 31.0 days |
| 99 days | 5 | 31.0 days |
| 46 days | 11 | 16.0 days |

**What it does not cover, and it is the real issue: domain validation.**
* From 2029 a CA may reuse a validation for only 10 days, so every 46-day certificate needs a fresh domain validation.
* DigiCert's knowledge base says public DV certificates "do not support domain validation reuse", so a DV wildcard needs a new DCV for every order or reissue today.
* DigiCert's DCV methods are DNS TXT, DNS CNAME (`_dnsauth` to `{token}.dcv.digicert.com`), HTTP file and email. The CNAME and TXT tokens are per order, so "you must create a new DNS record each time you validate or revalidate". A `persistent-txt` record stays in DNS, but DigiCert documents that it "does not eliminate the need to revalidate".
* DigiCert's stated automation path is ACME, with delegated CNAME validation, and it recommends ACME and its lifecycle manager because manual management becomes impractical.

**Consequence for this design.** Renewal timing is solved. Domain validation is the part that still needs a design before production at these lifetimes:

1. Put the zone in Azure DNS and give the renewal function a narrowly scoped role on that zone (`Microsoft.Network/dnsZones/TXT/write`, or CNAME) so it can publish the DCV token itself. The function's `DigiCertCaClient` already records the DCV token of each order; the publishing step is the missing piece.
2. Use DigiCert's ACME service with delegated CNAME validation, and let an ACME client (for example a Key Vault-aware ACME bot) own issuance for the DV certificates.
3. Keep the proof of concept's design for OV/EV certificates that DigiCert can validate through pre-validated domains, and use Key Vault's own DigiCert integration where the product allows it.

None of these is built or tested here. The 199-day cap also means a one-year order yields about two certificates, then the order itself must be renewed (`renewal_of_order_id`), which is a purchase. The function refuses to buy on its own (`DIGICERT_ALLOW_NEW_ORDER` is false by default).
