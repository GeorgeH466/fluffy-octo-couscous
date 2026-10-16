# LEGAL

> **This file is not legal advice.** It is a plain-language summary of the risks
> that come with the capabilities in this repository, written to make you stop
> and think before you point anything at a network you do not own. Laws differ
> by country, state and circumstance, and they change. If you have any doubt,
> ask a lawyer in your jurisdiction, or do not run the tool.

---

## 1. The notice you accepted

On first run the deck prints this and requires an explicit answer:

```
AUTHORISED USE ONLY

  cyberdeck-arsenal contains wireless, network and radio tools that are
  illegal to use against systems, networks or devices you do not own or do
  not have written permission to test.

  By continuing you confirm that:
    - you own the equipment you are about to test, or
    - you hold current, written authorisation from the owner, and
    - you will comply with the radio regulations and computer-misuse laws
      that apply where you operate.

  Unauthorised access to computer systems is a criminal offence in most
  countries, including under the Computer Misuse Act 1990 (UK), 18 U.S.C.
  § 1030 (US) and the EU Directive on attacks against information systems.
```

Until you acknowledge it, `general.authorised_use_acknowledged` stays `false` and
the active modules refuse to run. That gate exists to make sure the decision is
deliberate, not accidental. It is not a licence, and acknowledging it grants you
nothing — it only records that you were told.

## 2. What is in this repository

| Category | Examples | Typical risk |
| --- | --- | --- |
| **Passive receivers** | probe logging, BLE scanning, ARP watching, SDR, ADS-B, pager, TPMS | Low to moderate: receiving is one thing, intercepting communications another |
| **Active recon** | port scanning, service enumeration, web fingerprinting | **Requires authorisation.** Scanning a system you do not own can be an offence in itself |
| **Access tools** | handshake capture, PMKID, password cracking, exploitation | **High.** Unauthorised access is a criminal offence nearly everywhere |
| **Interception tools** | responder, MITM, evil twin, captive portal | **High.** Intercepting communications is separately criminal in many jurisdictions |
| **Defensive/monitoring** | rogue AP detection, USB watcher, hardening, evidence hashing | Low, but the data you collect may still be personal data |
| **Concealment** | decoy screens, hollywood mode | Legitimate opsec; do not use it to hide activity from someone entitled to see it |

## 3. Computer misuse and unauthorised access

Every jurisdiction listed below criminalises access to a computer or network
without authorisation, and most add aggravated offences for causing damage,
impairment or disruption:

* **United Kingdom** — Computer Misuse Act 1990, sections 1–3ZA. Section 1 is
  "unauthorised access to computer material", and it does not require any damage
  or intent to steal data. Port scanning, banner grabbing and even logging into a
  device with a default password can fall inside it. The maximum penalty for the
  basic offence is two years' imprisonment.
* **United States** — 18 U.S.C. § 1030 (Computer Fraud and Abuse Act). Both
  criminal and civil liability attach; statutory damages start in the thousands
  of dollars and the definition of "exceeds authorised access" has been litigated
  for decades. State laws such as California's Penal Code § 502 add more.
* **European Union** — Directive 2013/40/EU on attacks against information
  systems, implemented in each member state's criminal code (in Germany
  §§ 202a–202c StGB, in France Articles 323-1 to 323-3 of the Penal Code).
* **Australia, Canada, New Zealand, India, Japan** — Criminal Code Act 1995
  (Cth) Part 10.7, Criminal Code s. 342.1, Crimes Act 1961 ss. 249–252, IT Act
  2000 ss. 43/66, and the Unauthorised Computer Access Act respectively.

**Consent matters more than intent.** "I was only testing", "I did not change
anything" and "it was open" are not defences. Neither is "I found a
vulnerability" — discovery is not permission. Permission must come from someone
who is actually entitled to give it, must cover the specific systems and the
specific activities, and must still be valid on the day you work.

## 4. Wireless and radio regulation

Radio is regulated separately from computer law, and the rules catch activity
that computer law does not.

**Transmitting**

* **UK** — Wireless Telegraphy Act 2006. Transmitting on a frequency without a
  licence is an offence, and Ofcom enforces it. Deauth frames, a fake access
  point, a rogue cellular node: all transmissions.
* **US** — Communications Act 1934 as amended, enforced by the FCC; 47 CFR
  Part 15 governs unlicensed operation, and Part 97 covers amateur bands.
  Transmitting outside the permitted power, band or duty cycle is a violation
  even with the right equipment.
* **Elsewhere** — assume a national regulator with its own limits, and assume
  the ability to detect you. Transmissions identify themselves.

**Intercepting**

* **UK** — Regulation of Investigatory Powers Act 2000 (as amended by the
  Investigatory Powers Act 2016) makes it an offence to intentionally intercept
  communications without lawful authority. Section 1 does **not** require
  transmitting anything.
* **US** — Wiretap Act, 18 U.S.C. §§ 2510–2523; and 47 U.S.C. § 605 for radio.
  There is an exception for communications that are readily accessible to the
  general public, which does **not** cover encrypted traffic you have broken or a
  private network you are not a member of.
* **EU** — ePrivacy Directive 2002/58/EC and member-state implementations.

**Listening**

* Broadcast and amateur transmissions are generally lawful to receive.
* Pager traffic, TPMS sensors, key fobs, doorbells, tyre-pressure telemetry and
  similar carry no expectation of privacy, and receiving them with an SDR is
  lawful in many countries — but *decoding further*, *retaining*, *publishing*
  or *storing personal data* extracted from them steps into interception and data
  protection law. A garage door code you captured is not yours to replay.
* **Replay and injection** (re-transmitting a captured code) is transmission,
  and for vehicle key fobs and alarm systems there is often a specific offence
  alongside the theft offence.

**Practical rule:** receive only what you are entitled to receive, do not decode
or retain more than your purpose requires, and do not transmit at all unless you
hold authority, a licence or an experimental exemption that covers it.

## 5. Passwords, hashes and cryptography

* Cracking a hash you found on your own system is unremarkable.
* Cracking a hash belonging to someone else, or using recovered credentials to
  access anything, is unauthorised access — the law does not care that the
  password was weak.
* Key material, certificates and vaults you obtained in the course of an
  authorised test must be handled as the engagement contract says: usually
  destroyed or returned, never kept.
* Export controls cover strong cryptography and certain exploitation tooling in
  some countries. Do not ship this software into a jurisdiction where that is a
  problem.

## 6. Data protection and privacy

Even lawful testing generates personal data — MAC addresses, SSIDs, hostnames,
user agents, GPS tracks, Bluetooth device names. In the UK and EU, and
increasingly elsewhere:

* A **lawful basis** is required to process personal data (UK GDPR / EU GDPR
  Article 6); legitimate interests or contract, not curiosity.
* **Minimisation**: do not retain what you do not need. The suite's
  `monitoring.retention_days` default of 30 days exists for this reason.
* **Security**: captures in `captures/`, reports in `reports/` and notes in
  `vault/` are all personal-data stores. Vault them or destroy them when the
  engagement ends. `utilities/self_destruct.sh` is provided for exactly that.
* **Subject access**: a person whose MAC address you logged may have a right to
  know. Think about whether you could answer that question before you collect.
* **Passive collection in public spaces** — even probe logging in a street or a
  shopping centre raises questions under the UK's data protection regime. Prefer
  the smallest collection that answers your question, and prefer aggregated
  counts over raw identifiers.

## 7. Engagements and authorisation

Before running anything active, you should be able to answer all of these:

- [ ] **Who** gave permission — name, role, organisation?
- [ ] **What** exactly is in scope — hosts, subnets, SSIDs, physical sites,
      radio bands, frequencies, times?
- [ ] Is the permission **written**, dated, and valid today?
- [ ] Are **third parties** in scope by accident? Office WiFi often belongs to
      the landlord or a managed-service provider, not your client.
- [ ] **Rogue devices** — home devices, staff phones, IoT: who agreed to those?
- [ ] **Out-of-scope neighbours**: is the test network radiating into a
      neighbouring company's network? What is your containment method?
- [ ] **Data handling**: what happens to captures and reports at the end, and
      who destroys them?
- [ ] **Insurance and contractual cover**: is there a clause that says you are
      allowed to do this, and a liability position if something breaks?
- [ ] **Emergency contact**: who do you call if a service falls over at 02:00?
- [ ] **Deconfliction**: does the client's SOC/MSP/ISP know you are testing, so
      they do not treat you as an intrusion?
- [ ] **Regulatory limits**: does the engagement need anything beyond the
      client's consent (a radio licence, landlord consent, an ISP agreement)?

Anything you cannot tick is a boundary to be agreed before you begin, not after.
Write the answer down, and keep it with the engagement.

## 8. Where this platform will not help you

This suite is defensive and laboratory tooling. It is not:

* a way to test a network you have no authority over,
* a way to "see if the neighbours' WiFi is secure",
* a way to map, record or watch people you do not have authority over,
* a way to hide unauthorised activity from the people entitled to see it.

The decoy and camouflage features in `aesthetic/decoy/` exist for operational
security and for protecting a machine being used for lawful work in a public
place. Using them to conceal unlawful activity is an aggravating factor in every
jurisdiction.

## 9. Reporting a vulnerability you find

If you discover a vulnerability, even accidentally:

1. **Stop.** Do not enumerate further, do not pivot, do not download data.
2. **Document** the minimum: timestamp, the host, what you observed.
3. **Report** it to the owner or vendor through their disclosure channel, or a
   national coordinator (NCSC in the UK, CERT/CC or CISA in the US, the relevant
   national CERT elsewhere). Good-faith disclosure is protected in some
   jurisdictions by safe-harbour provisions — but not all, and the protection is
   rarely automatic.
4. **Do not publish** before a fix exists and a disclosure date is agreed.

## 10. Warranty and liability

This software is provided under the MIT Licence, "as is", without warranty of
any kind. The authors and contributors accept no liability for any loss, damage,
service interruption, data loss, prosecution, or other consequence arising from
its use. You are responsible for how you use it, for complying with the law
where you are, and for obtaining any authorisation, licence or consent that
applies.

If you are unsure whether something is lawful: **do not do it.** A tool that
stays in the bag has never put anyone in court.

---

*See also: [QUICKSTART.md](QUICKSTART.md) · [CONFIGURATION.md](CONFIGURATION.md) ·
[HARDWARE.md](HARDWARE.md). The full licence text is in [../LICENSE](../LICENSE).*
