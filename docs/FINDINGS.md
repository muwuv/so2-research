# Findings — internal structure and environment reporting in the Standoff 2 Android client

**Target** `com.axlebolt.standoff2` (Axlebolt / Standoff 2), version `1.1.0` (versionCode `203982`)
**Platform** Android, arm64-v8a, Unity IL2CPP
**Build analysed** the artefact as shipped on Google Play; SHA-256 of the analysed `libunity.so`
and of the analysed APK are listed in §7
**Class of issue** exposure of internal implementation detail; insufficient validation of a
client-supplied environment report; server-side device correlation

These findings were obtained by **offline analysis of the shipped binary** plus **read-only
introspection of the running process**. No third-party software was used to obtain them.

---

## 1. Executive summary

Five distinct issues, ordered by impact.

| # | Finding | Impact |
|---|---|---|
| 1 | The client reports its own root/device environment to the backend, which acts on it | Anti-abuse bypass |
| 2 | The backend correlates and bans **devices**, not only accounts | Account bans are trivially evaded |
| 3 | The complete internal class/method/field map is recoverable from the shipped binary | Cheat development cost ≈ zero |
| 4 | Configuration deserialisation bypasses property setters | Integrity checks on config are unreliable |
| 5 | A malformed environment report triggers a server-side `NullReferenceException` | Availability / robustness |

Findings 1 and 2 together mean that the current client-side anti-root design cannot work as
intended: the check result is a client-controlled field that is transmitted verbatim, and the
sanction is attached to a device identifier that a new account does not reset.

---

## 2. Finding 1 — the root/device verdict is a client-supplied field

### 2.1 What is transmitted

Sign-in is preceded by an `AppVerification` protobuf message. Recovered field set:

| field | type | semantics |
|---|---|---|
| `IsRooted` | `bool` | a root binary was found on the device |
| `Path` | `string` | the path at which it was found |
| `ContentHash` | `string` | digest of the file at that path |
| `AppSnapshot` | `bytes` | a snapshot of the application |
| `Token` | `string` | Play Integrity token |
| `Environment` | `message` | environment information |

The corresponding request/response types are present in the client as
`GuestAuthRequest/Response`, `BoltIdAuthRequest/Response`, `YandexAuthRequest/Response`,
`GoogleAuthIdTokenRequest`, `FacebookAuthRequest`, `AppleIdAuthRequest`, `HuaweiAuthRequest`,
`GameCenterAuthRequest` — i.e. **every** authentication path carries an environment report.

### 2.2 Why it matters

`IsRooted` is a plain managed `bool` field, written by a single accessor:

```
set_IsRooted:
    strb  w1, [x0, #0x18]
    ret
```

The value originates on the client, is serialised by client code, and is trusted by the backend.
The consequence is that the anti-abuse decision is exactly as strong as the honesty of the
client — and the honest client is the only client that is disadvantaged by it.

Concretely: a client that reports `IsRooted = false` is never challenged about a root binary,
because the backend has no independent view of the field's contents. The `Path` and
`ContentHash` fields are evidence attached to a claim that the backend itself can suppress.

### 2.3 Reproduction

1. Decompile / inspect the client's protobuf descriptors; the message set above is present in
   the shipped binary as plain type metadata.
2. Locate the environment-report builder in the sign-in path and observe it populating
   `IsRooted`, `Path` and `ContentHash` from a local filesystem probe.
3. Note that no server-side re-derivation is possible from the payload: `Path` and
   `ContentHash` are the client's own claims, and `AppSnapshot` is client-supplied bytes.

### 2.4 Remediation

* Treat the client report as **telemetry, not as an enforcement input**. Decide abuse
  server-side from signals that the client cannot author: Play Integrity device verdict,
  account age, match statistics, behavioural analysis.
* If a client-reported flag must be enforced, bind it to something the client cannot mint —
  for example require the environment report to be covered by a server-issued nonce and compare
  against a server-held expectation.
* Do not expose the raw `Path`/`ContentHash` of a root artefact to the client in the first
  place; it is an unnecessary disclosure of the detection mechanism.

---

## 3. Finding 2 — the backend correlates devices, not accounts

### 3.1 Evidence

Two messages in the same protocol family:

```
SMNewDeviceLogined { DeviceModel, Country, Ip }
OnDeviceBanned      { DeviceId }
```

The second is delivered to the client as the response to a ban, and carries a **device**
identifier rather than an account identifier.

### 3.2 Impact

Any mitigation that treats a ban as an account-level sanction is incomplete: the same device
that produced a ban keeps its association, so re-registering on the same hardware re-associates
the new account with the existing sanction.

Observed in practice during this research: two different accounts on the same emulator instance,
with an unchanged `android_id` and unchanged `ro.serialno`, were both banned. After rotating
the instance's `android_id` (which on this platform also rotates the serial), the environment
presents as a distinct device.

### 3.3 Remediation

* Make the device identifier **rotatable and non-permanent** where the platform allows it, and
  bind sanctions to the *account* plus a *risk score* on the device rather than to a hard
  device ban.
* If a device ban is required, publish an appeals path; today the client only learns the
  verdict, not how to contest it.
* Sanction a device only after independent evidence; a single client-reported `IsRooted` flag
  must not be enough to blacklist hardware.

---

## 4. Finding 3 — complete internal structure exposure

### 4.1 What leaks

The shipped `libunity.so` contains, in plaintext and in an easily machine-readable layout:

* every gameplay class name, e.g.
  `Axlebolt.Standoff.Gameplay.Player`,
  `Axlebolt.Standoff.Gameplay.PositionMarkers`,
  `Axlebolt.Standoff.Gameplay.RadarRender`,
  `Axlebolt.Standoff.Gameplay.Teams`,
  `Axlebolt.Standoff.Gameplay.Features.SpectatorOutline`,
  `Axlebolt.Standoff.Gameplay.Features.CameraShake`,
  `Axlebolt.Standoff.Gameplay.Features.Weaponry`
* every method name and its `.text` address
* every instance field name and offset

No debugger, no runtime instrumentation and no memory dump is required: the table is in the file.
`toolkit/` in this repository reconstructs the map from the binary alone, in minutes.

### 4.2 Why it matters

The protection layer replaces `global-metadata.dat` with native tables specifically so that
offline tooling cannot read the game structure. That goal is not met: the same information is
recoverable by other means, so the protection adds effort for legitimate analysts while costing
the publisher nothing.

The practical consequence for a publisher is that the cost of producing a working cheat for this
title is a few hours rather than a research project — the class layout, the field offsets and
the relevant game-logic methods are all directly available.

### 4.3 Remediation

* Strip or encrypt metadata strings at build time (the protector already encrypts *some*
  literals; class and method names are the remaining gap).
* Consider running gameplay-critical values (recoil, dispersion, hit validation) through
  server-authoritative simulation, so that knowledge of the client's internals does not translate
  into an advantage.
* Note that renaming alone is not a mitigation — §2.1 shows the client's own report is enough
  to be useful to an attacker.

---

## 5. Finding 4 — configuration deserialisation bypasses property setters

Weapon configuration is loaded from a binary/asset format and written **directly into the
instance fields**. The property setters (`set_RecoilAimMult`, `set_AccuracyAimMult`, …) are not
on that path.

Consequence: any integrity measure implemented as "sanity-check the values in the setter" is
bypassed by the normal loader, and conversely, instrumentation of the setters does not observe
the values actually in use.

This is reported as a finding because it is the reason a *client-side* validation of gameplay
configuration cannot be made reliable by patching the accessors alone.

**Remediation.** Validate the values after deserialisation, not in the property setters — i.e.
at the point where the configuration object is committed, or better, keep the authoritative
values server-side.

---

## 6. Finding 5 — malformed environment report crashes the sign-in path

### 6.1 Reproduction

Replace the `Path` field of the environment report with a null reference (equivalently: any
malformed report that leaves the field unset rather than empty). The server's sign-in handler
dereferences the field unconditionally and raises:

```
ERROR  An unknown error occurred.
We're already fixing this problem. Please try again later.
Code: SignIn [NullReferenceException]
```

The client presents this as a generic "server is broken" message, which makes it hard for
players to distinguish a server fault from a client fault.

Verified by A/B: with the report well-formed the sign-in succeeds; with `Path`/`ContentHash`
null it fails with the above, deterministically.

### 6.2 Impact

* Any client that emits a partially-populated environment report — a fork, an old build, a
  proxy, a modified client — locks itself out with an error message that misattributes the
  cause to the backend.
* The server turns untrusted input into an unhandled exception on an authentication path,
  which is an availability and error-handling weakness.

### 6.3 Remediation

* Treat every field of a client-supplied report as optional and validate before use; never
  dereference a nullable client field on the authentication path.
* Return a specific, actionable error code instead of a generic outage message, so that a
  malformed report does not present as a backend incident.

---

## 7. Artefacts and reproducibility

| artefact | sha-256 |
|---|---|
| analysed `libunity.so` (arm64-v8a, from the installed package) | `ba0966976204fa3f7a2755c9588d32299fe7eb794b712c9f1a444e046cbe7c13` |
| analysed APK | `d563f9646f6c4dee94e905026cc6608fd01716f9767eac4dbf38a0b2ffd65bff` |

All analysis in this report was produced with the scripts published alongside it; the method for
each finding is described in the corresponding section and implemented in `toolkit/`.

---

## 8. Disclosure

This report is intended for the publisher's own remediation, and — where a bug-bounty programme
applies — for submission there. Please do not redistribute the offsets in a form that enables
tampering with third-party installations.
