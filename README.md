# dsc

`dsc` lets a web page sign a PDF with a **digital signature certificate (DSC)
on a USB token** (ePass2003, ProxKey, Watchdata, mToken, SafeNet eToken, any
PKCS#11 smart card) while the private key stays on the token.

It is a small local service that runs through [hey](https://github.com/kitsyai/hey):

```sh
hey up dsc
```

Then a site that uses [`@kitsy/pdf`](https://www.npmjs.com/package/@kitsy/pdf),
such as prashantsinha.com's PDF tools, finds the token, shows its certificates,
and signs. Before **every** signature, `dsc` shows a native dialog that the web
page cannot click:

> https://prashantsinha.com wants to digitally sign:
>
>     contract.pdf
>
> with the certificate of Asha Verma (ePass2003).
>
> Only continue if you started this signature yourself.

## How it works

```
browser tab ──► hey hub (127.0.0.1:8525) ──► dsc (127.0.0.1:<port>) ──► token driver ──► token
               origin allow-list, CORS,       consent dialog, PIN          signs inside
               X-Hey-Client, PNA preflight    (macOS/Linux), SHA-256       the token
```

- **The page** builds the PDF signature (PAdES) itself and sends `dsc` only
  the bytes to be signed: the CMS signed attributes, a few hundred bytes.
- **dsc** hashes them with SHA-256, asks the user, and has the token sign the
  hash with RSA PKCS#1 v1.5. It returns the signature. It never sees, stores
  or exports a private key, and it never sees the PDF.
- **Windows:** token drivers publish their certificates to the *Personal*
  certificate store. `dsc` signs through Windows (CNG, falling back to
  CryptoAPI). The token driver shows its own PIN dialog.
- **macOS and Linux:** `dsc` loads the token's PKCS#11 driver library. The
  consent dialog also asks for the PIN (macOS: a system dialog; Linux:
  `zenity` or `kdialog`). PIN-pad readers skip the PIN field.

## Platforms and drivers

Release binaries: Windows, macOS and Linux, each for amd64 and arm64. They're
pure Go with no cgo; PKCS#11 drivers are loaded at run time with
[purego](https://github.com/ebitengine/purego).

Install the driver that came with your token first. On macOS and Linux, `dsc`
looks in the usual install locations for ePass2003, ProxKey, SafeNet and
OpenSC drivers. If yours is elsewhere, point `dsc` at it:

```sh
DSC_PKCS11_MODULES=/path/to/vendor-pkcs11.so hey up dsc
```

`DSC_PKCS11_MODULES` is a path list (`:`-separated). Check what `dsc` can see:

```sh
dsc list                                    # or: dsc list --pkcs11 /path/to/driver.so
```

Only RSA certificates are supported, which covers Indian Class 3 DSCs.

## API

Bound to `127.0.0.1` only. Browsers reach it through the hey hub at
`http://127.0.0.1:8525/svc/dsc/...`.

| Method | Path | Body | Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | | `{"ok": true, "name": "dsc", "version": "…"}` |
| `GET` | `/certificates` | | `{"certificates": [{"id", "certificate", "label", "source", "subject", "issuer", "notBefore", "notAfter"}]}` |
| `POST` | `/sign` | `{"certificateId", "data", "document"}` | `{"signature"}` |

- `id` is the certificate's SHA-1 thumbprint (hex).
- `certificate` is the DER certificate, base64.
- `data` is the bytes to sign, base64, at most 16 KB.
- `document` is the file name shown in the dialog.
- `signature` is the RSA signature, base64.

Errors are `{"error": code, "message": text}`:

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `declined` | 403 | The user cancelled |
| `not_found` | 404 | The certificate wasn't found (token unplugged?) |
| `pin_incorrect` | 401 | Wrong PIN |
| `pin_locked` | 423 | The token PIN is locked |
| `unsupported_key` | 422 | The key isn't RSA |

## Security model

- **Consent per signature.** A native dialog names the requesting site (the
  `Origin` the hub let through), the document and the certificate holder.
  Text is sanitized (no control or bidi characters, length-capped).
  Signatures are made one at a time.
- **Only allowed sites get in.** Browsers can only reach `dsc` through the
  hey hub, which enforces its origin allow-list and a CORS preflight on
  every request (`X-Hey-Client` header).
- **No direct browser access.** `dsc` answers no CORS preflight, requires
  `X-Hey-Client`, and only accepts a loopback `Host`, so a page can't call its
  port directly, even through DNS rebinding.
- **No key material leaves the token.** A PIN typed into `dsc`'s dialog goes
  straight to the driver and is never stored or logged. On Windows, the
  driver's own dialog asks for the PIN.
- Programs already running on the computer can call `dsc` too, but they still
  trigger the consent dialog, and they could talk to the token driver directly
  anyway.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```sh
go test ./...        # includes a real PKCS#11 run against SoftHSM2 when installed
GOOS=windows go vet ./... && GOOS=darwin go vet ./...
go build ./cmd/dsc
```

The PKCS#11 tests need `softhsm2` and `opensc` (`apt-get install softhsm2
opensc`); they're skipped otherwise. The Windows store code is compiled and
vetted in CI but needs a Windows machine and a token to run.

Releases are built by GoReleaser when a `v*` tag is pushed. hey pins each
release's archive SHA-256 in its `dsc` pack.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Developed by
HEYPKV INNOVATIONS PRIVATE LIMITED. On contributions, see
[CONTRIBUTING.md](CONTRIBUTING.md).
