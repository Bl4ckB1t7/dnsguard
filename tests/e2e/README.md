# DNSGuard real isolated E2E

`run-all.sh` creates a uniquely named, test-owned Docker network, BIND Primary,
BIND Secondary, DNSGuard API/Web project and temporary runtime directory. It
uses generated test-only TSIG, Bootstrap Token and TLS material. It refuses
name collisions and never removes resources it did not create.

```bash
bash tests/e2e/run-all.sh
```

Set `E2E_KEEP=true` to keep only the resources created by this run for manual
inspection. The default cleanup removes only the recorded project/network and
runtime directory. It never uses a global Docker prune. A Markdown report and
redacted command evidence are written below `tests/e2e/runtime/`.

The browser phase is real Chromium against the isolated HTTPS API/Web service;
the existing fixture UI suite remains separate. The BIND phase uses the real
`internetsystemsconsortium/bind9:9.20` image and real `nsupdate`, SOA, RPZ and
recursive checks. Global Deny is enabled only after the whitelist is published
and synchronised. DNSSEC DO=1 upstream behaviour is reported separately and is
not claimed to be fully blocked by an NXDOMAIN response alone.

The older `tests/bind-cluster/run-acceptance.sh` job remains a separate legacy
TLD-deny compatibility harness. This modern flow deliberately tests only the
v1.2.0 Global Deny zone (`global-deny.rpz.local`); it does not silently treat a
legacy TLD fixture or its resolver failures as proof of the modern policy.
The isolated recursive BIND profile uses `qname-wait-recurse no` to make the
tested pre-recursion policy explicit; DNSSEC `DO=1` upstream leakage remains a
separate risk and is not claimed as blocked by this flow.
