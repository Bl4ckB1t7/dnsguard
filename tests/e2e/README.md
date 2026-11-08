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
not claimed to be fully blocked by an NXDOMAIN response alone. To opt into a
controlled, isolated upstream observation (never a public DNSLog), run:

```bash
E2E_DNSSEC_OBSERVE=true bash tests/e2e/run-all.sh
```

CI enables this matrix for the real E2E job. Locally, this enables query logging only in the test-owned authoritative upstream,
issues unique names for A, AAAA, TXT, CNAME, DNSKEY and DS across RD=0/1 and DO=0/1, repeats cold/hot-cache and whitelist checks, and
records the client response plus whether each complete name appeared in that log. The observation is
reported as `PASS`, `FAIL`, or `NOT RUN`; it does not weaken the normal Global
Deny gate or hide a QNAME observed upstream. The local default remains `NOT RUN`, while the CI E2E job fails when the controlled matrix finds a real upstream leak.

The older `tests/bind-cluster/run-acceptance.sh` job remains a separate legacy
TLD-deny compatibility harness. This modern flow deliberately tests only the
v1.2.0 Global Deny zone (`global-deny.rpz.local`); it does not silently treat a
legacy TLD fixture or its resolver failures as proof of the modern policy.
The generated RPZ package uses `qname-wait-recurse no break-dnssec yes` in the
isolated recursive profile. This permits the explicit Global Deny RPZ rewrite
for DNSSEC-bearing responses while leaving `dnssec-validation` enabled; it is
an administrator-reviewed BIND policy trade-off, not a universal DNSSEC or
DNS-tunnel guarantee. The test report records the exact profile and remains
limited to the controlled BIND/upstream fixture.
