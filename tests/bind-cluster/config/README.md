# BIND cluster configuration templates

These files are intentionally limited to the isolated Docker acceptance
environment. The runtime TSIG key and zone data are generated below
`tests/bind-cluster/runtime/` and are never copied from production.

The `upstream` configuration is a fourth, isolated authoritative fixture only;
it provides a known-positive `example.com` answer so the three-node RPZ
cluster can prove that a TLD deny response is policy-driven rather than a
normal NXDOMAIN. It is not a DNSGuard cluster node or a production dependency.
