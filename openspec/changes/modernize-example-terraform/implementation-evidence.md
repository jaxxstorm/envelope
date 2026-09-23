# Implementation Evidence

## 2026-09-06

- `terraform fmt -check` passed for `example/terraform`.
- `terraform init -backend=false` downloaded
  `terraform-aws-modules/vpc/aws` v6.7.2 for both root module instances and
  Terraform test module instances. It then stopped at the root's declared Core
  constraint: the available Terraform is v1.9.0 while this root requires
  `>= 1.10.1, < 1.11.0`.
- `terraform validate` and `terraform test` were attempted after initialization
  and stopped at the same unsupported-Core gate. Consequently no infrastructure
  or targets plan was produced or reviewed in this environment.
- `python3 scripts/test_docs.py` passed (18 tests).
- `shasum -a 256 -c SOURCE.sha256` passed for every vendored cloud-init input.
- `openspec validate --all --strict --no-interactive` passed (9 items).
- `git diff --check` passed.

Terraform's dependency lock file records provider packages, not registry module
archives. The existing `.terraform.lock.hcl` retains the locked AWS and
cloud-init provider checksums; the exact v6.7.2 module selection is declared in
both module blocks and was confirmed by the initialization download above.

No AWS resources, Tailscale devices, credentials, or live plans were created.
