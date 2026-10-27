# Vale bounded editorial check

This is a one-shot local job, with no persistent daemon, ingress, database or cache configured. Runtime compatibility and dependency inventory require root qualification; configuration alone proves no deployment. Local synthetic rule Local.Guard reports CP080_FORBIDDEN_PHRASE. It does not establish facts, rights, editorial approval or publication authority. F04/F05 remain authoritative; no approval snapshot is generated.

Root acquisition: use the exact v3.25.1 release and commit recorded in component.json and public packet. Independently download/verify archive and checksum asset, inspect archive safely, record extracted executable digest separately, preserve upstream license, inventory dependencies/SBOM and scan. API archive metadata is not executable authentication. Do not install or sync external styles. Latest captured docs may exceed pinned version: required --no-global, --config, --output=JSON and --version must succeed on actual pinned binary, with no insecure fallback.

Run in root-controlled disposable Linux x86_64 executor with denied network, nonprivileged fixed UID/GID, read-only component/binary/input, private quota-limited tmp, one CPU, 1536 MiB RAM and enforced PID/disk limits. No host/private mounts or credentials. Actual target, UID/GID, sandbox and enforcement evidence are NOT_RUN. The Python wrapper is not an OS sandbox and cannot establish network isolation itself. Immutable executable/config plus exclusive read-only input ownership are required to avoid filesystem races.

Root commands (from repository root, shell placeholders replaced with reviewed absolute paths/digest):

```sh
CP080_VALE_BINARY=/approved/vale CP080_VALE_SHA256=<verified-executable-sha256> python -B -m unittest discover -s deploy/components/vale/tests -v
python -B deploy/components/vale/lint.py --binary /approved/vale --executable-sha256 <verified-executable-sha256> --input-root /approved/synthetic synthetic.txt
```

Missing real binary variables deliberately fail setup with NOT_RUN, rather than skip/pass. Tests authored here were not executed. Warning findings exit zero but retain HOLD; wrapper errors exit two and are never clean lint. Only one direct-child .txt UTF8 regular file is accepted; no user-controlled config, package, script or environment is forwarded. Reports omit source matches/messages, stderr and paths. Artifact binds input/config/rule/executable digests and version. Native owner must bind artifact to immutable client/action/revision and revalidate current approval; stale/missing/wrong-client/changed-revision authority never becomes authorization from lint. Unknown external outcome has no automatic retry; this job performs no external operation.

Backup reviewed config/rule/pins, source revision and approved binary receipt together. Restore or rollback the complete immutable reviewed set in an isolated executor, verify all digests and rerun real clean/forbidden regressions. A changed or disabled rule without reviewed pins fails closed. Restore/restart emits a new held artifact; do not reuse prior approval or replay an outbound action. Root must perform actual restore/rollback and no-network probes; these are NOT_RUN.

Original acceptance accounting:
1. Exact upstream metadata recorded; runtime/dependency compatibility and downloaded artifact verification blocked on root.
2. Repeatable root acquisition/run instructions supplied; disposable installation NOT_RUN.
3. Negative tests supplied; execution and executor access/egress/privacy evidence NOT_RUN.
4. Held restart semantics implemented; actual backup/restore/rollback qualification NOT_RUN.
5. Native bounded CLI classification justified; no Quadlet/container artifact claimed. Root validates isolation target.
6. Scoped executable tests supplied; candidate static AST only; tested executable revision and independent review NOT_RUN.

Do not accept any of the six criteria from this document alone. All 576 runtime IDs, G02 and production remain held.
