<!-- Thanks for contributing to Reconta! -->

## What does this PR do?

<!-- A clear, concise description of the change. -->

## Type of change

- [ ] Bug fix
- [ ] New signature(s)
- [ ] New module / tool integration
- [ ] Reporting / output improvement
- [ ] Docs
- [ ] Other:

## How was it tested?

<!-- Commands you ran, targets (use example.com), and what you observed. -->

- [ ] `make lint` passes (ShellCheck)
- [ ] `bash -n` clean on changed scripts
- [ ] Smoke run completes: `./reconta.sh example.com -p quick`

## Checklist

- [ ] External binaries are guarded with `require_tool` / `have_tool`
- [ ] New data is de-noised before it reaches a top-level output file
- [ ] Top-level output stays broad-topic (no new tiny files without discussion)
- [ ] Docs/README updated if behavior or flags changed
- [ ] I confirm this change is not primarily for unauthorized or malicious use
