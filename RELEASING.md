# Releasing a new version

## Manual release

1. Update `VERSION` in `abnf.go`.
2. Commit, push, and release:

```bash
git commit -m "Release vM.m.p"
git tag vM.m.p
git push --follow-tags
```

## Automated release

```bash
make release VERSION=vM.m.p
```
