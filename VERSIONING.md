# Net-Watcher Versioning

## Semantic Versioning

Format: `MAJOR.MINOR.PATCH`

### Commit Triggers
- `feat:` → Minor version bump (1.0.0 → 1.1.0)
- `fix:` → Patch version bump (1.1.0 → 1.1.1)
- `BREAKING CHANGE:` → Major version bump (1.1.1 → 2.0.0)

## Release Workflow

### Stable Release
```bash
git tag v1.2.0
git push origin v1.2.0
```

### Development Build
```bash
make dev-release
```

### Manual Release
```bash
make release VERSION=1.2.1
```

## Build Artifacts

Linux-only (uses AF_PACKET raw sockets):
- `net-watcher-linux-amd64`
- `net-watcher-linux-arm64`
