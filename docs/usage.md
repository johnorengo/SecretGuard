# Usage

Scan a repository:

```bash
secretguard scan ./my-project
```

Generate a JSON report:

```bash
secretguard scan ./my-project --json
```

Show version information:

```bash
secretguard --version
```

SecretGuard ignores common dependency, build, and cache directories such as `.git`,
`node_modules`, `vendor`, `__pycache__`, `dist`, and `build`.
