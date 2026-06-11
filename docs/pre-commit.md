# Pre-Commit

Run VibeGuard against staged changes:

```bash
vibeguard check --staged
```

Example `.git/hooks/pre-commit`:

```bash
#!/bin/sh
vibeguard check --staged
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

Blocking findings return exit code `1`, which stops the commit.

