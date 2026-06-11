# Getting Started

Install locally:

```bash
npm install
npm link
```

Initialize policy:

```bash
vibeguard init
```

Check the whole current repository:

```bash
vibeguard check
```

Check another repository:

```bash
vibeguard check "/Users/you/Projects/CV Maker"
```

Check staged changes before commit:

```bash
vibeguard check --staged
```

Check a branch diff:

```bash
vibeguard check --base origin/main
```

Use JSON for automation:

```bash
vibeguard check --format json
```

VibeGuard runs locally and does not upload source code.
