# git-recrypt

Retroactively introduce git-crypt to existing repos by rewriting history.

`git-recrypt` replays every commit of an existing git repo into a fresh target repo where git-crypt's clean filter encrypts matched files from the very first commit. The source repo is never touched.

---

## Prerequisites

- Python 3.12+
- `git`
- `git-crypt` (must be installed and in `PATH`)
- `gpg` (GPG mode only -- secret keys must be available in your keyring)
- `diff` (standard Unix tool, used for verification)

---

## Installation

Install as a tool with `uv`:

```
uv tool install .
```

Or run directly without installing:

```
uv run git-recrypt
```

---

## Quick start

1. Run `detect` to see what files would be encrypted:

```
git-recrypt detect --repo /path/to/your/repo
```

2. Run `init` to generate a manifest interactively:

```
git-recrypt init --repo /path/to/your/repo --output git-recrypt.yaml
```

3. Review and edit the manifest, then rewrite history:

```
git-recrypt run --manifest git-recrypt.yaml
```

---

## Manifest format

The manifest is a YAML file (default name: `git-recrypt.yaml`) that describes how the rewrite should happen.

### Fields

| Field | Required | Default | Description |
|---|---|---|---|
| `version` | yes | -- | Must be `1` |
| `key` | yes | -- | Exactly one of `symmetric` or `gpg` (see below) |
| `patterns` | yes | -- | List of gitattributes-style glob patterns for files to encrypt. At least one entry required. |
| `repo` | no | `"./"` | Path to source repository. Relative paths are resolved against the manifest's parent directory. |
| `introduce_at` | no | `"root"` | Where to introduce encryption. Currently only `"root"` (from first commit) is supported. `"first-match"` and SHA-based introduction points are rejected at validation time with a "not yet implemented" error. |
| `branches` | no | `["HEAD"]` | Branches to rewrite. `HEAD` resolves to the source repo's current branch via `git symbolic-ref`. Fails fast if unresolvable. |
| `exclude` | no | `[]` | Patterns to exclude from encryption. |
| `detection_profile` | no | -- | Hint for the `detect` command. Values: `"generic"`, `"etckeeper"`, `"kubernetes"`. |

### Key configuration

**Symmetric key:**

| Field | Description |
|---|---|
| `key.symmetric.key_file` | Path to an existing key file, or `"generate"` to create one automatically. |
| `key.symmetric.export_to` | Where to write the generated key. Default: `"./git-crypt.key"`. |

**GPG key:**

| Field | Description |
|---|---|
| `key.gpg.user_ids` | List of GPG user IDs (email addresses) to add as recipients. |
| `key.gpg.generate` | *Not yet implemented.* Auto-generate a GPG key. Planned sub-fields: `name`, `email`, `algorithm` (default: `ed25519`), `expire` (default: `"0"`), `passphrase` (`"provided"` or `"random"`). |

### GPG manifest example (etckeeper)

```yaml
version: 1
key:
  gpg:
    user_ids:
    - alice@example.com
    - bob@example.com
patterns:
- '**/*.key'
- '**/*.key.pem'
- '**/*.private'
- '**/*privkey*'
- '**/.htpasswd'
- '**/secret.*'
- gshadow
- gshadow-
- shadow
- shadow-
- ssh/ssh_host_*_key
introduce_at: root
branches:
- HEAD
exclude: []
detection_profile: etckeeper
```

### Symmetric key manifest example

```yaml
version: 1
key:
  symmetric:
    key_file: generate
    export_to: ./git-crypt.key
patterns:
- 'secrets/**'
- '**/*.env'
- '**/*.pem'
introduce_at: root
branches:
- HEAD
```

---

## CLI commands

### `detect`

Scan a repo and suggest encryption patterns based on filenames and content.

```
git-recrypt detect [--repo PATH] [--profile PROFILE]
```

| Option | Default | Description |
|---|---|---|
| `--repo` | `.` | Path to the repository to scan. |
| `--profile` | -- | Detection profile hint. Values: `generic`, `etckeeper`, `kubernetes`. |

### `init`

Interactive wizard that produces a manifest file.

```
git-recrypt init [--repo PATH] [--output FILE]
```

| Option | Default | Description |
|---|---|---|
| `--repo` | `.` | Path to the source repository. |
| `--output` | `git-recrypt.yaml` | Where to write the generated manifest. |

### `dry-run`

Show which files would be encrypted without modifying anything.

```
git-recrypt dry-run [--manifest FILE] [--repo PATH]
```

| Option | Default | Description |
|---|---|---|
| `--manifest` | `git-recrypt.yaml` | Path to the manifest file. |
| `--repo` | -- | Override the repo path from the manifest. |

### `run`

Execute the history rewrite. This is the main command.

```
git-recrypt run [--manifest FILE] [--repo PATH] [--force] [--work-dir DIR] [--skip-verify]
```

| Option | Default | Description |
|---|---|---|
| `--manifest` | `git-recrypt.yaml` | Path to the manifest file. |
| `--repo` | -- | Override the repo path from the manifest. |
| `--force` | false | Skip the confirmation prompt. |
| `--work-dir` | -- | Custom directory for the output (rewritten) repo. |
| `--skip-verify` | false | Skip post-rewrite verification. |

### `verify`

Verify that a rewritten repo matches the original content.

```
git-recrypt verify ORIGINAL REWRITTEN KEY_FILE [--manifest FILE] [--mode MODE]
```

| Argument / Option | Default | Description |
|---|---|---|
| `original` | -- | Path to the original (source) repo. |
| `rewritten` | -- | Path to the rewritten repo. |
| `key_file` | -- | Path to the git-crypt key file (required). For symmetric mode, use the exported key. For GPG mode, the value is unused -- pass any placeholder (e.g. `/dev/null`). |
| `--manifest` | `git-recrypt.yaml` | Path to the manifest file. |
| `--mode` | `fast` | Verification depth. `fast` or `full`. |

---

## How it works

The rewrite happens entirely in a fresh target repo. The source repo is never modified.

1. Create an empty target repo with `git init -b <branch>`.
2. Run `git-crypt init` and configure the key. For GPG mode, `add-gpg-user` is called for each user ID. For symmetric mode, the key file is copied in.
3. Commit `.gitattributes` with the encryption patterns.
4. Run `git-crypt unlock` so the working tree is in decrypted state.
5. Pre-flight check: test a lock/unlock roundtrip to catch configuration issues before touching any history.
6. Copy remotes from the source repo into the target repo.
7. Replay each commit:
   - Generate a patch with `git format-patch` from the source repo.
   - Temporarily hide `.gitattributes` in the target repo.
   - Apply the patch with `git apply`.
   - Restore `.gitattributes`.
   - Stage everything with `git add -A`. The git-crypt clean filter encrypts matched files at this point.
   - Commit with the original author, date, and message.

Rewrite state (commit map, config, setup commits) is persisted to `~/.cache/git-recrypt/<repo-hash>/` for post-rewrite verification and debugging. Resume from interrupted rewrites is a planned feature, not yet implemented.

---

## Verification

After `run` completes, verification runs automatically in three phases (unless `--skip-verify` is passed).

**Phase 1 -- git-crypt status.** Checks that `git-crypt status` reports the expected files as encrypted in the rewritten repo.

**Phase 2 -- lock/unlock roundtrip.** Locks and unlocks the rewritten repo at the tip commit and at one commit sampled from the middle of history. Confirms that encrypted content survives a full cycle.

**Phase 3 -- checkout and disk compare.** Checks out roughly 10% of commits (sampled), then compares the full file tree against the corresponding commit in the source repo. Any content mismatch is reported as a failure.

You can also run verification independently with the `verify` command.

---

## Debugging

Set `GIT_RECRYPT_DEBUG=1` before running any command to enable verbose debug output. Patches are dumped to:

```
~/.cache/git-recrypt/<repo-hash>/debug/
```

When the tool encounters an error, it prints a hint to re-run with this variable set.

```
GIT_RECRYPT_DEBUG=1 git-recrypt run --manifest git-recrypt.yaml
```

---

## Limitations

- Only branches listed in the manifest are rewritten. Tags are not rewritten.
- The rewrite produces a new repo with a different object graph. You'll need to force-push or replace the remote.
- GPG mode requires that all listed user IDs have public keys available in your local keyring before running.

---

## Planned features

The following features are not yet implemented but are on the roadmap:

- `introduce_at: first-match` and SHA-based introduction points. Currently only `root` is fully supported.
- Multi-branch rewriting. The `branches` list accepts multiple entries in the manifest schema, but rewriting more than one branch is not yet implemented.
- Octopus merge support. Merges with more than 2 parents are not handled.
- Named encryption keys (`named_patterns`). Per-pattern key selection is not yet supported.
- Resume interrupted rewrites. State is persisted after a successful run, but resuming a partially completed rewrite is not yet implemented.
- Per-GPG-identity verification. The verify command currently checks content correctness but does not validate per-recipient decryptability.
