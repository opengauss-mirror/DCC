# DCC pre-commit Developer Guide

## What Was Ported From DSS

DSS introduced a local pre-commit workflow with:

- `.pre-commit-config.yaml` defines commit-time checks.
- `setup-pre-commit.sh` installs pre-commit into `.pre-commit-venv/`, so system Python is not polluted.
- `PRE_COMMIT_README.md` documents install, daily use, bypass, and FAQ.
- `.gitignore` ignores the local virtual environment.

DCC is also a C/C++ repository, so the DCC version keeps the same operating model and uses checks that fit this repository.

## Checks Enabled For DCC

| Check | Tool | Scope | Auto-fix |
| --- | --- | --- | --- |
| File hygiene | `pre-commit-hooks` | staged files | yes, for whitespace, final newline, line endings |
| YAML/JSON/TOML syntax | `pre-commit-hooks` | staged config files | no |
| Merge markers | `pre-commit-hooks` | staged files | no |
| Large files | `pre-commit-hooks` | staged files | no |
| Private keys | `pre-commit-hooks` | staged files | no |
| Spelling | `codespell` | docs, shell, CMake, and config files | no |
| C/C++ formatting | `clang-format-diff.py` | changed C/C++ diff hunks | yes |

The C/C++ formatter intentionally works on changed diff hunks, not whole files. This keeps legacy files from being reformatted wholesale when a developer touches one line.

## First-Time Installation

Run this once per local clone:

```bash
cd <DCC repository root>
bash setup-pre-commit.sh
```

To use another PyPI mirror for this one installation:

```bash
PIP_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple bash setup-pre-commit.sh
```

The script creates `.pre-commit-venv/`, installs pre-commit there, installs the git hook, and pre-downloads hook environments from gitcode and the pip mirror.

## Daily Use

After installation, use git normally:

```bash
git add <files>
git commit -m "your message"
```

If a hook rewrites a file, the commit stops. Review the change, stage it, then commit again:

```bash
git diff
git add <fixed files>
git commit -m "your message"
```

Manual runs:

```bash
.pre-commit-venv/bin/pre-commit run --files src/interface/dcc_interface.h
.pre-commit-venv/bin/pre-commit run --all-files
```

`--all-files` is useful before large cleanups, but it may report old issues that are unrelated to your current change.

## Bypass When Necessary

Prefer skipping only the failing hook:

```bash
SKIP=clang-format-diff git commit -m "your message"
```

Emergency bypass for all hooks:

```bash
git commit --no-verify -m "your message"
```

Use bypasses sparingly and follow up with a normal pre-commit run when the emergency is over.

## Notes For DCC

- The hook repositories point to gitcode mirrors, matching the DSS setup for environments without direct github access.
- `clang-format==22.1.5` is installed in the hook environment through pip. Developers do not need a global `clang-format`.
- Spelling checks exclude C/C++ source for now because the repository has existing spelling debt in old source files. C/C++ formatting still runs on changed C/C++ lines.
- Delete `.pre-commit-venv/` to remove the local tool environment.
