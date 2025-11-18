# Branch Strategy

## Overview

This repository uses a structured branching strategy to manage multiple outstanding PRs while keeping development synchronized.

## Branch Structure

### `main` (local)
- **Tracks**: `upstream/main` (dc4eu/vc)
- **Purpose**: Always stays in sync with the upstream repository
- **Updates**: `git fetch upstream && git checkout main && git pull`
- **Never**: Contains local commits that aren't in upstream

### `origin/main` (leifj/vc)
- **Purpose**: Your fork's main branch
- **Can be**: Used for experimental work or left in sync with local main
- **Not critical**: Since local main tracks upstream directly

### Feature Branches
- **Pattern**: `feat/feature-name` or `fix/issue-name`
- **Base**: Created from `upstream/main`
- **Purpose**: Individual PRs to upstream
- **Examples**:
  - `feat/saml-issuer` (PR #206)
  - `feat/quick-wins` (PR #205)

### Integration Branch
- **Name**: `integration/all-prs`
- **Base**: `upstream/main`
- **Purpose**: Merge all outstanding PRs to verify they work together
- **Updates**: Recreated when PRs are updated

## Workflow

### Creating a New PR

```bash
# Make sure main is up to date
git checkout main
git fetch upstream
git pull

# Create feature branch from upstream/main
git checkout -b feat/my-feature upstream/main

# Make changes and commit
git add .
git commit -m "feat: add my feature"

# Push to your fork
git push origin feat/my-feature

# Create PR on GitHub: dc4eu/vc ← leifj/vc:feat/my-feature
```

### Updating the Integration Branch

```bash
# Start fresh from upstream/main
git checkout -b integration/all-prs-new upstream/main

# Merge all outstanding PRs
git merge --no-ff origin/feat/quick-wins -m "Merge PR #205"
git merge --no-ff origin/feat/saml-issuer -m "Merge PR #206"
# ... merge other PRs ...

# Resolve conflicts if needed
# Test everything works
go test ./...

# Replace old integration branch
git branch -D integration/all-prs
git branch -m integration/all-prs-new integration/all-prs
git push origin integration/all-prs --force-with-lease
```

### Rebasing a PR onto Updated Upstream

```bash
# Fetch latest upstream
git fetch upstream

# Create rebased branch
git checkout -b feat/my-feature-rebased upstream/main

# Cherry-pick commits from original branch
git cherry-pick <first-commit>..<last-commit>

# Resolve conflicts, test, then replace original
git branch -D feat/my-feature
git branch -m feat/my-feature-rebased feat/my-feature
git push origin feat/my-feature --force-with-lease
```

## Current State

### Outstanding PRs
- **PR #205**: `feat/quick-wins` - Verifier-proxy improvements (16 commits)
- **PR #206**: `feat/saml-issuer` - SAML authentication support (9 commits)

### Integration Branch
- **Name**: `integration/all-prs`
- **Contains**: Both PR #205 and PR #206 merged together
- **Purpose**: Verify PRs work together, run comprehensive tests
- **Status**: All tests passing (SAML and verifier-proxy)

## Benefits

1. **Clean main**: Always matches upstream, easy to create new branches
2. **Isolated PRs**: Each PR is independent and rebased on upstream
3. **Integration testing**: Verify all PRs work together before merging
4. **No conflicts**: Easy to resolve issues before they hit upstream
5. **Clear history**: Each PR has clean, focused commits

## Common Commands

```bash
# Update local main
git checkout main && git fetch upstream && git pull

# Check what's in a PR vs upstream
git log --oneline feat/my-feature ^upstream/main

# Check what's in integration branch
git log --oneline integration/all-prs ^upstream/main --graph

# Test specific code
go test -tags saml ./pkg/saml/...           # SAML tests
go test ./internal/verifier_proxy/...       # Verifier-proxy tests
go test ./...                                # All tests
```

## Notes

- Integration branch is **not** submitted as a PR
- Integration branch is **recreated** when PRs are updated
- Each PR should build and test independently
- Integration branch verifies PRs don't conflict
