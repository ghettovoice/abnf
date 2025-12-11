# Contributing to abnf

Thank you for considering contributing to **abnf**! This document outlines the guidelines and workflow for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Guidelines](#coding-guidelines)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

Please be respectful and considerate in all interactions. We aim to maintain a welcoming and inclusive environment for everyone.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:

   ```bash
   git clone https://github.com/<your-username>/abnf.git
   cd abnf
   ```

3. **Add the upstream remote**:

   ```bash
   git remote add upstream https://github.com/ghettovoice/abnf.git
   ```

## Development Setup

### Prerequisites

- Go 1.24 or later
- Make

### Setup

```bash
make setup
```

This will tidy up the Go modules.

### Build

```bash
make build
```

### Install CLI locally

```bash
make install
```

## Making Changes

1. **Create a new branch** from `master`:

   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/my-bugfix
   ```

2. **Make your changes** following the [coding guidelines](#coding-guidelines).

3. **Run tests and linters**:

   ```bash
   make test
   make lint
   ```

4. **Commit your changes** with a clear and descriptive commit message:

   ```bash
   git commit -m "Add feature X" 
   # or
   git commit -m "Fix issue with Y"
   ```

5. **Push to your fork**:

   ```bash
   git push origin feature/my-feature
   ```

6. **Open a Pull Request** against the `master` branch.

## Pull Request Process

1. Ensure all tests pass and there are no linter warnings.
2. Update documentation if your changes affect the public API.
3. Fill out the pull request template completely.
4. Link any related issues using `Fixes #issue-number`.
5. Wait for review and address any feedback.

### PR Types

- **Bug fix** — non-breaking change that fixes an issue
- **New feature** — non-breaking change that adds functionality
- **Breaking change** — fix or feature that would cause existing functionality to not work as expected
- **Documentation update** — changes to docs only
- **Refactoring** — no functional changes

## Coding Guidelines

- Follow idiomatic Go conventions and the [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments).
- Use `gofumpt` for formatting (included in the project tooling).
- Keep functions small and focused on a single responsibility.
- Write descriptive variable and function names.
- Add comments to explain non-obvious logic.
- Avoid unnecessary dependencies.

## Testing

### Run all tests

```bash
make test
```

### Run benchmarks

```bash
make bench
```

### View coverage report

```bash
make cov
```

### Guidelines

- Write tests for all new functionality.
- Ensure existing tests pass before submitting a PR.
- Include both positive and negative test cases.
- Use table-driven tests where appropriate.

## Reporting Issues

When reporting issues, please include:

- A clear and descriptive title.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Go version and OS information.
- Relevant code snippets or error messages.

Use the appropriate issue template when creating a new issue.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
