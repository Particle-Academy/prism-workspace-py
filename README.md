# Prism Workspace for Python

Python implementation of Prism's guarded agent workspace. `Workspace` is the
async-first API and `SyncWorkspace` is its blocking facade. Both provide stable
owner addressing, optional authorization, streamed sync listings, stable
failure codes, lexical path guarding, and realpath-based symlink containment.

The package ships the same byte-preserving 134-case adversarial corpus as PHP.
Tests run every case and create real links both into and out of the workspace.
Workspace contents are never executed.

This package is private while coordinated parity work is in progress.
