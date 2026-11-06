# Script contract support

This directory contains support for shell-driven contracts. [NetworkManager tests](networkmanager/README.md) exercise extracted ownership and validation code using synthetic filesystem/process inputs. [Fixtures](fixtures/README.md) holds public upstream dracut data used by boot-assessment checks.

The entry points are the named `scripts/test-*.sh` wrappers, not recursive execution of this tree. In particular, the NetworkManager wrapper extracts selected implementation blocks into a temporary directory before placing these tests beside them; running the Python test files in place omits their required modules.

Use Python 3 and the wrapper's platform prerequisites, with fresh temporary/output paths. Public fixture shell files are data and must not be sourced. These contracts can verify parsing, refusal and owned cleanup but cannot by themselves establish an installed host's boot behavior or network policy. See the [script guide](../README.md) and preserve upstream fixture provenance and licensing when changing test inputs.
