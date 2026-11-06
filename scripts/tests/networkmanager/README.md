# NetworkManager ownership and validation contracts

`test_nm_owned_config.py` exercises owned configuration changes, crash boundaries, locking and recovery under a private synthetic root. `test_validator.py` checks host assessment and validation using temporary proc/config paths and an inert manager-command boundary. The tests deliberately include failure and timeout cases; these are contract controls, not live NetworkManager operations.

Run through [test-device-networkmanager-policy-contract.sh](../../test-device-networkmanager-policy-contract.sh) from the repository root. That wrapper extracts `PY_NM_POLICY` and `PY_NM_VALIDATE` from the shipped helper into a temporary directory, copies the test modules and the installer fixture there, and runs the tests. Direct `python3` execution in this directory cannot find the expected sibling `nm_owned_config.py`, `validator.py` and staged `install.sh`.

The wrapper requires Python 3 and Unix process/filesystem facilities used by the tests, including `fcntl` and signals. It does not establish actual daemon policy adoption, boot behavior or installed full-wide acceptance. Keep fixture rebasing confined to tests; production roots and ownership checks are not general override points. See [script test support](../README.md).
