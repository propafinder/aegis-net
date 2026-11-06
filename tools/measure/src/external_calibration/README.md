# Calibration report contracts

contract.rs validates calibration report behavior using fixtures, and output.rs renders the parent module’s calibration summary as Markdown.

### Contracts and limits

Observed witness and classifier records, freshness and coverage are separate inputs. A summary or declared calibration source cannot prove independent measurement or a current censorship decision. Missing/stale inputs must remain explicit.

### Entry points and maintenance

The data aggregation lives in ../external_calibration.rs; the calibration dispatcher exposes the commands. Keep JSON and Markdown meanings aligned.

### Local map

- [contract.rs](contract.rs)
- [output.rs](output.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
