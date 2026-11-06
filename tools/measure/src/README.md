# Measurement implementation and dispatch

main.rs registers the normal build tool and hands Clap commands to dispatch.rs. Domain dispatchers separate calibration, phase reviews, release/delivery, transport operations and miscellaneous tools. research_main.rs registers the separate restricted delivery target with only ResearchCommand. research_command.rs shares the original seven handler bodies between both targets; the normal tool refuses the restricted build-info producer claim.

### Contracts and limits

Keep report construction distinct from execution. artifact.rs reads/writes JSON/JSONL; it does not authenticate input origin. The private control operators retain separate settings, original clocks, owned resources and refusal receipts. Some legacy live helpers execute external commands; they are not generic safe parsers.

### Entry points and maintenance

For privacy work follow privacy_pcap → privacy_study → privacy_frontier. For actual paired control follow private_control/poisson_control/poisson_insertion. The nested READMEs identify evidence-review modules and test-only support.

### Local map

- [artifact.rs](artifact.rs)
- [brain_outcome_replay.rs](brain_outcome_replay.rs)
- [cli.rs](cli.rs)
- [dispatch.rs](dispatch.rs)
- [main.rs](main.rs)
- [research_main.rs](research_main.rs)
- [research_command.rs](research_command.rs)
- [poisson_control.rs](poisson_control.rs)
- [poisson_insertion.rs](poisson_insertion.rs)
- [privacy_frontier.rs](privacy_frontier.rs)
- [privacy_pcap.rs](privacy_pcap.rs)
- [privacy_study.rs](privacy_study.rs)
- [private_control.rs](private_control.rs)
- [research_operator_delivery.rs](research_operator_delivery.rs)
- [adversarial_runner/](adversarial_runner/README.md)
- [brain_runtime_proof/](brain_runtime_proof/README.md)
- [cli/](cli/README.md)
- [external_calibration/](external_calibration/README.md)
- [master_plan/](master_plan/README.md)
- [phase_a/](phase_a/README.md)
- [phase_b_runtime/](phase_b_runtime/README.md)
- [phase_b_score/](phase_b_score/README.md)
- [phase_c/](phase_c/README.md)
- [phase_d/](phase_d/README.md)
- [privacy_frontier/](privacy_frontier/README.md)
- [privacy_pcap/](privacy_pcap/README.md)
- [privacy_study/](privacy_study/README.md)
- [transport_camouflage/](transport_camouflage/README.md)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
