# Linux Wide Rollout Runbook

Этот документ фиксирует **операционный contract** для Linux wide ingress в AEGIS: какие combinations считаются supported, какие intentionally unsafe, какие env/config invariants обязательны и какой rollout order рекомендуется.

Важно:
- адреса лабораторных узлов в примерах заменены documentation placeholders; исходные датированные receipts сохраняют историю и не разрешают повторное использование флота;
- это **runbook для текущего open-source runtime**, а не обещание полного production firewall manager
- source of truth для machine-readable enforcement остаётся в `aegis-client` preflight/startup JSON и smoke helper contracts
- если prose в этом документе расходится с `selection_error_code`, `runtime_checks[].code`, `backend_notes[].code` или smoke exit codes, правдой считается machine-readable contract
- readiness vocabulary тоже считается normative: `selection.wide_platform_family_supported`, `selection.wide_supported`, `selection.wide_runtime_readiness`
- current UDP preview policy surface тоже считается normative: `selection.wide_udp_capture_contract_requested`, `selection.wide_udp_capture_support_tier_requested`, `selection.wide_udp_capture_contract`, `selection.wide_udp_capture_support_tier`, `selection.wide_udp_capture_policy`, `selection.wide_udp_capture_runtime_scope`, `selection.wide_dns_port`, `selection.wide_udp_preview_ports`, `startup.wide_udp_capture_contract`, `startup.wide_udp_capture_support_tier`, `startup.wide_udp_capture_policy`, `startup.wide_udp_capture_runtime_scope`, `startup.wide_udp_preview_policy`, `startup.wide_udp_preview_ports` и runtime `ingress_backend_started.fields.wide_udp_*`; requested/active/runtime-scope trio теперь закреплён и в CI preflight/startup assertions как для Linux/IPv4, так и для первых Linux/IPv6 happy-path cases
- в этой trio requested и active читаются буквально: `selection.wide_udp_capture_*_requested` описывают wide config intent, а `selection.wide_udp_capture_contract` / `support_tier` / `policy` / `runtime_scope` считаются active only when `selection.selected_backend = "wide_primary"`; на pure `socks5_fallback` path эти active-поля должны быть `null`, даже если requested wide config сам по себе заполнен
- этот runbook относится только к Linux-first baseline и не должен читаться как claim о cross-platform готовности `wide-first` ingress

## 1. Цель runbook

Runbook нужен для того, чтобы operator-side decisions были выражены не только через "какой helper запустить", но и через согласованный набор:
- `platform_backend`
- `rollout_profile`
- `prerouting_interface`
- helper env (`AEGIS_WIDE_INTERFACE`, `AEGIS_EXEMPT_UID`, `AEGIS_WIDE_FWMARK`, `AEGIS_WIDE_ROUTE_TABLE`)

Иначе Linux wide path слишком легко разваливается на несколько разных источников правды:
- config говорит одно
- helper применяет другое
- preflight hints намекают на третье

## 1.1 Product entry layer

Product entry для текущего supported path теперь фиксирован отдельно:
- верхнеуровневый вход для пользователя = `README.md`;
- внешний вход: аутентифицированный exact-pinned client launcher либо заранее проверенный bootstrap с явным `--source` и `--bundle-url-file /absolute/private/client-access-url.txt`; серверный facade использует отдельный приватный operator release base;
- role-aware install ядро = `./install.sh server` и `./install.sh client`;
- release packaging entry = `./scripts/build-release-bundle.sh` и `./scripts/build-release-delivery.sh`, после которых тот же `install.sh` работает уже и вне git checkout;
- server-side setup обязан materialize `client-bundle/`, а не только печатать relay параметры;
- server-side setup теперь обязан materialize и `client-bundle.tar.gz`, чтобы remote handoff шёл не только каталогом, но и URL/archive contract;
- systemd layer рендерится тем же installer-ом под конкретные binary/config/state paths и не живёт как отдельный ручной checklist;
- этот runbook остаётся **low-level operator contract** для Linux wide path и не должен подменять собой product entry layer.

Практический смысл разделения:
- `bootstrap-install.sh` отвечает за внешний delivery/bootstrap слой: в обычной online installation на `Ubuntu` / `debian-apt` он проверяет prerequisites и при необходимости получает пакеты через `apt-get`, а на распознанном RHEL/Fedora/CentOS/Rocky/Alma family — через `dnf`; offline/download-only требуют пакеты заранее. Затем проверяются подписанные release manifest/freshness policy и archive checksum, и управление передаётся bundle installer. Это source-контракт, а не новая native distro-приёмка;
- локальный manifest задаётся через `file://...`; локальный access bundle — через `--bundle /absolute/private/client-bundle`, где путь указывает на уже проверенный и распакованный каталог, не `.tar.gz`. Приватную URL-загрузку выполняет проверенный Rust client; HTTP(S) urllib fallback удалён, нужны curl или wget и соблюдение [private inputs](../../operations/private-installer-inputs.md);
- `install.sh server` отвечает за server config, relay certs и client bundle handoff, но не превращается в package-manager bootstrap;
- `install.sh client --bundle ...` / `install.sh client --bundle-url-file /absolute/private/client-access-url.txt` отвечают за установку клиентского binary/config/`ca.pem`, сохраняя ту же role-centric границу и вне repo, и внутри release bundle;
- `scripts/build-release-bundle.sh` отвечает за self-contained bundle-артефакт, который переносит тот же install flow на другой Linux host без repo checkout;
- `scripts/build-release-delivery.sh` отвечает за внешний `release.manifest.json` и полный delivery surface (`bundle`, `package-root`, `deb`, optional `rpm`);
- `.github/workflows/release.yml` публикует только девять клиентских файлов: bootstrap, два `client-release.manifest*.json` с подписями и два Linux client archive с checksum. `release.manifest.json`, серверные/operator archives и credentials остаются в приватной доставке. Выбор exact tag и независимые pins обязательны; `latest` не выбирает prerelease. Подписание/публикация требуют manual dispatch из protected main и отдельных governance/environment gates; [hold от 10 октября](../../operations/release-governance-and-opsec.md#temporary-operational-hold--10-october-2026) не снят этим runbook;
- release bundle при этом должен оставаться self-describing: `bundle.manifest.json`, `SHA256SUMS` внутри bundle и archive-side `.sha256` file считаются частью packaging handoff;
- repo-side contract для этого delivery layer теперь проверяется через `scripts/test-release-bundle-contract.sh`, а при наличии `systemd-analyze` дополнительно валидирует и rendered units;
- внешний delivery layer теперь удерживается ещё и через `scripts/test-release-delivery-contract.sh` и `scripts/test-bootstrap-install-contract.sh`;
- `scripts/build-package-root.sh` отвечает уже не за install-from-bundle, а за канонический `rootfs` staging layout для следующей `deb/rpm` wave; этот contract удерживается `scripts/test-package-root-contract.sh`;
- `scripts/build-deb-package.sh` и `scripts/test-deb-package-contract.sh` уже дают первый `deb` baseline поверх `package-root`; это package-manager layer, но ещё не финальный split-package/distro-parity story;
- `scripts/build-split-deb-packages.sh` и `scripts/test-split-deb-packages-contract.sh` уже добавляют следующий Debian ergonomics layer: role-specific `aegis-server` / `aegis-client` packages поверх того же package-root contract;
- `scripts/build-rpm-packages.sh` и `scripts/test-rpm-packages-contract.sh` теперь добавляют и rpmbuild-based parity поверх того же `package-root`, но текущая среда может честно оставлять этот test как `SKIP`, если `rpmbuild`/`rpm` недоступны;
- `scripts/test-dpkg-lifecycle-smoke.sh` уже даёт rootless lifecycle smoke для split packages через temp-root `dpkg --install/--remove`; это полезный repo-side contract, но не заменяет будущий live host install/remove proof на настоящем Debian environment;
- `scripts/validate-debian-package-host.sh` теперь уже считается canonical Ubuntu/Debian host gate: `--run` покрывает не только `dpkg --install/--remove/--purge`, но и `systemctl start/restart/status`, `journalctl`, green client preflight/startup artifacts, runtime-events summary, reinstall и same-version `upgrade_reapply`, а reboot path честно выражается как `daemon-reload + restart` reproducible contract; artifacts при этом возвращаются во владение invoking user, чтобы canary evidence не оставалось root-only residue после `sudo`;
- `scripts/validate-rpm-package-host.sh` теперь симметрично готовит RHEL/SUSE-family package lifecycle proof (`--check`, затем `--run`) поверх split `.rpm` packages и того же package-root contract;
- `scripts/test-validate-debian-package-host-contract.sh` теперь удерживает и сам helper contract network-free: помимо `--check`, он уже гоняет fake-root `--run` harness c shimmed `dpkg`/`dpkg-query`/`systemctl`/`journalctl` и runtime artifacts, так что live Debian-host step не остаётся единственным местом, где впервые проверяется lifecycle/service order;
- `scripts/test-validate-rpm-package-host-contract.sh` делает то же для RPM helper-а через stubbed `rpm` / `rpmbuild`, чтобы RHEL/SUSE-family entrypoint не проверялся впервые только на живом host;
- `scripts/build-linux-package-acceptance-matrix.sh` собирает JSON evidence от Debian/RPM host helper-ов в `matrix.targets.json`, `matrix.results.json`, `matrix-summary.md` и `bundle.manifest.json`, а `scripts/test-linux-package-acceptance-matrix-contract.sh` удерживает этот collector machine-readable;
- `scripts/build-linux-next-expansion-playbook.sh` читает `bundle.manifest.json` от acceptance matrix и materialize-ит конкретный next-family runbook (`next-expansion-playbook.json` / `.md`) для ближайшего non-Ubuntu host evidence step без ручного glue между helper check/run и matrix refresh;
- `scripts/build-linux-next-expansion-review-bundle.sh` берёт тот же `bundle.manifest.json` плюс новый family-specific `host-validation.json`, пересобирает refreshed matrix и materialize-ит top-level review bundle (`next-expansion-review.json` / `.md` / manifest), чтобы next-family wave заканчивалась не console glue, а отдельным machine-readable verdict surface;
- `scripts/linux-next-expansion-status.sh` materialize-ит отдельный status/handoff artifact поверх current matrix manifest и optional latest review, чтобы automation видела, остаётся ли wave в `pending_next_family`, перешла ли в `target_validated_next_candidate_pending`, упёрлась ли в `latest_review_blocked` или уже дошла до `all_documented_families_validated`;
- `scripts/build-linux-next-expansion-wave-bundle.sh` сводит эти entrypoint-ы в один top-level helper: без нового evidence он собирает `playbook + status`, а после live rerun может сразу собрать `review bundle + refreshed status`, чтобы next-family wave имела один короткий orchestration entry;
- `scripts/build-linux-release-program-bundle.sh` даёт уже program-level status поверх `ubuntu-release-wave.manifest.json`, optional `linux-next-expansion-status.json` и optional `stealth-wave-summary.json`, чтобы верхний Linux release/growth contour читался как один machine-readable artifact, а не как набор разрозненных helpers;
- packaging layer теперь уже несёт и service integration metadata: `sysusers.d` для server-side service user и `tmpfiles.d` для state/log/config directories; combined/split `deb` maintainer scripts по возможности вызывают `systemd-sysusers`, `systemd-tmpfiles` и `systemctl daemon-reload`;
- maintainer lifecycle contract теперь уже выражает и Debian service-policy shape: `postinst` применяет `systemctl preset`, `prerm` делает `disable --now`, а `postrm purge` чистит `tmpfiles` state через `systemd-tmpfiles --remove`, когда утилиты доступны;
- split packages при этом уже не конфликтуют и по policy/doc assets: server и client используют разные `system-preset` / Debian note files, так что role-specific `dpkg` lifecycle не опирается на shared-file overlap;
- helper/product boundary теперь чище и после установки: `setup-wide-linux-tproxy.sh` предпочитает установленный `aegis-client` binary и только потом падает обратно в repo/dev `cargo run`;
- release bundle и `package-root` теперь несут installed-client helper layer (`bootstrap-wide-linux-validation-host.sh`, `setup-wide-linux-redirect.sh`, `setup-wide-linux-tproxy.sh`), так что separate-host runtime proof не должен зависеть от отдельного repo checkout только ради helper-скриптов; split packages при этом больше не дублируют shared helper paths между `aegis-server` и `aegis-client`, чтобы same-host `dpkg` lifecycle оставался installable;
- после этого уже имеет смысл переходить к `preflight`, `probe`, `doctor`, `launch`, `events` и privileged helper flows из этого runbook.

Если речь идёт о первом "как поставить и подключить роли" вопросе, source of truth = `README.md` + `install.sh`.
Если речь идёт о Linux interception/runtime contract, source of truth = этот runbook + machine-readable preflight/startup/runtime surfaces.

## 1.1.1 Ubuntu-first product claim

Для текущего product/release слоя этот runbook надо читать жёстко:
- primary supported path = `Ubuntu` / `debian-apt`
- role model = separate `server` / separate `client`
- supported entry path = installed-product flow через `bootstrap-install.sh` и `install.sh`
- `compose`, same-host helpers и repo/dev flows остаются diagnostics/lab layers, а не canonical production entry
- current green claim не включает universal Linux, `macOS`, `Windows` и зрелую wire-level mimicry
- current apt-based matrix result тоже читать жёстко: и `Ubuntu server -> Debian client`, и повторный `Debian server -> Ubuntu client` уже зелёные на реальных VPS; Debian теперь baseline-compatible на текущем `debian-apt` contour, но broader multi-family claim всё равно не расширяется дальше Ubuntu/Debian без новых live family proofs

## 1.1.2 Ubuntu release gate

Для текущего Ubuntu-first contour правило `ship / no-ship` такое:
- repo-side CI, packaging contracts и helper self-tests обязательны, но сами по себе не делают release ship-ready
- обязательный host gate = `scripts/validate-debian-package-host.sh --run`
- release candidate без зелёного Ubuntu host evidence не считается валидным релизом

Canonical install-to-healthy orchestration теперь встроен прямо в host gate:
- `scripts/validate-debian-package-host.sh --check`
- `sudo env HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" bash scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/ubuntu-release`
- для release-bound evidence тот же helper теперь умеет и prebuilt mode: `--server-deb <published aegis-server_*.deb> --client-deb <published aegis-client_*.deb>`, так что published split packages можно валидировать без локальной cargo rebuild
- этот run сам пишет `ubuntu-release-gate-handoff.json`, `ubuntu-product-release-summary.json` и `ubuntu-controlled-pilot-inputs.json`, чтобы install-to-healthy contour читался как один release artifact surface
- `scripts/validate-ubuntu-product-release.sh` остаётся только совместимым shim entrypoint поверх того же validation layer

Минимальный required Ubuntu evidence:
- `validation-summary.json`
- `systemctl status` для `aegis-server.service` и `aegis-client.service`
- `journalctl` artifacts для обеих служб
- `client-preflight.json`
- `client-startup-probe.json`
- `client-runtime-events-summary.json`
- `client-operator-evidence.json`
- `client-operator-evidence.txt`

Repo-side CI при этом обязан отдельно оставлять machine-readable handoff artifact:
- `ubuntu-release-gate-handoff.json` = `repo_green_only` до тех пор, пока не приложен зелёный Ubuntu host evidence bundle

Required lifecycle phases:
- `install`
- `preset_policy`
- `service_start`
- `service_restart`
- `reboot_contract`
- `remove`
- `reinstall`
- `upgrade_reapply`
- `purge`

## 1.1.3 Operator evidence and product verdict

Operator-side shortest path для installed Ubuntu contour:
- `systemctl status`
- `journalctl`
- `aegis-client --ingress-preflight`
- `aegis-client --ingress-startup-probe --json`
- `scripts/setup-wide-linux-tproxy.sh doctor`
- `scripts/setup-wide-linux-tproxy.sh probe`
- `scripts/setup-wide-linux-tproxy.sh run` или `launch`
- `scripts/setup-wide-linux-tproxy.sh events`
- generated `operator-evidence.json`
- generated `runtime/client-operator-loop-summary.json` внутри `validate-debian-package-host.sh --run`

Практически это теперь рекомендуется читать так:
- короткий release/operator source of truth = artifacts из `validate-debian-package-host.sh --run`
- низкоуровневый diagnostic path = `setup-wide-linux-tproxy.sh doctor|probe|run|events`
- главным operator verdict surface считать `runtime/client-operator-loop-summary.json` и `client-operator-evidence.json`, а не отдельный console fragment

Нормативный product verdict для этого слоя:
- `green` = `startup_health=healthy`, `runtime_status=healthy`, `failover_count=0`, `terminal_failure_count=0`
- `degraded` = service/process жив, но runtime summary или probe/events показывают fallback/degraded-runtime surface
- `red` = startup path не healthy, probe не даёт supported-ready result или runtime/events содержат terminal failure

## 1.1.4 Upgrade and config discipline

Upgrade/reapply policy для supported Ubuntu path:
- повторный installer run не заменяет Ubuntu release gate и post-upgrade validation
- overwrite существующих `/etc/aegis/server/*` и `/etc/aegis/client/*` разрешён только через `--force`
- перед forced reapply/operator upgrade нужно сохранить config diff и только затем перегенерировать server materials или client bundle
- post-upgrade shortest path = `systemctl daemon-reload` -> `systemctl status` -> `journalctl` -> `runtime-events`

## 1.1.5 Mimicry boundary

Для текущего Ubuntu release contour принято отдельное решение:
- full mimicry не блокирует выпуск Ubuntu-first product contour
- текущий Ubuntu gate закрывается packaging/install/service/runtime evidence
- wire-level mimicry, raw packet shaping и отдельный packet-level acceptance идут как следующий отдельный technical program после стабилизации Ubuntu contour

## 1.2 Readiness vocabulary

Чтобы operator-side automation не путала разные классы проблем, current contract различает:
- `selection.wide_platform_family_supported`
- `selection.wide_supported`
- `selection.wide_runtime_readiness`

Практический смысл:
- `ready` — rollout/config shape выглядит допустимым для текущего runtime; можно идти к bind/start checks
- `needs_privilege` — backend/rollout поддержан, но transparent path требует elevated capability contract
- `unsupported_adapter` — platform family может совпадать, но working adapter в open-source runtime отсутствует
- `config_error` — rollout/backend/prerequisite contract сломан ещё до runtime start
- `disabled` — wide path выключен и selection/fallback уже описывают intentional non-wide state

## 2. Supported combinations

### Baseline: local OUTPUT-first redirect

Использовать когда:
- нужен safest baseline
- нужен lab/debug path
- нужен первый rollout без transparent interception

Config:

```toml
[ingress.wide]
platform_backend = "auto" # или "linux_redirect"
rollout_profile = "output_only_safe"
# prerouting_interface не нужен
default_mark = 0
```

Operational invariants:
- helper: `scripts/setup-wide-linux-redirect.sh`
- по умолчанию только `OUTPUT`
- обязательно задавать `AEGIS_EXEMPT_UID=<uid клиента>`
- `wide.listen` и `socks.listen` должны быть разведены по портам
- DNS в этом baseline не считается полноценным product-grade contour: redirect path годится для safe TCP/runtime baseline, а полноценный DNS надо переводить в privileged `linux_tproxy`

Это считается recommended baseline.

### Scoped PREROUTING redirect

Использовать когда:
- нужен `REDIRECT` path, но уже не только для локального `OUTPUT`
- interception должно быть ограничено конкретным ingress interface

Config:

```toml
[ingress.wide]
platform_backend = "linux_redirect"
rollout_profile = "prerouting_scoped"
prerouting_interface = "eth0"
default_mark = 0
```

Operational invariants:
- helper: `scripts/setup-wide-linux-redirect.sh`
- обязательно `AEGIS_ENABLE_PREROUTING=1`
- обязательно `AEGIS_WIDE_INTERFACE=<тот же iface, что и prerouting_interface>`
- без interface scope такой rollout считается invalid уже на preflight

Это supported только как **interface-scoped** PREROUTING rollout.

### Transparent privileged TPROXY

Использовать когда:
- нужен настоящий transparent interception path
- есть root или `CAP_NET_ADMIN`
- есть готовность обслуживать policy routing

Config:

```toml
[ingress.wide]
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
default_mark = 1
```

Operational invariants:
- helper: `scripts/setup-wide-linux-tproxy.sh`
- обязательно `AEGIS_WIDE_INTERFACE=<тот же iface, что и prerouting_interface>`
- обязательно ненулевой `AEGIS_WIDE_FWMARK`
- обязательно согласованный `AEGIS_WIDE_ROUTE_TABLE`
- сам `aegis-client` должен успешно выставлять `IP_TRANSPARENT`
- для client-machine DNS contour helper contract должен учитывать loopback/systemd-resolved path: existing-socket traffic не должен повторно TPROXY'иться, а local DNS packets после policy routing должны всё равно попадать обратно в `PREROUTING` interception path

Это supported только как privileged transparent rollout.

Именно этот rollout теперь считается честным supported path для полноценного DNS contour на Ubuntu.

## 3. Intentionally Unsafe Combinations

Эти combinations не считаются supported даже если их можно частично "заставить работать":

### `output_only_safe` + `linux_tproxy`

Почему unsafe:
- transparent interception семантически шире, чем safe OUTPUT-first baseline
- такой config теперь fail-fast отклоняется клиентом

Ожидаемое поведение:
- `selection_error_code = "rollout_profile_backend_mismatch"`

### `prerouting_scoped` без `prerouting_interface`

Почему unsafe:
- PREROUTING без interface scope слишком легко расширяется до all-interfaces capture

Ожидаемое поведение:
- `selection_error_code = "rollout_profile_prerequisites"`
- smoke helper redirect тоже должен завершаться с preflight exit `25`

### `transparent_privileged` без `linux_tproxy`

Почему unsafe:
- rollout intent требует transparent delivery semantics, а не NAT/original-dst redirect

Ожидаемое поведение:
- `selection_error_code = "rollout_profile_backend_mismatch"`

### `transparent_privileged` c `default_mark = 0`

Почему unsafe:
- policy routing не сможет нормально различать intercepted traffic

Ожидаемое поведение:
- `selection_error_code = "rollout_profile_prerequisites"`

### PREROUTING helper scope != config scope

Примеры:
- `prerouting_interface = "eth0"`, но helper запускается с `AEGIS_WIDE_INTERFACE=ens3`
- helper включает `PREROUTING`, а config остался на `output_only_safe`

Почему unsafe:
- client-side contract и firewall-side contract начинают описывать разные traffic domains

Ожидаемое поведение:
- preflight/smoke должны завершаться ошибкой ещё до runtime traffic check

## 4. Required Invariants

### Redirect baseline

Нужно соблюдать всегда:
- `AEGIS_EXEMPT_UID` задан
- `wide.listen != socks.listen`
- если включён `PREROUTING`, то есть `AEGIS_WIDE_INTERFACE`
- если config использует `prerouting_scoped`, то `prerouting_interface == AEGIS_WIDE_INTERFACE`

### TPROXY baseline

Нужно соблюдать всегда:
- `platform_backend = "linux_tproxy"`
- `rollout_profile = "transparent_privileged"`
- `default_mark != 0`
- `prerouting_interface == AEGIS_WIDE_INTERFACE`
- клиент запускается с возможностью поставить `IP_TRANSPARENT`
- policy routing helper и config смотрят на один и тот же `fwmark`

## 5. Recommended Rollout Order

Практический порядок rollout:

1. Начать с `output_only_safe` + `auto` или `linux_redirect`
2. Подтвердить, что owner exemption и listener separation работают стабильно
3. Если нужен ingress не только из локального `OUTPUT`, перейти к `prerouting_scoped`
4. Только после этого переходить к `transparent_privileged` + `linux_tproxy`

Не рекомендуется перескакивать сразу в `linux_tproxy`, если ещё не подтверждены:
- loop-avoidance
- port separation
- interface scoping discipline
- remediation path по capability failures

## 6. Helper Mapping

### `scripts/setup-wide-linux-redirect.sh`

Использовать для:
- `output_only_safe`
- `prerouting_scoped`

Env contract:
- `AEGIS_WIDE_PORT`
- `AEGIS_EXEMPT_UID`
- `AEGIS_ENABLE_PREROUTING`
- `AEGIS_WIDE_INTERFACE` при `PREROUTING`
- `AEGIS_ENABLE_DNS_PREVIEW=1` для узкого UDP preview в preview socket
- `AEGIS_DNS_PORT` для primary helper-side UDP rule; текущий client preview success-path тоже должен совпадать с `ingress.wide.dns_port` (по умолчанию `53`)
- `AEGIS_UDP_PREVIEW_PORTS=5353,853,...` для дополнительных helper-side UDP preview rules сверх primary `AEGIS_DNS_PORT`

### `scripts/setup-wide-linux-tproxy.sh`

Использовать только для:
- `transparent_privileged`

Важно:
- live audit на `Debian 13` public VPS теперь подтвердил жёсткий safety contract: blind `apply` по `AEGIS_WIDE_INTERFACE=<public-nic>` без SSH-safe bypass больше не проходит и fail-fast останавливается до firewall changes
- installed-product path теперь раскладывает helper прямо на host: после release install использовать `/usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh`, а не отдельный `scp` repo-side script
- supported public-host path теперь такой: сначала `doctor`, затем явный `AEGIS_WIDE_SSH_SAFE_PORTS=<ports>` и только потом `apply`; `AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=1` остаётся только conscious risk opt-in

Env contract:
- `AEGIS_WIDE_PORT`
- `AEGIS_WIDE_INTERFACE`
- `AEGIS_WIDE_IP_FAMILY=auto|ipv4|ipv6` для явного helper-side firewall/routing family; `auto` следует family из `ingress.wide.listen`
- `AEGIS_WIDE_FIREWALL_BACKEND=auto|xtables|nft` для явного выбора helper-side firewall backend; `auto` по-прежнему предпочитает `iptables`/`ip6tables`, но при их отсутствии может перейти на `nft`
- `AEGIS_WIDE_FWMARK`
- `AEGIS_WIDE_ROUTE_TABLE`
- `AEGIS_ENABLE_DNS_PREVIEW=1` для узкого UDP preview в preview socket
- `AEGIS_DNS_PORT` для primary helper-side UDP rule; текущий client preview success-path тоже должен совпадать с `ingress.wide.dns_port` (по умолчанию `53`)
- `AEGIS_UDP_PREVIEW_PORTS=5353,853,...` для дополнительных helper-side UDP preview rules сверх primary `AEGIS_DNS_PORT`
- `AEGIS_WIDE_STARTUP_WAIT_SECS` и `AEGIS_WIDE_REQUEST_TIMEOUT_SECS` для slow first-run smoke на Linux VM/host, где clean build или локальный namespace/relay datapath стартуют заметно медленнее happy-path
- `AEGIS_CLIENT_CONFIG` (опционально, для config-aware `doctor`/`status`)
- `AEGIS_RUNTIME_EVENTS_JSONL` и `AEGIS_ENABLE_RUNTIME_EVENTS_JSONL=0|1` для helper-managed long-running launch
- `AEGIS_RUNTIME_EVENTS_LIMIT` для post-launch `events` summary window
- `AEGIS_WIDE_ALLOW_ALL_INTERFACES=1` только если intentionally нужен unsafe lab-only all-interface `PREROUTING`; supported rollout path не должен на это опираться
- `AEGIS_WIDE_SSH_SAFE_PORTS=22,2222,...` для явных public-host SSH bypass `RETURN` rules перед `TPROXY`
- `AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=1` только для явного override public-host refusal; normal supported rollout path не должен считать это нормой

Practical happy-path:
- helper теперь печатает effective contract (`ip_family`, `firewall_backend`, `listen_port`, `fwmark`, `route_table`, `prerouting_interface`, `dns_preview`, `dns_port`, `udp_preview_ports`) и готовые `status` / `doctor` / `run` / `probe` / `launch` / `events` / `teardown` команды; при активном helper-side UDP capture summary сразу добавляет и family-aware `wide_udp_capture_policy` + `wide_udp_capture_runtime_scope`, а для `generic_capture_unstable` помечает preview allowlist knobs как `ignored_by_generic_capture_contract`
- при `AEGIS_WIDE_IP_FAMILY=ipv6` helper уже не ограничивается только runtime observability: firewall/apply/status/doctor/teardown теперь идут либо через `ip6tables` + `ip -6 rule/route`, либо через `nft` `ip6` table c тем же верхнеуровневым operator contract
- `AEGIS_WIDE_FIREWALL_BACKEND=nft` больше не считается отдельным lab-only side path: helper сохраняет те же `doctor` / `status` / `run` / `probe` / `events` surfaces, CI валидирует этот backend на network-free contract self-test слое, а hosted CI уже держит и живые guarded smoke для `dns` и `generic_udp`
- `apply` без `AEGIS_WIDE_INTERFACE` теперь fail-fast останавливается ещё до firewall changes; helper может подсказать candidate interface по Linux default route, но supported operator path остаётся только explicit/interface-scoped
- all-interface `PREROUTING` больше не выглядит как почти-normal fallback: его можно включить только явным `AEGIS_WIDE_ALLOW_ALL_INTERFACES=1`, и даже тогда helper помечает этот режим как unsafe opt-in, а не как supported rollout state
- на public/default-route interface helper теперь вставляет SSH-safe bypass rules раньше `TPROXY`, а отсутствие `AEGIS_WIDE_SSH_SAFE_PORTS` переводит `apply` в explicit refusal вместо best-effort риска потери доступа
- helper теперь strict и по policy-routing post-condition: `apply` больше не считается green, пока host реально не показывает `fwmark ${AEGIS_WIDE_FWMARK}` -> `lookup ${AEGIS_WIDE_ROUTE_TABLE}` и local-delivery route в той же table; partial failure теперь сворачивается rollback-ом helper state вместо тихого residue
- для DNS на отдельной client-machine helper теперь должен учитывать и loopback return path: на практике живой Ubuntu contour потребовал socket-matching защиты для existing sockets, local `OUTPUT` marking только для DNS UDP и дополнительного `PREROUTING -i lo` hook, чтобы systemd-resolved/upstream DNS path не проваливался в blackhole после policy routing
- `doctor` даёт operator-oriented pass/fail summary: проверяет наличие chain/hooks/policy route, существование интерфейса на host и, если задан `AEGIS_CLIENT_CONFIG`, совпадение helper contract с `ingress.wide` (`platform_backend`, `rollout_profile`, `listen`, `default_mark`, `prerouting_interface`, `capture_dns`, `dns_port`, `udp_preview_ports`, `udp_capture_contract`)
- на public-host path `doctor` теперь отдельно показывает `ssh_safe_ports` и предупреждает, когда default-route interface выглядит public-sensitive и blind apply потребует bypass ports или explicit dangerous opt-in
- для `linux_tproxy` этот drift-check теперь жёстче: helper считает supported только config с `rollout_profile = "transparent_privileged"`; `prerouting_scoped` больше не проходит как «почти совместимый» shape только потому, что тоже использует interface scope, а missing `fwmark` rule / route-table local delivery теперь сопровождаются и короткой remediation-подсказкой про повторный `apply`/`doctor`
- config-aware `doctor` теперь сверяет не только raw inputs, но и derived operator surface: `wide_udp_capture_support_tier`, `wide_udp_capture_policy` и `wide_udp_capture_runtime_scope` должны совпадать между helper env и client config, иначе это считается fail-fast contract drift до runtime traffic interception
- при `generic_capture_unstable` этот drift-check намеренно уже не делает `dns_port` / `udp_preview_ports` active fail-gate: helper теперь явно считает их ignored allowlist knobs для generic contract, чтобы operator path не притворялся preview-only semantics
- это даёт machine-friendly “host ready / contract drift” surface без запуска реального traffic smoke
- после успешного `doctor` следующий recommended шаг уже не сразу long-running client, а `AEGIS_CLIENT_CONFIG=<cfg> ./scripts/setup-wide-linux-tproxy.sh probe`; этот action внутри запускает `--ingress-startup-probe --json`, но печатает короткий operator summary и remediation по `failure_code` / `hint_code`, включая `startup.wide_udp_capture_runtime_scope`, когда startup path реально публикует этот field
- сам client-side `--ingress-preflight --json` и `--ingress-startup-probe --json` теперь для Linux wide rollout path с `selection.requested_primary = "wide"` дополнительно публикуют `selection.linux_validation_bootstrap_check_command` и `selection.linux_validation_bootstrap_install_command`, чтобы operator/automation могли перейти к тому же host-prep helper contract без отдельного поиска по README/runbook; pure `socks5` path не должен получать этот Linux-wide bootstrap handoff
- по той же причине pure `socks5` path не должен нести wide-rollout hints или `selection.backend_notes`: если `selection.requested_primary = "socks5"`, machine-readable preflight/startup contract не должен выглядеть как скрытый `linux_redirect`/`linux_tproxy` rollout
- `probe` возвращает `0` только когда startup path выглядит ready для supported `linux_tproxy`; degraded/error outcomes считаются operator-facing failure и требуют remediation до long-running запуска
- сам `probe` должен запускаться в том же privilege mode, что и будущий `linux_tproxy` client process
- после успешного `probe` helper action `launch` становится shortest-path entry point для long-running client start; по умолчанию он добавляет `--runtime-events-jsonl`, чтобы runtime event stream был включён сразу, но это можно отключить через `AEGIS_ENABLE_RUNTIME_EVENTS_JSONL=0`
- после `launch` helper action `events` читает runtime JSONL и печатает operator-facing summary не только по latest problem, но и по короткому product-status слою: `startup_health`, `runtime_status`, `product_verdict`, `runtime_degradation_count`, `failover_count`, `terminal_failure_count`; backend/problem summary по-прежнему поднимает и `wide_udp_capture_runtime_scope`, когда runtime event fields его публикуют. При этом isolated `relay_transport_failed` теперь считается degraded-runtime сигналом до тех пор, пока рядом не появился terminal session failure
- тот же `events` action теперь ещё и пишет canonical machine-readable evidence bundle (`AEGIS_OPERATOR_EVIDENCE_JSON`, по умолчанию рядом с `runtime-events.jsonl`), чтобы operator review и release/canary artifacts читали один и тот же short verdict
- `events` возвращает `0` только если startup/runtime status остались `healthy`; одного отсутствия warn/error record больше недостаточно, потому что release-gate теперь должен видеть и info-level degraded paths вроде `direct_relay_failover_triggered`
- при `ingress_udp_datagram_dropped` helper `events` теперь отдельно печатает `drop_reason_code`, `expected_dns_port` и `expected_udp_preview_ports`, чтобы allowlist mismatch был виден без ручного разбора JSONL
- если runtime drop произошёл уже при `generic_capture_unstable`, helper `events` больше не советует «просто opt into generic»: remediation теперь ведёт к inspection runtime drop stage/reason и reply path, а не обратно к preview allowlist knobs
- новый shortest-path wrapper теперь `run`: action сначала прогоняет `probe`, потом запускает long-running client с helper-managed `launch` contract и после выхода автоматически запускает `events`
- сам `probe` при успехе теперь тоже ведёт именно в helper-managed `run` / `launch`, а не советует обходить rollout flow прямым `cargo run`
- `run` возвращает `0` только если probe прошёл, client завершился с `0` и post-exit `events` подтвердили `startup_health=healthy`, `runtime_status=healthy`, `failover_count=0`, `terminal_failure_count=0`; retry/recovery path с `relay_transport_failed` без terminal outcome всё равно считается degraded и не проходит как clean green
- отдельные `probe` / `launch` / `events` остаются supported manual path для пошаговой отладки
- этот `run` contract теперь отдельно покрыт automation self-test script-ом `scripts/test-wide-linux-tproxy-helper-run-contract.sh`, который валидирует healthy path, runtime-warning path и probe-failure path без real-network smoke
- firewall backend surface теперь отдельно покрыт automation self-test script-ом `scripts/test-wide-linux-tproxy-firewall-contract.sh`, который без root/network smoke проверяет и `xtables`, и `nft` helper contract для `apply` / `doctor` / `status` / `teardown` уже по обеим family-осям (`ipv4`/`ipv6`)
- live smoke теперь должен интерпретировать concrete runtime-check codes раньше, чем broad `wide_runtime_readiness`: например, `listener_busy` должен вести к смене `AEGIS_WIDE_PORT`, а не к ложной remediation про `CAP_NET_ADMIN`

### `scripts/run-pair.sh`

Использовать для:
- локального relay bootstrap без Docker Compose
- быстрого получения known-good клиентского lab-config под `linux_tproxy` или `linux_redirect`
- lab/debug bootstrap, когда нужен явный low-level helper path поверх уже понятной role/install story

Не использовать как основной product entrypoint:
- для product install path теперь есть `./install.sh server` и `./install.sh client --bundle ...`
- `run-pair.sh` остаётся lab-oriented helper для ручного first-run/debug flow, а не главным ответом на вопрос "как пользователь ставит сервер и клиента"

Env contract:
- `AEGIS_WIDE_PROFILE=linux_tproxy_relay|linux_redirect_relay`
- `AEGIS_CLIENT_CONFIG` для пути generated client config
- `AEGIS_WIDE_PREROUTING_INTERFACE` или `AEGIS_WIDE_INTERFACE` для interface-scoped wide config
- `AEGIS_WIDE_LISTEN`
- `AEGIS_WIDE_DEFAULT_MARK`
- `AEGIS_SKIP_BUILD=1`, если нужен только быстрый config/bootstrap без release-build
- `AEGIS_SKIP_SERVER_START=1`, если нужен только config/bootstrap hint без запуска долгоживущего `aegis-server`

Recommended TPROXY happy-path:
- `AEGIS_WIDE_PROFILE=linux_tproxy_relay` теперь intentionally fail-fast требует `AEGIS_WIDE_PREROUTING_INTERFACE` или `AEGIS_WIDE_INTERFACE`
- printed happy-path теперь явно фиксирует equality contract `ingress.wide.prerouting_interface == AEGIS_WIDE_INTERFACE`, чтобы generated config и helper scope не расходились молча
- helper command, который печатает `run-pair.sh`, уже синхронизирован с generated config по `AEGIS_WIDE_PORT`, `AEGIS_WIDE_FWMARK` и `AEGIS_WIDE_ROUTE_TABLE`, а printed shortest-path теперь явно напоминает, что `run` опирается на уже подтверждённый helper-side `fwmark/table` contract
- printed happy-path теперь включает `doctor` между `apply` и запуском клиента, чтобы operator видел mismatch раньше runtime traffic interception
- printed happy-path теперь включает и helper `probe` между `doctor` и full client run, чтобы capability/listener failures были видны ещё до long-running startup без разбора сырого JSON
- printed happy-path теперь переводит и сам long-running старт на helper `launch`, чтобы startup/probe/run оставались в одном shell-guided flow и structured runtime JSONL включался по умолчанию
- printed happy-path теперь включает и post-launch `events`, чтобы runtime JSONL превращался в короткий operator summary, а не оставался только automation artifact
- printed happy-path теперь схлопнут в `run` как главный recommended flow, а `probe` / `launch` / `events` остаются как manual drill-down sequence
- это делает `run-pair.sh` главным shortest-path entry point для первого ручного `linux_tproxy` lab-run, а не только relay bootstrap helper

## 7. Smoke Mapping

### `scripts/smoke-wide-linux-redirect.sh`

Baseline mode:
- без `AEGIS_ENABLE_PREROUTING`
- временный config использует `rollout_profile = "output_only_safe"`

Scoped mode:
- с `AEGIS_ENABLE_PREROUTING=1`
- требует `AEGIS_WIDE_INTERFACE`
- временный config использует `rollout_profile = "prerouting_scoped"`

Optional DNS harness groundwork:
- c `AEGIS_ENABLE_DNS_PREVIEW=1` helper дополнительно вешает узкий UDP interception для `AEGIS_DNS_PORT` (по умолчанию `53`) и optional `AEGIS_UDP_PREVIEW_PORTS`
- временный client config в этом path теперь тоже пишет `ingress.wide.dns_port = <AEGIS_DNS_PORT>` и optional `ingress.wide.udp_preview_ports = [...]`, чтобы helper rule и runtime preview не расходились по expected destination ports
- сам smoke всё ещё проверяет HTTP/TCP path; UDP rule-set добавлен как controlled lab surface для следующего DNS success-side pass, а не как claim про готовый DNS e2e

Relay-backed DNS success mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=dns ./scripts/smoke-wide-linux-redirect.sh`
- helper поднимает локальный `aegis-server`, переводит client в `relay` mode с `transport_priority = ["masque_derived"]` и шлёт UDP probe через interface-scoped `PREROUTING` lab path из временного namespace
- текущий runtime success-path здесь намеренно остаётся диагностическим: kernel возвращает UDP original-dst уже как local redirect address (`*:15080`), поэтому preview path фиксирует `ingress_udp_datagram_dropped` вместо relay success

### `scripts/smoke-wide-linux-tproxy.sh`

Всегда использует:
- `platform_backend = "linux_tproxy"`
- `rollout_profile = "transparent_privileged"`
- `prerouting_interface = <host-veth>`

Optional DNS harness groundwork:
- c `AEGIS_ENABLE_DNS_PREVIEW=1` helper дополнительно ставит narrow UDP TPROXY rule для `AEGIS_DNS_PORT` (по умолчанию `53`) и optional `AEGIS_UDP_PREVIEW_PORTS`
- временный client config в этом path теперь тоже пишет `ingress.wide.dns_port = <AEGIS_DNS_PORT>` и optional `ingress.wide.udp_preview_ports = [...]`, чтобы helper rule и runtime preview не расходились по expected destination ports
- это подготавливает тот же interface-scoped lab path для будущего intercepted DNS success smoke, но текущий сценарий по-прежнему валидирует только HTTP/TCP transport

Relay-backed DNS success mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=dns ./scripts/smoke-wide-linux-tproxy.sh`
- helper поднимает локальный `aegis-server`, запускает client в `relay` mode с `transport_priority = ["masque_derived"]`, добавляет lab target IP на host loopback и шлёт UDP probe из временного namespace
- после подготовки lab interface smoke теперь проходит через helper `apply -> doctor -> probe`, а сам client внутри smoke стартует через helper-managed `launch`; это держит smoke на том же rollout sub-flow, что и ручной operator path до реального traffic smoke
- при runtime failure smoke дополнительно печатает helper `events` summary, а не только raw client log
- current runtime success-path здесь остаётся узким: original destination должен попасть в explicit preview allowlist (`dns_port` или `udp_preview_ports`), это не generic UDP interception smoke
- smoke при необходимости пишет и отдельный contract artifact (`AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT`) с `smoke_class`, `host_shape`, `firewall_backend_effective`, `wide_udp_capture_policy` и `wide_udp_capture_runtime_scope`, чтобы CI/operator automation могли assert-ить реальный helper backend и конкретный smoke mode отдельно от runtime JSONL клиента
- этот artifact теперь поднимает и machine-readable delivery/health surface (`runtime_delivery_stage`, `runtime_response_action`, `runtime_response_stage`, `runtime_health_status`, `runtime_transport_status`, `runtime_target_host`, `runtime_target_port`), когда runtime уже дошёл до `ingress_udp_datagram_observed` / `completed` / `dropped` или terminal transport/session failure; это делает return-delivery tail и transport degradation отдельным contract surface, а не просто stderr hint
- recovered relay warning тоже должен читаться честно: если перед success уже был `relay_transport_failed`, но terminal outcome дошёл до `completed`, smoke artifact сохраняет completed/healthy delivery surface и не маскирует recovered path под `terminal_transport_failure`
- рядом с repo-side runtime contour это теперь значит и более честную relay semantics для UDP: terminal `generic_udp` relay failure должен поднимать тот же `relay_transport_failed` / `RelayTerminalFailure` слой, что и tunnel relay path, а не оставаться special-case ошибкой без transport summary
- текущий known-good status подтверждён privileged Linux container run и может дополнительно проверяться guarded CI step-ом, если runner поддерживает `xt_TPROXY`; для IPv4 DNS path теперь есть и отдельный hosted-CI `nft`-backed smoke
- self-test runtime contract этого smoke теперь можно валидировать и на macOS shell, потому что временные файлы больше не завязаны на GNU-only `mktemp ...XXXXXX.suffix` pattern
- поверх этого теперь есть и отдельный network-free smoke-contract mirror (`scripts/test-wide-linux-tproxy-smoke-contract.sh`): он без реального `TPROXY`/namespace startup воспроизводит must-pass hosted smoke shapes и валидирует тот же artifact/runtime vocabulary, так что guarded Linux runner больше не является единственным источником истины для smoke contract слоя
- при startup/runtime failure smoke теперь должен указывать и на helper-side policy routing: кроме interface/firewall/timing, failure hints должны вести и к проверке `AEGIS_WIDE_FWMARK` / `AEGIS_WIDE_ROUTE_TABLE`

Relay-backed DNS IPv6 success mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=dns_ipv6 AEGIS_WIDE_SMOKE_IP_FAMILY=ipv6 ./scripts/smoke-wide-linux-tproxy.sh`
- helper переключается на `ip6tables` + `ip -6 rule/route`, временный client config слушает `[::]:<port>`, а UDP probe уходит из namespace на IPv6 lab target
- этот сценарий закрепляет первый firewall-backed IPv6 `linux_tproxy` path именно для narrow DNS preview baseline; он не притворяется generic IPv6 UDP smoke и пока intentionally не расширяется на arbitrary target ports
- guarded GitHub CI теперь может запускать этот режим отдельно от IPv4 DNS smoke, если runner реально поддерживает IPv6 loopback и IPv6 `TPROXY`

Relay-backed extra UDP preview success mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=udp_preview AEGIS_WIDE_UDP_PREVIEW_PORT=5353 ./scripts/smoke-wide-linux-tproxy.sh`
- helper поднимает локальный `aegis-server`, запускает client в `relay` mode с `transport_priority = ["masque_derived"]` и шлёт UDP probe из временного namespace уже на allowlisted extra preview port
- временный client config пишет `ingress.wide.udp_preview_ports = [<AEGIS_WIDE_UDP_PREVIEW_PORT>]`, а helper получает matching `AEGIS_UDP_PREVIEW_PORTS`, так что smoke валидирует не только runtime accept path, но и полный config/helper contract
- guarded CI может прогонять этот режим как первый real e2e smoke для `udp_preview_ports`, не притворяясь generic UDP validation

Relay-backed extra UDP preview drop mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=udp_preview_drop AEGIS_WIDE_UDP_PREVIEW_PORT=5353 AEGIS_WIDE_UDP_PREVIEW_DROP_TARGET_PORT=5300 ./scripts/smoke-wide-linux-tproxy.sh`
- helper оставляет preview allowlist на `dns_port` + `AEGIS_WIDE_UDP_PREVIEW_PORT`, но сам UDP probe уходит на non-allowlisted port и ожидаемо не получает ответа
- сценарий считается успешным только как negative-case: shell возвращает `EXIT_RUNTIME_SMOKE_REQUEST_FAILED`, а guarded CI отдельно читает сохранённый `runtime-events-jsonl` и assert-ит top-level drop vocabulary (`wide_udp_capture_drop_stage`, `wide_udp_capture_drop_reason_code`) вместе с existing preview-specific `drop_reason_code`
- это даёт первый real workflow-level contract именно для dropped UDP datagram path, а не только для happy-path success events

Relay-backed generic UDP success mode:
- `AEGIS_WIDE_SMOKE_PROTOCOL=generic_udp AEGIS_WIDE_GENERIC_UDP_TARGET_PORT=54321 ./scripts/smoke-wide-linux-tproxy.sh`
- временный client config пишет `ingress.wide.udp_capture_contract = "generic_capture_unstable"`, а helper-side contract тоже явно переключается в `AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable`
- в этом mode helper/runtime больше не должны читать `AEGIS_DNS_PORT` / `AEGIS_UDP_PREVIEW_PORTS` как active allowlist contract: это уже broader guarded generic surface для выбранной family, а не preview-port flow с другими именами
- тот же smoke теперь наследует и `AEGIS_WIDE_FIREWALL_BACKEND=auto|xtables|nft`, так что operator/CI могут гонять один и тот же privileged scenario поверх обоих helper backends без смены верхнеуровневого smoke contract
- helper в этом mode расширяет UDP `TPROXY` interception до arbitrary target port, иначе broader Linux IPv4 runtime path остался бы недостижим даже в privileged lab smoke
- после UDP echo smoke сценарий дополнительно читает `runtime-events-jsonl` и требует `wide_udp_capture_contract = "generic_capture_unstable"` + `wide_udp_capture_support_tier = "guarded_unstable"` + family-aware `wide_udp_capture_policy` (`any_target_port_linux_ipv4_unstable` или `any_target_port_linux_ipv6_unstable`), а top-level success vocabulary должна переключиться в `wide_udp_capture_match_kind = "generic_capture_contract"` и `wide_udp_capture_accept_reason_code = "matched_generic_udp_capture_contract"`; preview-only fields при этом остаются `null`
- shell success для этого режима теперь тоже должен читаться ограниченно: это подтверждение `guarded_unstable` Linux-only contract, а не production-ready generic UDP claim
- если smoke падает уже в `generic_capture_unstable`, remediation должна вести к runtime drop/reply path и helper/policy-routing state, а не обратно к подбору preview allowlist
- если runtime уже дошёл до `ingress_udp_datagram_completed`, новый artifact/hint surface должен классифицировать это именно как `completed_return_delivery_tail`: ingress/runtime path уже завершил обработку datagram, а оставшийся риск сидит между host-local send и namespace peer
- guarded CI теперь не только гоняет этот режим, но и отдельно assert-ит сохранённый smoke `runtime-events-jsonl` вместе с contract artifact, чтобы generic contract/policy/success vocabulary и реальный firewall backend не проверялись только внутри shell helper-а
- для первого IPv6 generic path тот же smoke запускается как `AEGIS_WIDE_SMOKE_PROTOCOL=generic_udp AEGIS_WIDE_SMOKE_IP_FAMILY=ipv6 ...`; helper переходит на `ip6tables` + `ip -6 rule/route`, а CI требует `linux_ipv6_only` вместе с IPv6 generic policy и теперь тоже сохраняет явный contract artifact вместо status-only evidence
- hosted CI теперь держит и первый `nft`-backed `generic_udp` smoke для IPv4, но это всё ещё не claim о полном dual-stack rollout baseline: richer-host matrix и non-Linux adapters остаются следующими слоями

Richer-host validation lane:
- канонический privileged entrypoint на хосте:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
bash ./scripts/bootstrap-wide-linux-validation-host.sh --check
sudo env HOME="$HOME" PATH="$PATH" bash ./scripts/validate-wide-linux-tproxy-rich-host.sh
```

- `bash ./scripts/bootstrap-wide-linux-validation-host.sh --check` перед первым прогоном на новом Linux shape; если host ещё сырой, тот же helper можно запустить как `bash ./scripts/bootstrap-wide-linux-validation-host.sh --install` для package-manager/rustup bootstrap
- эти же команды теперь дублируются и в client-side preflight/startup `selection` block как `linux_validation_bootstrap_*_command`, когда binary реально идёт по Linux wide rollout path с `requested_primary = "wide"`
- для automation тот же helper теперь умеет и `--json`: readiness/remediation path можно читать как machine-readable report, а не только как human-readable таблицу; туда теперь входит и `helper_exit_code`, чтобы orchestration видела не только semantic `error_code`, но и точный shell exit. Если среди аргументов вообще присутствует `--json` и helper получает неизвестный аргумент, parser-level fail path тоже обязан остаться machine-readable и вернуться как `error_code = "unknown_argument"` независимо от порядка аргументов, а не как human-only usage dump
- `sudo` semantics в этом JSON contract тоже фиксированы: interactive `sudo` на `--check` даёт `sudo.status = "warn"` и не переводит host в not-ready, а полное отсутствие `sudo` даёт `sudo.status = "missing"`, попадает в `missing_commands` и делает `ready = false`
- helper теперь дополнительно ищет `cargo` и в `~/.cargo/bin`, так что host с уже установленным `rustup` не требует ложного reinstall только из-за узкого login `PATH`
- сам privileged matrix нужно запускать с сохранёнными `HOME`/`PATH` под `sudo`, иначе root-shell может не увидеть user-level `cargo`
- direct contract дополнительно удерживает и anti-drift по этим статусам: набор `sudo.status`, реально используемых helper-ом, должен совпадать с набором статусов, закреплённых в self-test assertions
- по тому же принципу direct contract удерживает и top-level JSON schema set: набор top-level ключей, реально публикуемых helper-ом, должен совпадать с набором ключей, закреплённых assertions в self-test
- ещё один такой же anti-drift слой теперь держит и `commands[].status` vocabulary: набор статусов внутри command entries, реально публикуемых helper-ом, должен совпадать с набором статусов, закреплённых assertions
- nested keys тоже теперь закреплены через drift gate: набор ключей внутри `sudo` и внутри `commands[]`, реально публикуемых helper-ом, должен совпадать с набором ключей, закреплённых assertions
- install happy-path тоже теперь считается частью прямого JSON contract: `--install --json` должен стабильно публиковать detected `package_manager`, `ready = true`, `helper_exit_code = 0` и не расходиться с фактически вызванными install-step командами
- этот install happy-path теперь закреплён не только для `apt-get`, но и для остальных заявленных package-manager веток (`dnf`, `yum`, `zypper`), чтобы cross-distro bootstrap surface была проверена напрямую
- набор поддерживаемых package-manager веток тоже теперь удерживается anti-drift gate-ом: helper-side package-manager list должен совпадать с тем, что реально покрыто direct contract
- `--skip-rustup` закреплён не только как fail-path без `cargo`, но и как success-mode: при уже доступном `cargo` helper должен оставаться successful и публиковать `install_rustup = false`
- live richer-host matrix теперь тоже умеет сохранять этот bootstrap-report рядом с остальными artifacts как `host.bootstrap.json`, чтобы prerequisite snapshot и итоговый host evidence не приходилось собирать из разных мест
- этот bootstrap-artifact слой теперь удерживается не только live rerun-ом: network-free `scripts/test-wide-linux-tproxy-rich-host-contract.sh` умеет подставлять override bootstrap helper и валидирует, что bundle действительно протаскивает `host.bootstrap.json` в results/summary surface
- этот script не заменяет hosted GitHub CI, а даёт reproducible Linux host/container matrix поверх уже существующих smoke сценариев
- он запускает xtables/nft и IPv4/IPv6 validation shape там, где host реально поддерживает соответствующий `TPROXY` path, и складывает status/artifacts в локальный validation directory
- теперь этот path оформлен не только как набор `passed/skipped` status files, а как documented matrix: `matrix.targets.json` фиксирует operator target shapes, `matrix.results.json` собирает фактический host evidence, а `matrix-summary.md` держит короткий handoff between documented baseline и реально пройденным host coverage
- поверх этого bundle теперь ещё и пишет `bundle.manifest.json`, `rerun-rich-host.env` и `rerun-rich-host-validation.sh`: manifest даёт machine-readable индекс текущего proof bundle, а rerun helper фиксирует тот же bootstrap/validation contract как короткий повторяемый entrypoint для следующего host
- matrix summary теперь ещё и явно маркирует, какой target уже зеркалится в hosted must-pass subset, а какой остаётся richer-host-only coverage; для must-pass cases summary показывает и прямой Hosted CI mirror, чтобы operator не путал «нет в hosted CI» с «не является documented Linux target shape»
- поверх case-level artifacts richer-host lane теперь ещё и пишет отдельный `host.metadata.json` с machine-readable fingerprint (`os_id`, `os_version_id`, `kernel_release`, `machine`, `iproute2_version`, toolchain versions), а `matrix.results.json` / `matrix-summary.md` дублируют этот host fingerprint рядом с case evidence; это делает broader host coverage сравнимым уже по зафиксированному host shape, а не только по имени каталога или ручным заметкам
- live failure одного кейса больше не должен обрывать весь matrix: validation path пишет `failed:<exit>` для конкретного shape, продолжает остальные documented cases и только в самом конце возвращает non-zero, чтобы handoff содержал полный host evidence, а не только первый timeout
- отдельный network-free self-test дополнительно валит workflow drift, если реальные guarded step IDs расходятся с documented hosted subset; это удерживает must-pass contract независимым от live runner capability probing
- первый такой richer-host-only слой теперь включает IPv6 `nft` shapes (`dns-ipv6-nft`, `generic-udp-ipv6-nft`): helper/backend contract для них уже документирован и self-test-ится, но hosted CI пока не объявляет их must-pass subset
- для real Linux host matrix теперь заранее прогревает shared cargo target и передаёт более консервативные `AEGIS_WIDE_STARTUP_WAIT_SECS` / `AEGIS_WIDE_REQUEST_TIMEOUT_SECS`, чтобы first-run evidence не терялся из-за compile latency или медленного namespace/relay roundtrip
- richer-host matrix теперь ещё и сам резервирует отдельные `AEGIS_WIDE_PORT` / `AEGIS_SOCKS_PORT` / `AEGIS_RELAY_PORT` на каждый case, жёстко якорится в repo root для внутренних `cargo`-вызовов и ограничивает каждый smoke case своим timeout budget, чтобы default-host `listener_busy`, launch-cwd drift или один зависший IPv6/generic path не держали весь handoff в подвешенном состоянии
- `scripts/janitor-wide-linux-tproxy.sh` теперь safe/idempotent и без passwordless `sudo`: он больше не может зависнуть в cleanup loop на `ip rule del`, а быстро выходит с warning, если для полного cleanup нужен root shell
- финальный live rerun на Linux host теперь проходит по всем 8 documented shapes; из подтверждённых host-side remediation для IPv6 richer-host tails понадобились два конкретных слоя: explicit `ip6tables TPROXY --on-ip ::` в helper `xtables`-ветке и `nodad` на временных IPv6 smoke-адресах, чтобы matrix не ловил DAD/tentative race сразу после `ip -6 addr add`
- ожидаемый happy-path summary теперь должен заканчиваться полным `8/8 passed` списком (`dns-xtables`, `dns-nft`, `generic-udp-xtables`, `generic-udp-nft`, `dns-ipv6`, `dns-ipv6-nft`, `generic-udp-ipv6`, `generic-udp-ipv6-nft`); после отдельного `sudo bash ./scripts/janitor-wide-linux-tproxy.sh` на хосте не должно оставаться `aegis-smoke-*` netns, `lookup 100` policy rules и `AEGIS_WIDE_TPROXY` firewall artifacts
- подтверждённый distinct-host rerun теперь уже не просто “ещё один Linux host”, а конкретный fingerprinted shape: `Ubuntu 24.04.3 LTS`, `kernel 6.8.0-107-generic`, `iproute2-6.1.0`; эти поля лежат прямо в `host.metadata.json` и summary artifacts
- successful privileged rerun теперь должен оставлять bundle в inspectable operator shape, а не как root-only residue: validation script нормализует permissions на artifacts и, если запуск шёл через `sudo`, по возможности возвращает bundle во владение invoking user вместе с готовым rerun helper
- следующий rerun на втором host сначала показал ещё одну важную границу broader coverage: даже при том же userspace fingerprint (`Ubuntu 24.04.3 LTS`, `6.8.0-107-generic`, `iproute2-6.1.0`) helper-level capability evidence может разъехаться из-за host tooling defaults. На host `/home/dpi/work/aegis-second-validation-7a29dac/.artifacts-second-validation-rerun2` оба IPv6 probes ложно ушли в `unavailable` не из-за kernel/module gap, а потому что `probe_ipv6_loopback()` зависел от установленного `rg`
- после перевода loopback probe на dependency-free shell check второй host был повторно прогнан в `/home/dpi/work/aegis-second-validation-7a29dac/.artifacts-second-validation-rerun3` и дал полный `8/8 passed`; `host.metadata.json` сохранил тот же fingerprint, но capability profile теперь честно показывает `available` по всем четырём probes
- broader-host story на текущий момент поэтому уже честно опирается на два distinct Ubuntu 24.04 host rerun-а, но не идёт дальше этого: следующий meaningful validation step должен быть non-Ubuntu / non-6.8-family, а не очередной rerun того же семейства
- тот же принцип теперь дотянут и до hosted smoke surface: guarded GitHub CI больше не обязан устанавливать `ripgrep` только ради startup-log wait path, потому что smoke scripts уже умеют fallback-иться на `python3`; это уменьшает расхождение между “clean host” и hosted runner dependency contours
- чтобы следующий broader-host pass не возвращался к ad hoc host prep, richer-host lane теперь ещё и fail-fast проверяет `python3`/`ip`/`openssl`/`cargo`/`sudo` prerequisites и явно отправляет в `scripts/bootstrap-wide-linux-validation-host.sh`, вместо позднего падения уже посреди `cargo build` или первого smoke case
- bootstrap flow тоже закреплён отдельно: `scripts/test-bootstrap-wide-linux-validation-host-contract.sh` network-free проверяет и happy-path `--check`, и remediation/install surface, а теперь ещё и явно сравнивает полный набор helper `error_code` с набором direct assertions и сверяет `payload.helper_exit_code` с фактическим shell exit-status, чтобы next-host prep не дрейфовал от фактических richer-host needs и не получал тихий новый fail-path или сломанный exit contract без обновления контракта
- этот full-pass всё ещё остаётся evidence одного richer Linux host shape; broader host coverage нужно либо отдельно подтвердить на ещё одном distinct Linux shape, либо честно оставить как незакрытый хвост без усиления product claim
- если UDP smoke падает по timeout, но runtime summary уже дошёл до `ingress_udp_datagram_completed`, это надо читать как return-delivery problem между host local send и namespace peer; smoke helper теперь печатает эту подсказку отдельно, чтобы не смешивать её с отсутствием самого ingress/runtime path

## 8. Machine-Readable Remediation Surface

Operator automation должна ориентироваться не на prose, а на следующие surfaces:

Client-side:
- `selection.selection_error_code`
- `selection.wide_platform_family_supported`
- `selection.wide_supported`
- `selection.wide_runtime_readiness`
- `selection.wide_rollout_profile`
- `selection.wide_prerouting_interface`
- `selection.wide_prerouting_interface_candidate`
- `selection.wide_dns_port`
- `selection.wide_udp_preview_ports`
- `selection.wide_udp_capture_contract_requested`
- `selection.wide_udp_capture_policy`
- `hints[].code = "linux_redirect_dns_preview_nat_limited"` при `capture_dns + linux_redirect`
- `hints[].code = "udp_preview_allowlist_only"` при `capture_dns`, когда automation должна помнить, что current UDP preview принимает только `dns_port` + `udp_preview_ports`, а не arbitrary UDP
- `hints[].code = "generic_udp_capture_contract_requested"` при `ingress.wide.udp_capture_contract = "generic_capture_unstable"`, когда operator/automation должны помнить, что broader UDP path уже включён, но всё ещё Linux-only/unstable и без production-ready rollout contract
- `hints[].code = "prerouting_interface_candidate_detected"` когда Linux default route даёт assisted-detect candidate для explicit PREROUTING scope
- `runtime_checks[].code`
- `runtime_checks[target="wide.dns_preview"]`
- `selection.backend_notes[].code`

Runtime-side:
- `--runtime-events-jsonl`
- `direct_relay_preferred_from_probe_history.fields.observation_capture_confidence`
- `direct_active_probe_branch_selected.fields.observation_capture_confidence`
- `direct_active_stall_probe_retry_selected.fields.observation_capture_confidence`
- `direct_active_stall_probe_retry_skipped.fields.observation_capture_confidence`
- `direct_active_stall_probe_retry_budget_exhausted.fields.observation_capture_confidence`
- `direct_relay_failover_triggered.fields.observation_capture_confidence`
- `direct_session_succeeded.fields.observation_capture_confidence`
- `direct_active_stall_probe_finished.fields.observation_capture_confidence`
- `ingress_startup_selection_failed`
- `ingress_startup_fallback_selected`
- если `requested_primary = "socks5"`, runtime stream не должен публиковать `ingress_preflight_hint`, а `ingress_startup_plan_evaluated` не должен нести top-level wide rollout metadata (`wide_enabled`, `wide_supported`, `wide_platform_family_supported`, `wide_runtime_readiness`, `wide_platform`, `wide_rollout_profile`, `wide_prerouting_interface`, `wide_listen`): pure `socks5` path не должен выглядеть как скрытый wide rollout даже на уровне JSONL startup-story
- по той же причине pure `socks5` per-session runtime events (`ingress_accept_failed`, `ingress_session_broker_failed`, `ingress_tcp_connect_rejected`, `ingress_udp_associate_rejected`) не должны нести hidden-wide background metadata (`wide_supported`, `wide_platform_family_supported`, `wide_runtime_readiness`, `rollout_profile`, `rollout_profile_code`): эти поля остаются `null`, пока wide rollout вообще не requested
- `ingress_backend_started.fields.wide_dns_port`
- `ingress_backend_started.fields.wide_udp_capture_contract`
- `ingress_backend_started.fields.wide_udp_capture_policy`
- `ingress_backend_started.fields.wide_udp_capture_runtime_scope`
- `ingress_backend_started.fields.wide_udp_preview_policy`
- `ingress_backend_started.fields.wide_udp_preview_ports`
- для `ingress_backend_started` и live UDP events эти поля считаются active only: если runtime backend не `wide_primary`, `wide_udp_capture_*` / `wide_udp_preview_*` / `wide_dns_port` должны быть `null`, а `wide_udp_preview_ports` — пустым списком, даже когда requested wide config остаётся заполненным
- `ingress_wide_bind_fallback`
- `ingress_backend_started`
- `ingress_backend_started.fields.wide_dns_capture_preview_status`
- `ingress_session_broker_failed.fields.startup_path_code`
- `ingress_session_broker_failed.fields.startup_fallback_reason_code`
- `ingress_session_broker_failed.fields.startup_fallback_reason`
- `ingress_session_broker_failed.fields.startup_bind_error_code`
- hosted CI теперь держит этот late-fallback contract не только на startup events: для `wide_disabled -> socks5_fallback` и Linux-only `wide_bind_failed_fallback_started -> socks5_fallback` workflow отдельно проверяет, что `ingress_session_broker_failed` и `ingress_tcp_connect_rejected` сохраняют useful wide-requested context (`requested_primary`, `wide_supported`, `wide_platform_family_supported`, `wide_runtime_readiness`, `rollout_profile`, `startup_path_code`, `startup_fallback_reason_code` / `startup_bind_error_code`), а не деградируют в hidden-socks-only story
- `ingress_udp_datagram_observed.fields.wide_udp_capture_contract`
- `ingress_udp_datagram_observed.fields.wide_udp_capture_policy`
- `ingress_udp_datagram_observed.fields.wide_udp_capture_runtime_scope`
- `ingress_udp_datagram_observed.fields.wide_udp_capture_match_kind`
- `ingress_udp_datagram_observed.fields.wide_udp_capture_accept_reason_code`
- `ingress_udp_datagram_observed.fields.wide_udp_preview_policy`
- `ingress_udp_datagram_observed.fields.wide_udp_preview_match_kind`
- `ingress_udp_datagram_observed.fields.wide_udp_preview_accept_reason_code`
- `ingress_udp_datagram_observed.fields.wide_udp_preview_ports`
- `ingress_udp_datagram_dropped.fields.wide_udp_capture_contract`
- `ingress_udp_datagram_dropped.fields.wide_udp_capture_policy`
- `ingress_udp_datagram_dropped.fields.wide_udp_capture_runtime_scope`
- `ingress_udp_datagram_dropped.fields.wide_udp_capture_drop_stage`
- `ingress_udp_datagram_dropped.fields.wide_udp_capture_drop_reason_code`
- `ingress_udp_datagram_dropped.fields.wide_udp_preview_policy`
- `ingress_udp_datagram_dropped.fields.expected_udp_preview_ports`
- `ingress_udp_datagram_response_stage`
- `ingress_udp_datagram_completed.fields.wide_udp_capture_contract`
- `ingress_udp_datagram_completed.fields.wide_udp_capture_policy`
- `ingress_udp_datagram_completed.fields.wide_udp_capture_runtime_scope`
- `ingress_udp_datagram_completed.fields.wide_udp_capture_match_kind`
- `ingress_udp_datagram_completed.fields.wide_udp_capture_accept_reason_code`
- `ingress_udp_datagram_completed.fields.wide_udp_preview_policy`
- `ingress_udp_datagram_completed.fields.wide_udp_preview_match_kind`
- `ingress_udp_datagram_completed.fields.wide_udp_preview_accept_reason_code`
- `ingress_udp_datagram_completed.fields.wide_udp_preview_ports`
- `relay_udp_datagram_stage`
- `--ingress-startup-probe --json` -> `startup.wide_dns_capture_preview_status`

Shell-side:
- preflight exits `20`..`25`
- runtime exits `30`..`32`
- helper logs должны печатать readiness summary (`family_supported=... readiness=...`) до маппинга в stable exit codes

## 9. Current Linux-First Release Gate

Repo-side must-pass:
- `aegis-client/src/main.rs` runtime tests теперь должны держать не только один `wide_primary` happy-path, но и маленький product contour: stable-preview success, generic-capture success, local-response degradation, runtime-unready relay transport rejection, terminal generic-UDP relay transport failure и recovered-after-initial-transport-failure semantics и на relay TCP contour, и на generic UDP path
- `scripts/test-wide-linux-tproxy-smoke-contract.sh` должен отдельно подтверждать `runtime_health_status = healthy` для completed generic path, `degraded_capture_drop` для preview-drop и `transport_unhealthy` для terminal transport failure mirror

Operator-side must-pass:
- Ubuntu package/service shortest-path теперь начинается с `validate-debian-package-host.sh --run` как release gate для install/remove/reinstall/reapply/service/logs/events
- helper-side shortest-path для client runtime остаётся `apply -> doctor -> probe -> launch/events` или supervised `run`
- для wire-level proof поверх runtime JSONL теперь есть отдельный honest path: внешний `tcpdump`/`pcapng` capture -> `scripts/build-mimicry-wire-witness-summary.sh` -> `scripts/validate-mimicry-wire-host.sh --witness-summary`; этот слой не заменяет package/runtime gate, а только усиливает privileged mimicry evidence
- smoke artifact должен быть достаточен для быстрой классификации: `healthy`, `degraded_response_pending`, `degraded_capture_drop`, `transport_unhealthy`
- helper `events`/`run` теперь тоже должны подтверждать короткий status layer: `startup_health=healthy`, `runtime_status=healthy`, `product_verdict=green`, `failover_count=0`, `terminal_failure_count=0`; isolated `relay_transport_failed` без terminal session outcome здесь уже считается degraded-runtime evidence, а не hidden terminal failure
- recovered transport-warning path теперь должен читаться одинаково на всех слоях: repo-side generic UDP runtime proof, smoke artifact и helper status не должны превращать completed outcome в terminal failure только из-за раннего `relay_transport_failed`
- release/readiness claim не должен опираться только на helper green state без repo-side runtime proofs и smoke health artifact

Короткий operator path для реально поддержанного scope:
- сначала `validate-debian-package-host.sh --check`, затем repo-side runtime/self-test proofs, затем `validate-debian-package-host.sh --run` как Ubuntu package/service gate
- сам `validate-debian-package-host.sh --run` теперь уже включает canonical install-to-healthy release summary поверх host gate/handoff
- после package/service gate уже идёт installed-product flow: `bootstrap-install.sh server|client`, `systemctl enable --now`, `systemctl status`, `journalctl`, `runtime-events`
- для нового two-VPS reinstall отдельно выбираются точный приватный server distribution и точный публичный client-only package. Server facade требует независимый bootstrap SHA-256 и приватный exact `--release-base`; публичный репозиторий не содержит server manifest/archive. После server install передайте bundle/access record с проверенной UID-custody и запускайте root client bootstrap с явным утверждённым профилем; команды и границы приведены в [INSTALL](../../../INSTALL.md#linux-relay), [fronted delivery](../../cloudflare-fronted-operator-guide.md#legacy-fronted-bundle-delivery) и [private inputs](../../operations/private-installer-inputs.md).
- `scripts/redeploy-two-vps-release.sh` остаётся историческим контуром purge/redeploy с default `releases/latest` и прежним общим public release path. Он не является текущим способом установки приватного сервера и не должен запускаться для нового кандидата без отдельной сверки его доставки, pins, teardown и rollback. Связанный `scripts/run-linux-wide-mimicry-live-audit.sh` сохраняет сбор `systemctl`/`journalctl`, wire witness и `stealth-live-acceptance/`, но его вызов старого redeploy helper также не удостоверяет текущую exact/private установку или новый product gate.
- сам `scripts/purge-installed-aegis.sh` по умолчанию работает как dry-run и только с `--force` удаляет binaries, systemd units/env, `/etc/aegis`, `/var/lib/aegis-*`, `/var/log/aegis-client` и best-effort wide helper networking residue; это держит reinstall flow явным и повторяемым, а не ad-hoc ручной чисткой
- для daily operator remediation по-прежнему полезен `setup-wide-linux-tproxy.sh doctor|probe|events`, но release-facing truth теперь должен читаться из validation-generated artifacts, а не из отдельного wrapper summary
- `bootstrap --json` теперь считается machine-readable handoff layer для этого path: именно он публикует `supported_product_contour`, `supported_operator_scope`, `host_family_id`, `host_family_validation_tier`, `bootstrap_*` / `validation` / `upgrade_reapply` commands
- `bundle.manifest.json` теперь считается machine-readable operator index: `supported_operator_flow` описывает `bootstrap -> repo proofs -> richer-host validation -> doctor -> probe -> launch -> events`, а `release_gate.product_required_cases` отделяет product-green baseline от `guarded_evidence_only` и `rich_host_candidate`
- источником истины по host coverage считать `bundle.manifest.json`, `matrix.results.json`, `matrix-summary.md` и helper/smoke status surface, а не одиночный console line
- degraded/failed matrix cases остаются полезным diagnostics evidence и не должны маскироваться под universal Linux success claim; отдельно и passed `generic_capture_unstable` shapes не расширяют supported product claim без `product_required` subset и healthy helper/runtime status
- upgrade/reapply path должен оставаться тем же, а не ad-hoc: повторный installer/bundle run, затем `validate-debian-package-host.sh --run` на canary Ubuntu host, затем `systemctl daemon-reload -> status -> journalctl -> runtime-events`
- следующий честный non-Ubuntu expansion contour теперь фиксируется прямо в bundle как `documented_host_family_matrix`: ближайшая цель = `debian-apt`, а `rhel-dnf` / `suse-zypper` остаются planned families до живого richer-host evidence
- machine-readable matrix теперь дополнительно фиксирует `canonical_release_family = debian-apt`, `release_claim_boundary = ubuntu_first_only` и `next_expansion_candidate`, чтобы next-family work не читался как уже закрытый ship-ready claim
- current deploy story остаётся Linux-first и server-centric: `compose.yaml` покрывает `aegis-server`, а supported client path = установленный Ubuntu binary/runtime-events flow (`aegis-client --ingress-preflight` / `--ingress-startup-probe` / `aegis-client.service` + `runtime-events.jsonl`)
- canonical Ubuntu wire-proof run теперь должен читаться так: `runtime-events.jsonl` фиксирует active wire plan, внешний host/bridge capture сохраняется в `pcapng`, затем `scripts/build-mimicry-wire-witness-summary.sh --pcap capture.pcapng --runtime-events runtime-events.jsonl --output wire-witness-summary.json`, и только после этого `scripts/validate-mimicry-wire-host.sh --run --runtime-events runtime-events.jsonl --artifact-dir <dir> --witness-summary wire-witness-summary.json`; если witness mismatch/uncorrelated, verdict обязан оставаться degraded
- controlled pilot evidence теперь тоже рекомендуется сводить в один bundle через validation-generated manifest: `scripts/build-ubuntu-controlled-pilot-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json> [--blocked-shape ...] [--wire-witness-summary ...] [--wire-acceptance-summary ...]`
- restart/reapply/rollback operator canary теперь тоже materialize-ится отдельно и без ручного чтения phase table: `scripts/build-ubuntu-operator-reapply-canary.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json>`; helper читает validation-generated `phase_results` и отдельно классифицирует `service_restart`, `reboot_contract`, `remove/reinstall` и `upgrade_reapply`
- Ubuntu-only remote pilot bundle теперь тоже materialize-ится одним entrypoint: `scripts/build-ubuntu-field-pilot-remote-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json> [--relay-host ...] [--client-host ...] [--blocked-shape ...]`; helper собирает `operator canary`, `pilot review` и `release wave` в один handoff поверх тех же inputs
- release bundle/package-root/server package теперь обязаны нести этот evidence layer внутрь артефактов: `validate-debian-package-host.sh`, pilot/review/wave helper-ы и post-release stealth/mimicry handoff scripts больше не считаются repo-only tooling
- pilot bundle/review/wave artifacts теперь надо читать в три слоя: `service_health_verdict` отдельно отвечает за install/service/runtime health, `baseline_bypass_ready` показывает что Ubuntu bypass contour жив на базовом runtime уровне, а `hostile_path_verdict` / `fully_proven` отдельно отвечают за hostile-path proof с независимым witness; `ship_ready` больше нельзя трактовать как простой синоним service health или полного hostile-path proof
- controlled pilot review bundle теперь дополнительно тащит и `operator_reapply_canary_json`, чтобы must-pass/advisory rollout contract не существовал отдельно от restart/reapply/rollback canary evidence
- canonical pilot playbook теперь тоже можно materialize-ить отдельно: `scripts/build-ubuntu-controlled-pilot-playbook.sh <output-dir> [--relay-host ...] [--client-host ...] [--blocked-shape ...]`
- shortest one-shot Ubuntu pilot/review path теперь есть и поверх тех же inputs: `scripts/build-ubuntu-controlled-pilot-review-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json> [--matrix-manifest ...] [--wire-witness-summary ...] [--wire-acceptance-summary ...]`
- top-level Ubuntu release wave теперь тоже имеет короткий orchestration entrypoint: `scripts/build-ubuntu-release-wave-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json> [--matrix-manifest ...] [--wire-witness-summary ...] [--wire-acceptance-summary ...]`; helper материализует `pilot-review-bundle/`, `ubuntu-release-wave-status.json` и итоговый wave manifest
- отдельный reusable Ubuntu release-wave status helper тоже есть: `scripts/ubuntu-release-wave-status.sh --pilot-inputs <ubuntu-controlled-pilot-inputs.json> --pilot-review-manifest <pilot-review.manifest.json> --output <status.json>`; он теперь держит `baseline_ship_ready` отдельно от `fully_proven_hostile_path`, чтобы baseline bypass и hostile-path proof не смешивались в один verdict
- release review поверх live Ubuntu evidence теперь надо собирать отдельно и явно: `scripts/build-ubuntu-release-review.sh <output-dir> --release-summary <ubuntu-product-release-summary.json> --pilot-bundle <pilot-summary.json> [--matrix-manifest ...] [--wire-acceptance-summary ...]`; если blocked-shape evidence, correlated witness и зелёный wire proof присутствуют вместе, review повышает product contour до `wire_level_supported_hostile_path`, иначе честно оставляет только baseline transport/runtime tier
- отдельный post-release technical track теперь ещё и materialize-ится как summary helper: `scripts/build-post-release-stealth-wave-summary.sh <output-dir> [--ubuntu-release-wave-status ...] [--wire-acceptance-summary ...]`; helper теперь держит первый milestone `witness_maturity_and_correlation_discipline` как отдельный state/next action, а stealth wave должна начинаться только после `fully_proven` Ubuntu bypass и `wire_level_supported_hostile_path`
- следующий Ubuntu-only implementation handoff после этого summary теперь тоже materialize-ится отдельно: `scripts/build-ubuntu-mimicry-next-contour.sh <output-dir> --stealth-summary <stealth-wave-summary.json>`; helper вытаскивает `linux_wire_mimicry_execution_contour`, runtime slice ladder и главные code paths вместо prose-only backlog
- после стабилизации Ubuntu-first release contour все deeper stealth/mimicry claims должны открываться отдельной wave и не менять retroactively release bar для package/service/operator gate

## 10. Current Boundaries

Этот runbook **не** обещает:
- полноценный persistent firewall orchestration layer
- automatic rollback applied rules on host crash beyond helper teardown semantics
- non-Linux parity for WinDivert/macOS PF
- подтверждённый production e2e для `TPROXY` без privileged Linux run; текущий known-good status ограничен локальным privileged Linux smoke
- production-ready DNS interception path для `ingress.wide.capture_dns`; сейчас есть только narrow Linux/IPv4 UDP preview с configurable `dns_port` и optional `udp_preview_ports`, а generic UDP/IPv6 capture и operator rollout contract ещё не завершены

Но он уже фиксирует текущий supported operating envelope достаточно жёстко, чтобы:
- не смешивать rollout intent с incompatible backend semantics
- не расширять PREROUTING scope молча
- не терять sync между config и helper interface scope

Отдельно важно:
- `darwin`/macOS теперь должен читаться как **honest degraded baseline**, а не как скрытый `Linux-lite`: supported story там = compile/test/dev UX, preflight/startup/runtime-reporting и machine-readable `unsupported_adapter` / `socks5_fallback`
- если проект позже откроет отдельный `macOS PF` трек, это должен быть новый platform epic со своим scope, а не неявное расширение этого Linux runbook
- observation/probe/fingerprint, broader health layer и experimental ветки (`URLTest`-like health, `TURN/WebRTC`, `Geneva-style`, deeper wire-level mimicry) остаются следующими фазами и не должны маскироваться под уже закрытый Linux-first release gate

## 11. Deployment Matrix

Следующий practical rollout шаг уже не в single-host smoke, а в reproducible matrix для разных сред.

### Separate relay-server

Shape:
- `aegis-server` запускается на отдельном Linux server
- `aegis-client` запускается на другом Linux host/VM
- client config использует `mode = "relay"` и указывает `relay.server` на отдельный host

Success criteria:
- relay-server слушает TCP/UDP transport port
- client preflight/startup не деградирует по capability/listener причинам
- helper scope и `prerouting_interface` согласованы на клиентском host

Current status:
- binary/Docker deploy path для relay-server уже подтверждён
- multi-host operator flow теперь можно bootstrap'ить через `scripts/run-pair.sh`, если явно задать `AEGIS_RELAY_SERVER`, `AEGIS_RELAY_SERVER_NAME`, `AEGIS_RELAY_CA_CERT`, `AEGIS_RELAY_AUTH_TOKEN`; generated client config при этом уже не завязан на локальный `127.0.0.1:8443`
- live remote proof уже выполнен и в более честном shape `1 relay + 2 clients`: один `aegis-server` на `192.0.2.11` обслужил два разных Linux-клиента (`192.0.2.12`, `192.0.2.13`), и оба получили `HTTP/1.0 200 OK` через один relay-host

### Separate client host

Shape:
- relay может быть локальным или удалённым
- все wide helpers (`redirect` / `tproxy`) и policy routing применяются только на клиентском Linux host

Success criteria:
- `ingress.wide.prerouting_interface == AEGIS_WIDE_INTERFACE`
- `default_mark != 0` для `linux_tproxy`
- клиент может успешно выставить `IP_TRANSPARENT`

Current status:
- это основной supported target для Linux-wide rollout
- current operator ergonomics уже лучше, но всё ещё опираются на lab-oriented helpers, а не на persistent firewall manager
- practical happy-path: relay-target задаётся в generated client config, а `setup-wide-linux-tproxy.sh` / policy routing применяются только на клиентском host
- direct safety net на separate client host уже подтверждён удалённо: для обоих клиентов (`192.0.2.12`, `192.0.2.13`) controlled stall target сначала принял direct attempt от самого клиента, потом relay-backed retry от `192.0.2.11`, а client-side JSONL зафиксировал `direct_relay_failover_triggered` без `ingress_session_failed` и без `relay_transport_failed`
- следующий незакрытый слой для этого же deployment shape теперь уже узкий: multi-host `wide/linux_tproxy` proof на separate client host, а не базовая relay-connectivity или direct-to-relay viability
- этот следующий слой уже закрыт как live multi-host proof: на `192.0.2.12` и `192.0.2.13` `linux_tproxy` поднялся как `wide_primary_started`, isolated `netns` traffic реально ушёл через interception path, а remote target на relay-host увидел source `192.0.2.11`, то есть relay pickup произошёл поверх separate-client `wide`
- terminal success тоже подтверждён: при нормальном full-read HTTP client (`curl --http1.0` из `netns`) на обоих клиентах после ответа не появляется ни `relay_transport_failed`, ни `ingress_session_failed`; предыдущий `Connection reset by peer` оказался свойством грубого test harness, а не самого multi-host `wide/linux_tproxy` path
- отдельный privileged DNS contour на Ubuntu separate client host теперь тоже подтверждён live: DNS datagram'ы реально наблюдаются как `ingress_udp_datagram_observed`, уходят в relay как `relay_udp_datagram_stage` и возвращаются как `ingress_udp_datagram_completed`, то есть DNS relay proof больше не остаётся только smoke/CI-заготовкой
- practical boundary после этого уточнена: safe `linux_redirect` baseline остаётся честным TCP/HTTPS baseline, а полноценный Ubuntu DNS contour считается доказанным только на privileged `linux_tproxy` path

### Linux VM

Shape:
- тот же Linux client host path, но внутри hypervisor/bridge/NAT окружения

Success criteria:
- выбран именно ingress-facing VM interface, а не bridge-only/management iface
- `wide.listen` не конфликтует с уже занятым портом
- helper scope и config scope совпадают

Current status:
- VM считается supported только как Linux host variant
- interface selection здесь особенно чувствительна, поэтому silent auto-detect считается unsafe

### Privileged container

Shape:
- privileged Linux container используется как reproducible validation environment для `linux_tproxy`
- helper/smoke используют root, `iptables`, `ip netns`, policy routing и capability surface внутри container

Success criteria:
- container имеет `--privileged` или эквивалентный capability set
- есть `xt_TPROXY`, `iptables`, `iproute2`
- guarded DNS smoke проходит end-to-end

Current status:
- это current known-good validation shape для `linux_tproxy` smoke и CI-like checks
- это не заменяет production operator story для separate host/server deployment

## 11. Interface Selection Strategy

Для `PREROUTING` / `TPROXY` сейчас есть три возможные стратегии:

### Explicit interface only

Плюсы:
- минимальный риск
- нет скрытой магии
- лучше всего работает на multi-homed host, VM bridge, VPN и namespace-heavy setup

Минусы:
- больше ручного ввода

### Silent auto-detect

Плюсы:
- минимальное число шагов

Минусы:
- слишком легко выбрать не тот iface
- helper и config могут разъехаться незаметно
- all-interface fallback остаётся опасным default shape

### Assisted-detect + strict apply gate

Это текущий рекомендуемый компромисс.

Практический contract:
- preflight / launcher / helper могут показать candidate interface по Linux default route
- final `ingress.wide.prerouting_interface` и `AEGIS_WIDE_INTERFACE` всё равно задаются явно
- candidate interface — это hint, а не implicit rollout decision
- `scripts/setup-wide-linux-tproxy.sh apply` без явного интерфейса теперь завершается ошибкой; all-interface path доступен только через явный `AEGIS_WIDE_ALLOW_ALL_INTERFACES=1`

Почему выбран именно этот путь:
- он улучшает UX для separate host / VM / container
- но не ломает основной safety contract: PREROUTING scope остаётся operator-owned и machine-readable
