# Server configuration fixtures

The configuration implementation remains in [config.rs](../config.rs).
[legacy_tcp_limits_tests.rs](legacy_tcp_limits_tests.rs) checks the defaults,
operator-selected long authenticated silence budget and rejection of zero or
excessive deadlines for the separately scoped legacy TCP path. The file is
compiled only as a test module; it does not construct a listener or read a real
credential, key or certificate file.

The fixture definitions are prepared source and have not been executed by the
preparation agent. The focused QA command is documented in
[the legacy TCP policy directory](../session/legacy_tcp/README.md).
