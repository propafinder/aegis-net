//! v39 (B-06 menu-bar app, source only; not yet run installed): the AEGIS
//! menu-bar app, started when AEGIS.app is opened from Finder (no verb, no
//! terminal: `menu_model::launched_as_app`).
//!
//! The app is a thin shell. One worker thread runs every action as a child
//! of this same signed executable with one existing CLI verb
//! (`menu_flow`), one at a time, and polls read-only verbs for the state;
//! the main thread only draws the status item and its menu, asks before
//! anything that shows a macOS prompt, and opens the file picker. It never
//! changes a System Settings value itself, never turns the leak guard off,
//! never forgets an identity and never runs a verb the CLI does not have.
//! Quitting leaves the tunnel and the leak guard as they are, unless the
//! user chooses "Disconnect and Quit".
//!
//! v45: "Join with Invitation…" picks one `.aegis-invite` file, copies it
//! into the app's private inbox (`invite_package::copy_to_inbox`; the
//! child never reads a privacy-protected folder) and runs
//! `--enroll COPY --remove-source` as a child, showing each progress step.
//! After a join it offers to delete the chosen file. Every menu string is
//! English or Russian, following the system language (`menu_l10n`).

use crate::appkit::{
    NSAlert, NSApplication, NSImage, NSMenu, NSMenuItem, NSOpenPanel, NSPasteboard, NSStatusBar,
    NSStatusItem, NSWorkspace, ACTIVATION_POLICY_ACCESSORY, ALERT_FIRST_BUTTON,
    ALERT_STYLE_INFORMATIONAL, ALERT_STYLE_WARNING, IMAGE_ONLY, MODAL_RESPONSE_OK,
    PASTEBOARD_TYPE_STRING, VARIABLE_STATUS_ITEM_LENGTH,
};
use aegis_network_extension::{
    invite_package::{self, PackageSource},
    menu_diagnostics::{self, EventLog, ReportInput},
    menu_flow::{self, Outcome, ProcessRunner, Runner},
    menu_l10n::{self, tr},
    menu_model::{
        self, derive, explain, Activity, JoinStep, MenuView, NativeStatus, Observation, Primary,
        SetupStep,
    },
};
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, Sel};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly};
use objc2_foundation::{NSArray, NSBundle, NSProcessInfo, NSString, NSURL};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A full refresh (extension list, certificate, leak guard) at least this
/// often; light refreshes between.
const FULL_EVERY: Duration = Duration::from_secs(60);
/// Poll while something changes (connecting, an action, an approval).
const FAST_POLL: Duration = Duration::from_secs(3);
const SLOW_POLL: Duration = Duration::from_secs(20);
/// How long "Disconnect and Quit" waits to see the tunnel down.
const QUIT_DISCONNECT_WAIT: Duration = Duration::from_secs(20);

const APPKIT: &std::ffi::CStr = c"/System/Library/Frameworks/AppKit.framework/AppKit";

struct AppInfo {
    /// `CFBundleShortVersionString (CFBundleVersion)`.
    version: String,
    build: Option<String>,
    macos: String,
    macos_major: isize,
    exe: PathBuf,
    in_applications: bool,
    /// v45: the private inbox the chosen invitation is copied into.
    inbox: Option<PathBuf>,
}

static INFO: OnceLock<AppInfo> = OnceLock::new();

fn info() -> &'static AppInfo {
    INFO.get()
        .expect("menu app info is set before the worker starts")
}

/// One action at a time, in order; refreshes run when nothing is queued.
#[derive(Clone, Debug)]
enum Job {
    Refresh {
        full: bool,
    },
    Connect,
    Disconnect,
    ForceStop,
    EnableGuard {
        wizard: bool,
    },
    Activate {
        wizard: bool,
    },
    Import {
        dir: PathBuf,
        remove_source: bool,
        wizard: bool,
    },
    /// v45: `copy` is the inbox copy of `original`, the file the user chose.
    Join {
        copy: PathBuf,
        original: PathBuf,
        source: PackageSource,
        replace_identity: bool,
        wizard: bool,
    },
    AddVpn {
        wizard: bool,
    },
    Diagnostics,
    QuitAfterDisconnect,
}

struct State {
    obs: Observation,
    events: EventLog,
    jobs: VecDeque<Job>,
    last_full: Option<Instant>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

fn shared() -> &'static Shared {
    SHARED.get().expect("menu app state is set before use")
}

fn state() -> MutexGuard<'static, State> {
    shared()
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn enqueue(job: Job) {
    let mut guard = state();
    if matches!(job, Job::Refresh { .. })
        && guard
            .jobs
            .iter()
            .any(|queued| matches!(queued, Job::Refresh { .. }))
    {
        return;
    }
    guard.jobs.push_back(job);
    drop(guard);
    shared().wake.notify_one();
}

/// Run `work` on the main thread (the main queue), after the current call.
fn on_main(work: impl FnOnce(MainThreadMarker) + Send + 'static) {
    DispatchQueue::main().exec_async(move || {
        if let Some(mtm) = MainThreadMarker::new() {
            work(mtm);
        }
    });
}

fn render_later() {
    on_main(render);
}

// ---------------------------------------------------------------------------
// Worker thread: every child verb runs here, never on the main thread.

fn poll_interval(obs: &Observation) -> Duration {
    let changing = !obs.refreshed
        || obs.activity.is_some()
        || obs.approval_requested
        || matches!(
            obs.native_status(),
            Some(
                NativeStatus::Connecting | NativeStatus::Reasserting | NativeStatus::Disconnecting
            )
        );
    if changing {
        FAST_POLL
    } else {
        SLOW_POLL
    }
}

fn next_job() -> Job {
    let mut guard = state();
    loop {
        if let Some(job) = guard.jobs.pop_front() {
            return job;
        }
        let interval = poll_interval(&guard.obs);
        let (next, waited) = shared()
            .wake
            .wait_timeout(guard, interval)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard = next;
        if waited.timed_out() && guard.jobs.is_empty() {
            let full = guard.last_full.is_none_or(|at| at.elapsed() >= FULL_EVERY);
            return Job::Refresh { full };
        }
    }
}

fn worker(exe: PathBuf) {
    let mut runner = ProcessRunner::new(exe);
    loop {
        let job = next_job();
        run_job(&mut runner, job);
    }
}

fn do_refresh(runner: &mut dyn Runner, full: bool) {
    let mut obs = state().obs.clone();
    let events = menu_flow::refresh(runner, &mut obs, full, now());
    let mut guard = state();
    guard.obs = obs;
    if full {
        guard.last_full = Some(Instant::now());
    }
    let at = now();
    for event in &events {
        guard.events.push(at, event);
    }
    drop(guard);
    render_later();
}

/// The first sentence of `message`, short enough for a menu line.
fn short(message: &str) -> String {
    let sentence = message.split(". ").next().unwrap_or(message);
    let mut text: String = sentence.chars().take(110).collect();
    if text.len() < sentence.len() {
        text.push('…');
    }
    text
}

/// Mark `activity`, run `flow`, record its events and outcome, then refresh.
fn action(
    runner: &mut dyn Runner,
    activity: Activity,
    flow: impl FnOnce(&mut dyn Runner) -> Outcome,
) -> Outcome {
    {
        let mut guard = state();
        guard.obs.activity = Some(activity);
        guard.obs.notice = None;
    }
    render_later();
    let outcome = flow(&mut *runner);
    {
        let mut guard = state();
        let at = now();
        for event in &outcome.events {
            guard.events.push(at, event);
        }
        guard.obs.activity = None;
        if outcome.approval_needed {
            guard.obs.approval_requested = true;
        }
        guard.obs.notice = (!outcome.ok).then(|| {
            format!(
                "{} {}",
                tr("Last action:", "Последнее действие:"),
                short(&outcome.message)
            )
        });
    }
    do_refresh(runner, true);
    outcome
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Connect,
    Disconnect,
    ForceStop,
    EnableGuard,
    Activate,
    Import,
    AddVpn,
}

fn run_job(runner: &mut ProcessRunner, job: Job) {
    let (kind, wizard, outcome) = match job {
        Job::Refresh { full } => return do_refresh(runner, full),
        Job::Diagnostics => {
            do_refresh(runner, true);
            let report = build_report();
            on_main(move |mtm| show_when_free(mtm, move |mtm| copy_report(mtm, &report)));
            return;
        }
        Job::QuitAfterDisconnect => {
            let outcome = action(runner, Activity::Disconnecting, menu_flow::disconnect);
            let down = wait_until_down(runner, QUIT_DISCONNECT_WAIT);
            on_main(move |mtm| {
                show_when_free(mtm, move |mtm| {
                    quit_after_disconnect(mtm, outcome.ok && down)
                })
            });
            return;
        }
        Job::Connect => (
            Kind::Connect,
            false,
            action(runner, Activity::Connecting, menu_flow::connect),
        ),
        Job::Disconnect => (
            Kind::Disconnect,
            false,
            action(runner, Activity::Disconnecting, menu_flow::disconnect),
        ),
        Job::ForceStop => (
            Kind::ForceStop,
            false,
            action(runner, Activity::Stopping, menu_flow::force_stop),
        ),
        Job::EnableGuard { wizard } => (
            Kind::EnableGuard,
            wizard,
            action(runner, Activity::EnablingGuard, menu_flow::enable_guard),
        ),
        Job::Activate { wizard } => (
            Kind::Activate,
            wizard,
            action(runner, Activity::Activating, |runner| {
                menu_flow::activate(runner, &mut || {
                    state().obs.approval_requested = true;
                    render_later();
                    on_main(|mtm| show_when_free(mtm, |mtm| approval_help(mtm, false)));
                })
            }),
        ),
        Job::Import {
            dir,
            remove_source,
            wizard,
        } => (
            Kind::Import,
            wizard,
            action(runner, Activity::Importing, |runner| {
                menu_flow::import(runner, &dir, remove_source)
            }),
        ),
        Job::Join {
            copy,
            original,
            source,
            replace_identity,
            wizard,
        } => {
            let outcome = action(runner, Activity::Joining(JoinStep::Checking), |runner| {
                menu_flow::join(runner, &copy, replace_identity, &mut |step| {
                    state().obs.activity = Some(Activity::Joining(step));
                    render_later();
                })
            });
            // The host removes its copy after a commit; any other end
            // leaves it, and it is only a copy of the chosen file.
            if let Some(inbox) = &info().inbox {
                invite_package::discard_inbox_copy(&copy, inbox);
            }
            on_main(move |mtm| {
                show_when_free(mtm, move |mtm| {
                    joined(mtm, wizard, &outcome, &original, &source)
                })
            });
            return;
        }
        Job::AddVpn { wizard } => (
            Kind::AddVpn,
            wizard,
            action(
                runner,
                Activity::SavingProfile,
                menu_flow::add_vpn_configuration,
            ),
        ),
    };
    on_main(move |mtm| show_when_free(mtm, move |mtm| finished(mtm, kind, wizard, &outcome)));
}

fn wait_until_down(runner: &mut dyn Runner, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    loop {
        do_refresh(runner, false);
        let up = state()
            .obs
            .native_status()
            .is_some_and(NativeStatus::tunnel_up);
        if !up {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn build_report() -> String {
    let guard = state();
    let at = now();
    let view = derive(&guard.obs, at);
    let events = guard.events.entries();
    let info = info();
    menu_diagnostics::report(&ReportInput {
        now: at,
        app_version: &info.version,
        macos_version: &info.macos,
        observation: &guard.obs,
        view: &view,
        events: &events,
    })
}

// ---------------------------------------------------------------------------
// Main thread: the status item, its menu and the dialogs.

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AegisMenuController"]
    struct MenuController;

    unsafe impl NSObjectProtocol for MenuController {}

    impl MenuController {
        #[unsafe(method(connect:))]
        fn connect(&self, _sender: Option<&AnyObject>) {
            enqueue(Job::Connect);
        }

        #[unsafe(method(disconnect:))]
        fn disconnect(&self, _sender: Option<&AnyObject>) {
            enqueue(Job::Disconnect);
        }

        #[unsafe(method(forceStop:))]
        fn force_stop(&self, _sender: Option<&AnyObject>) {
            confirm_force_stop(self.mtm());
        }

        #[unsafe(method(setup:))]
        fn setup(&self, _sender: Option<&AnyObject>) {
            run_setup(self.mtm());
        }

        #[unsafe(method(openSettings:))]
        fn open_settings(&self, _sender: Option<&AnyObject>) {
            approval_help(self.mtm(), true);
        }

        #[unsafe(method(enableGuard:))]
        fn enable_guard(&self, _sender: Option<&AnyObject>) {
            confirm_enable_guard(self.mtm(), false);
        }

        #[unsafe(method(importInvitation:))]
        fn import_invitation(&self, _sender: Option<&AnyObject>) {
            import_dialog(self.mtm(), false);
        }

        #[unsafe(method(joinInvitation:))]
        fn join_invitation(&self, _sender: Option<&AnyObject>) {
            join_dialog(self.mtm(), false);
        }

        #[unsafe(method(copyDiagnostics:))]
        fn copy_diagnostics(&self, _sender: Option<&AnyObject>) {
            enqueue(Job::Diagnostics);
        }

        #[unsafe(method(quit:))]
        fn quit(&self, _sender: Option<&AnyObject>) {
            quit_dialog(self.mtm());
        }

        /// NSMenuDelegate: read the state again whenever the menu opens.
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: Option<&AnyObject>) {
            enqueue(Job::Refresh { full: false });
        }
    }
);

struct Ui {
    item: Retained<NSStatusItem>,
    menu: Retained<NSMenu>,
    controller: Retained<MenuController>,
    shown: Option<MenuView>,
    welcomed: bool,
}

type Deferred = Box<dyn FnOnce(MainThreadMarker)>;

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
    /// A modal alert or panel is open: other dialogs wait for it.
    static MODAL: Cell<bool> = const { Cell::new(false) };
    static PENDING: RefCell<VecDeque<Deferred>> = const { RefCell::new(VecDeque::new()) };
}

/// Show a dialog now, or after the open one closes (never nested).
fn show_when_free(mtm: MainThreadMarker, dialog: impl FnOnce(MainThreadMarker) + 'static) {
    if MODAL.with(Cell::get) {
        PENDING.with(|pending| pending.borrow_mut().push_back(Box::new(dialog)));
    } else {
        dialog(mtm);
    }
}

fn drain_pending(mtm: MainThreadMarker) {
    while !MODAL.with(Cell::get) {
        let Some(next) = PENDING.with(|pending| pending.borrow_mut().pop_front()) else {
            return;
        };
        next(mtm);
    }
}

fn modal<T>(mtm: MainThreadMarker, run: impl FnOnce() -> T) -> T {
    MODAL.with(|modal| modal.set(true));
    NSApplication::sharedApplication(mtm).activate();
    let result = run();
    MODAL.with(|modal| modal.set(false));
    // Dialogs that arrived meanwhile run after this one's caller is done.
    on_main(drain_pending);
    result
}

/// A modal alert; the index of the clicked button.
fn alert(
    mtm: MainThreadMarker,
    warning: bool,
    title: &str,
    text: &str,
    buttons: &[&str],
) -> Option<usize> {
    modal(mtm, || {
        let alert = NSAlert::new(mtm);
        alert.setAlertStyle(if warning {
            ALERT_STYLE_WARNING
        } else {
            ALERT_STYLE_INFORMATIONAL
        });
        alert.setMessageText(&NSString::from_str(title));
        alert.setInformativeText(&NSString::from_str(text));
        for button in buttons {
            let _ = alert.addButtonWithTitle(&NSString::from_str(button));
        }
        let index = alert.runModal() - ALERT_FIRST_BUTTON;
        usize::try_from(index)
            .ok()
            .filter(|index| *index < buttons.len())
    })
}

fn notify(mtm: MainThreadMarker, warning: bool, title: &str, text: &str) {
    let _ = alert(mtm, warning, title, text, &["OK"]);
}

fn cancel() -> &'static str {
    tr("Cancel", "Отменить")
}

/// The folder picker: one existing folder, or `None`.
fn choose_folder(mtm: MainThreadMarker) -> Option<PathBuf> {
    modal(mtm, || {
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseFiles(false);
        panel.setCanChooseDirectories(true);
        panel.setAllowsMultipleSelection(false);
        panel.setCanCreateDirectories(false);
        panel.setMessage(Some(&NSString::from_str(tr(
            "Choose the AEGIS folder you received. It contains the folders bundle and identity.",
            "Выберите полученную папку AEGIS. В ней лежат папки bundle и identity.",
        ))));
        panel.setPrompt(Some(&NSString::from_str(tr("Import", "Импортировать"))));
        if panel.runModal() != MODAL_RESPONSE_OK {
            return None;
        }
        let path = panel.URL()?.path()?.to_string();
        Some(PathBuf::from(path)).filter(|path| path.is_absolute())
    })
}

/// v45: the invitation file picker: one `.aegis-invite` file, or `None`.
fn choose_invitation(mtm: MainThreadMarker) -> Option<PathBuf> {
    modal(mtm, || {
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseFiles(true);
        panel.setCanChooseDirectories(false);
        panel.setAllowsMultipleSelection(false);
        panel.setCanCreateDirectories(false);
        let types = NSArray::from_retained_slice(&[NSString::from_str(invite_package::EXTENSION)]);
        panel.setAllowedFileTypes(Some(&types));
        panel.setMessage(Some(&NSString::from_str(tr(
            "Choose the invitation file you received. Its name ends in .aegis-invite.",
            "Выберите полученный файл приглашения. Его имя оканчивается на .aegis-invite.",
        ))));
        panel.setPrompt(Some(&NSString::from_str(tr("Join", "Присоединиться"))));
        if panel.runModal() != MODAL_RESPONSE_OK {
            return None;
        }
        let path = panel.URL()?.path()?.to_string();
        Some(PathBuf::from(path)).filter(|path| path.is_absolute())
    })
}

fn snapshot() -> (MenuView, Observation) {
    let guard = state();
    (derive(&guard.obs, now()), guard.obs.clone())
}

fn render(mtm: MainThreadMarker) {
    let view = snapshot().0;
    let mut welcome = false;
    let drawn = UI.with(|ui| {
        let Ok(mut ui) = ui.try_borrow_mut() else {
            return false;
        };
        let Some(ui) = ui.as_mut() else {
            return true;
        };
        if ui.shown.as_ref() != Some(&view) {
            draw_icon(mtm, ui, &view);
            draw_menu(mtm, ui, &view);
            ui.shown = Some(view.clone());
        }
        if !ui.welcomed && view.primary != Primary::Checking {
            ui.welcomed = true;
            welcome = matches!(
                view.primary,
                Primary::Setup(_) | Primary::NeedsApproval | Primary::MoveToApplications
            );
        }
        true
    });
    if !drawn {
        render_later();
    }
    if welcome {
        show_when_free(mtm, welcome_dialog);
    }
}

fn draw_icon(mtm: MainThreadMarker, ui: &Ui, view: &MenuView) {
    let Some(button) = ui.item.button() else {
        return;
    };
    let label = NSString::from_str(&format!("AEGIS: {}", view.title));
    let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(
        mtm,
        &NSString::from_str(view.symbol),
        Some(&label),
    );
    match image {
        Some(image) => {
            image.setTemplate(true);
            button.setImage(Some(&image));
            button.setTitle(&NSString::from_str(""));
            button.setImagePosition(IMAGE_ONLY);
        }
        None => {
            button.setImage(None);
            button.setTitle(&NSString::from_str("AEGIS"));
        }
    }
    button.setToolTip(Some(&label));
}

fn info_item(mtm: MainThreadMarker, menu: &NSMenu, title: &str) {
    let item = NSMenuItem::initWithTitle_action_keyEquivalent(
        NSMenuItem::alloc(mtm),
        &NSString::from_str(title),
        None,
        &NSString::from_str(""),
    );
    item.setEnabled(false);
    menu.addItem(&item);
}

fn action_item(
    mtm: MainThreadMarker,
    menu: &NSMenu,
    target: &AnyObject,
    title: &str,
    action: Sel,
    enabled: bool,
    key: &str,
) {
    let item = NSMenuItem::initWithTitle_action_keyEquivalent(
        NSMenuItem::alloc(mtm),
        &NSString::from_str(title),
        Some(action),
        &NSString::from_str(key),
    );
    item.setTarget(Some(target));
    item.setEnabled(enabled);
    menu.addItem(&item);
}

fn setup_title(step: SetupStep, primary: Primary) -> &'static str {
    match (step, primary) {
        (_, Primary::NeedsApproval) => tr(
            "Finish Setup After Approval…",
            "Завершить настройку после разрешения…",
        ),
        (SetupStep::UpdateExtension, _) => tr("Finish Update…", "Завершить обновление…"),
        (SetupStep::ActivateExtension, _) => tr("Set Up AEGIS…", "Настроить AEGIS…"),
        (SetupStep::ImportIdentity, _) => {
            tr("Join with Invitation…", "Присоединиться по приглашению…")
        }
        _ => tr("Continue Setup…", "Продолжить настройку…"),
    }
}

fn draw_menu(mtm: MainThreadMarker, ui: &Ui, view: &MenuView) {
    let menu = &ui.menu;
    let target: &AnyObject = &ui.controller;
    menu.removeAllItems();
    info_item(mtm, menu, &format!("AEGIS: {}", view.title));
    for detail in &view.details {
        info_item(mtm, menu, detail);
    }
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let actions = view.actions;
    let item = |title: &str, action: Sel, enabled: bool| {
        action_item(mtm, menu, target, title, action, enabled, "");
    };
    if actions.connect {
        item(tr("Connect", "Подключить"), sel!(connect:), true);
    }
    if actions.disconnect {
        item(tr("Disconnect", "Отключить"), sel!(disconnect:), true);
    }
    if actions.force_stop {
        item(
            tr("Force Stop Tunnel…", "Принудительно остановить туннель…"),
            sel!(forceStop:),
            true,
        );
    }
    if let Some(step) = actions.setup {
        item(setup_title(step, view.primary), sel!(setup:), true);
    }
    if actions.open_settings {
        item(
            tr("Open System Settings…", "Открыть Системные настройки…"),
            sel!(openSettings:),
            true,
        );
    }
    if actions.enable_guard && actions.setup != Some(SetupStep::TurnOnLeakGuard) {
        item(
            tr("Turn On Leak Guard…", "Включить защиту от утечек…"),
            sel!(enableGuard:),
            true,
        );
    }
    // v45: joining is the first-run path; it stays at the top while there
    // is no identity (or it can no longer connect), unless the setup item
    // already offers it.
    let join_on_top = actions.join_prominent && actions.setup != Some(SetupStep::ImportIdentity);
    if join_on_top {
        item(
            tr("Join with Invitation…", "Присоединиться по приглашению…"),
            sel!(joinInvitation:),
            actions.join,
        );
    }
    let more = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str(tr("More", "Ещё")));
    more.setAutoenablesItems(false);
    if !actions.join_prominent {
        action_item(
            mtm,
            &more,
            target,
            tr(
                "Join with Another Invitation…",
                "Присоединиться по другому приглашению…",
            ),
            sel!(joinInvitation:),
            actions.join,
            "",
        );
    }
    action_item(
        mtm,
        &more,
        target,
        tr(
            "Import Invitation Folder…",
            "Импортировать папку приглашения…",
        ),
        sel!(importInvitation:),
        actions.import,
        "",
    );
    let more_item = NSMenuItem::initWithTitle_action_keyEquivalent(
        NSMenuItem::alloc(mtm),
        &NSString::from_str(tr("More", "Ещё")),
        None,
        &NSString::from_str(""),
    );
    more_item.setSubmenu(Some(&more));
    menu.addItem(&more_item);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    item(
        tr("Copy Diagnostics", "Скопировать диагностику"),
        sel!(copyDiagnostics:),
        true,
    );
    info_item(mtm, menu, &format!("AEGIS {}", info().version));
    action_item(
        mtm,
        menu,
        target,
        tr("Quit AEGIS", "Завершить AEGIS"),
        sel!(quit:),
        true,
        "q",
    );
}

// ---------------------------------------------------------------------------
// Dialogs.

fn move_text() -> &'static str {
    tr(
        "AEGIS works only from the Applications folder. Quit AEGIS, drag AEGIS into Applications in Finder, and open it from there.",
        "AEGIS работает только из папки «Программы». Завершите AEGIS, перетащите AEGIS в «Программы» в Finder и откройте его оттуда.",
    )
}

fn move_title() -> &'static str {
    tr(
        "Move AEGIS to Applications",
        "Переместите AEGIS в «Программы»",
    )
}

fn welcome_dialog(mtm: MainThreadMarker) {
    let (view, _) = snapshot();
    if view.primary == Primary::MoveToApplications {
        notify(mtm, true, move_title(), move_text());
        return;
    }
    let choice = alert(
        mtm,
        false,
        tr("Welcome to AEGIS", "Добро пожаловать в AEGIS"),
        tr(
            "AEGIS lives in the menu bar: look for the shield icon at the top of the screen.\n\nSetting it up takes four steps: turning on the AEGIS network extension, turning on the leak guard, joining with the invitation file you received and adding the VPN configuration. macOS asks you to approve some of them.",
            "AEGIS живёт в строке меню: ищите значок щита вверху экрана.\n\nНастройка займёт четыре шага: включить сетевое расширение AEGIS, включить защиту от утечек, присоединиться по полученному файлу приглашения и добавить конфигурацию VPN. Некоторые шаги macOS попросит подтвердить.",
        ),
        &[tr("Set Up Now", "Настроить сейчас"), tr("Later", "Позже")],
    );
    if choice == Some(0) {
        run_setup(mtm);
    }
}

fn approval_text() -> &'static str {
    if info().macos_major >= 15 {
        tr(
            "macOS needs your permission to turn on the AEGIS network extension.\n\nIn System Settings, open General > Login Items & Extensions, find Network Extensions (click the ⓘ button next to it) and switch AEGIS on. You may need your password.\n\nAEGIS waits up to two minutes. If it stops waiting, choose Finish Setup again.",
            "macOS нужно ваше разрешение, чтобы включить сетевое расширение AEGIS.\n\nВ Системных настройках откройте «Основные» > «Объекты входа и расширения», найдите «Сетевые расширения» (нажмите кнопку ⓘ рядом) и включите AEGIS. Может понадобиться пароль.\n\nAEGIS ждёт до двух минут. Если ожидание закончится, снова выберите «Завершить настройку…».",
        )
    } else {
        tr(
            "macOS needs your permission to turn on the AEGIS network extension.\n\nIn System Settings, open Privacy & Security, scroll down to Security and click Allow next to the message about AEGIS. You may need your password.\n\nAEGIS waits up to two minutes. If it stops waiting, choose Finish Setup again.",
            "macOS нужно ваше разрешение, чтобы включить сетевое расширение AEGIS.\n\nВ Системных настройках откройте «Конфиденциальность и безопасность», прокрутите до раздела «Безопасность» и нажмите «Разрешить» рядом с сообщением об AEGIS. Может понадобиться пароль.\n\nAEGIS ждёт до двух минут. Если ожидание закончится, снова выберите «Завершить настройку…».",
        )
    }
}

fn open_system_settings(mtm: MainThreadMarker) {
    let pane = if info().macos_major >= 15 {
        "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
    } else {
        "x-apple.systempreferences:com.apple.preference.security"
    };
    if let Some(url) = NSURL::URLWithString(&NSString::from_str(pane)) {
        let _ = NSWorkspace::sharedWorkspace(mtm).openURL(&url);
    }
}

/// Explain the System Settings switch; `check_again` also asks macOS
/// again (a request that waited 120 s was withdrawn when it ended).
fn approval_help(mtm: MainThreadMarker, check_again: bool) {
    let open = tr("Open System Settings", "Открыть Системные настройки");
    let buttons: [&str; 2] = if check_again {
        [open, cancel()]
    } else {
        [open, tr("Not Now", "Не сейчас")]
    };
    if alert(
        mtm,
        false,
        tr(
            "Allow AEGIS in System Settings",
            "Разрешите AEGIS в Системных настройках",
        ),
        approval_text(),
        &buttons,
    ) == Some(0)
    {
        open_system_settings(mtm);
        if check_again {
            enqueue(Job::Activate { wizard: true });
        }
    }
}

fn run_setup(mtm: MainThreadMarker) {
    let (view, _) = snapshot();
    if view.primary == Primary::MoveToApplications {
        notify(mtm, true, move_title(), move_text());
        return;
    }
    let continue_ = tr("Continue", "Продолжить");
    match view.actions.setup {
        None if view.actions.connect => notify(
            mtm,
            false,
            tr("AEGIS is set up", "AEGIS настроен"),
            tr(
                "Choose Connect in the AEGIS menu to start the tunnel.",
                "Выберите «Подключить» в меню AEGIS, чтобы запустить туннель.",
            ),
        ),
        None => {}
        Some(SetupStep::ActivateExtension | SetupStep::UpdateExtension)
            if view.primary == Primary::NeedsApproval =>
        {
            approval_help(mtm, true)
        }
        Some(step @ (SetupStep::ActivateExtension | SetupStep::UpdateExtension)) => {
            let (title, text) = if step == SetupStep::UpdateExtension {
                (
                    tr("Finish updating AEGIS", "Завершите обновление AEGIS"),
                    tr(
                        "AEGIS replaces its network extension with the new version. This takes a few seconds and usually needs no approval.",
                        "AEGIS заменит своё сетевое расширение новой версией. Это займёт несколько секунд и обычно не требует разрешения.",
                    ),
                )
            } else {
                (
                    tr(
                        "Turn on the AEGIS network extension",
                        "Включите сетевое расширение AEGIS",
                    ),
                    tr(
                        "AEGIS sends your traffic through its network extension. macOS will ask you to allow it in System Settings; AEGIS shows you where.",
                        "AEGIS направляет трафик через своё сетевое расширение. macOS попросит разрешить его в Системных настройках; AEGIS покажет, где.",
                    ),
                )
            };
            if alert(mtm, false, title, text, &[continue_, cancel()]) == Some(0) {
                enqueue(Job::Activate { wizard: true });
            }
        }
        Some(SetupStep::TurnOnLeakGuard) => confirm_enable_guard(mtm, true),
        Some(SetupStep::ImportIdentity) => join_dialog(mtm, true),
        Some(SetupStep::AddVpnConfiguration) => {
            let choice = alert(
                mtm,
                false,
                tr(
                    "Add the AEGIS VPN configuration",
                    "Добавьте конфигурацию VPN AEGIS",
                ),
                tr(
                    "macOS will ask whether AEGIS may add VPN configurations: click Allow (you may need your password or Touch ID). Answer within 30 seconds.",
                    "macOS спросит, может ли AEGIS добавлять конфигурации VPN: нажмите «Разрешить» (может понадобиться пароль или Touch ID). Ответьте в течение 30 секунд.",
                ),
                &[continue_, cancel()],
            );
            if choice == Some(0) {
                enqueue(Job::AddVpn { wizard: true });
            }
        }
    }
}

fn confirm_enable_guard(mtm: MainThreadMarker, wizard: bool) {
    let choice = alert(
        mtm,
        false,
        tr("Turn on the leak guard", "Включите защиту от утечек"),
        tr(
            "While the tunnel runs, the leak guard stops apps from sending traffic outside it. macOS will ask whether AEGIS may filter network content: click Allow.",
            "Пока работает туннель, защита от утечек не даёт программам отправлять трафик мимо него. macOS спросит, может ли AEGIS фильтровать сетевой контент: нажмите «Разрешить».",
        ),
        &[tr("Continue", "Продолжить"), cancel()],
    );
    if choice == Some(0) {
        enqueue(Job::EnableGuard { wizard });
    }
}

fn confirm_force_stop(mtm: MainThreadMarker) {
    let choice = alert(
        mtm,
        true,
        tr("Force stop the tunnel?", "Принудительно остановить туннель?"),
        tr(
            "AEGIS asks macOS to stop every AEGIS VPN connection. The Mac then uses its normal network, without the tunnel. The leak guard stays on.",
            "AEGIS попросит macOS остановить все VPN-подключения AEGIS. После этого Mac будет работать через обычную сеть, без туннеля. Защита от утечек останется включённой.",
        ),
        &[tr("Stop Tunnel", "Остановить туннель"), cancel()],
    );
    if choice == Some(0) {
        enqueue(Job::ForceStop);
    }
}

fn disconnect_first(mtm: MainThreadMarker) {
    notify(
        mtm,
        false,
        tr("Disconnect first", "Сначала отключитесь"),
        tr(
            "AEGIS changes its identity only while the tunnel is off. Choose Disconnect, then try again.",
            "AEGIS меняет удостоверение только при выключенном туннеле. Выберите «Отключить» и повторите.",
        ),
    );
}

fn import_dialog(mtm: MainThreadMarker, wizard: bool) {
    let (_, obs) = snapshot();
    if !menu_flow::import_allowed(&obs) {
        disconnect_first(mtm);
        return;
    }
    let choice = alert(
        mtm,
        false,
        tr("Import an invitation folder", "Импорт папки приглашения"),
        tr(
            "Choose the AEGIS folder you received from the person who invited you. It contains two folders, bundle and identity; do not change anything inside it.\n\nmacOS then asks for an administrator's name and password: AEGIS needs them to install your identity.",
            "Выберите папку AEGIS, полученную от пригласившего. В ней две папки, bundle и identity; ничего в ней не меняйте.\n\nЗатем macOS попросит имя и пароль администратора: они нужны AEGIS, чтобы установить ваше удостоверение.",
        ),
        &[tr("Choose Folder…", "Выбрать папку…"), cancel()],
    );
    if choice != Some(0) {
        return;
    }
    let Some(dir) = choose_folder(mtm) else {
        return;
    };
    let remove_source = match alert(
        mtm,
        false,
        tr(
            "Remove the folder after importing?",
            "Удалить папку после импорта?",
        ),
        tr(
            "The folder holds your private key. After a successful import AEGIS can remove it from this Mac, after checking that nothing in it changed. Keep it if you may need to set up AEGIS again on this Mac.",
            "В папке лежит ваш закрытый ключ. После успешного импорта AEGIS может удалить её с этого Mac, проверив, что в ней ничего не изменилось. Оставьте её, если вам может понадобиться снова настроить AEGIS на этом Mac.",
        ),
        &[
            tr("Import and Keep Folder", "Импортировать и оставить папку"),
            tr("Import and Remove Folder", "Импортировать и удалить папку"),
            cancel(),
        ],
    ) {
        Some(0) => false,
        Some(1) => true,
        _ => return,
    };
    enqueue(Job::Import {
        dir,
        remove_source,
        wizard,
    });
}

/// v45: join with one invitation file: choose it, copy it into the private
/// inbox, confirm replacing a working identity, then run `--enroll`.
fn join_dialog(mtm: MainThreadMarker, wizard: bool) {
    let (_, obs) = snapshot();
    if !menu_flow::join_allowed(&obs) {
        disconnect_first(mtm);
        return;
    }
    let choice = alert(
        mtm,
        false,
        tr("Join with your invitation", "Присоединение по приглашению"),
        tr(
            "Choose the invitation file you received from the person who invited you (its name ends in .aegis-invite).\n\nAEGIS then creates this Mac's key, contacts its server and asks for an administrator password to install your identity. It takes under a minute.",
            "Выберите файл приглашения, полученный от пригласившего (его имя оканчивается на .aegis-invite).\n\nЗатем AEGIS создаст ключ этого Mac, свяжется со своим сервером и попросит пароль администратора, чтобы установить ваше удостоверение. Это займёт меньше минуты.",
        ),
        &[tr("Choose File…", "Выбрать файл…"), cancel()],
    );
    if choice != Some(0) {
        return;
    }
    let Some(original) = choose_invitation(mtm) else {
        return;
    };
    let Some(inbox) = info().inbox.clone() else {
        notify(
            mtm,
            true,
            tr("Joining did not start", "Присоединение не началось"),
            &explain::join(Some(45), None),
        );
        return;
    };
    let (copy, source) = match invite_package::copy_to_inbox(&original, &inbox) {
        Ok(copied) => copied,
        Err(code) => {
            notify(
                mtm,
                true,
                tr("This file cannot be used", "Этот файл нельзя использовать"),
                &explain::with_code(&explain::invitation_file(Some(code)), Some(code)),
            );
            return;
        }
    };
    let now = now();
    let (_, obs) = snapshot();
    if !obs.identity_replaceable(now) {
        let replace = alert(
            mtm,
            true,
            tr(
                "Replace this Mac's AEGIS identity?",
                "Заменить удостоверение AEGIS на этом Mac?",
            ),
            tr(
                "This Mac already has an AEGIS identity that may still work. Joining with this invitation replaces it. Continue only if the person who invited you asked you to.",
                "На этом Mac уже есть удостоверение AEGIS, которое может ещё работать. Присоединение по этому приглашению заменит его. Продолжайте, только если вас об этом попросил пригласивший.",
            ),
            &[tr("Replace", "Заменить"), cancel()],
        );
        if replace != Some(0) {
            invite_package::discard_inbox_copy(&copy, &inbox);
            return;
        }
    }
    enqueue(Job::Join {
        copy,
        original,
        source,
        replace_identity: obs.identity_present != Some(false),
        wizard,
    });
}

/// v45: the end of a join: the result, then the offer to delete the chosen
/// file (its invitation is spent), then the rest of the setup.
fn joined(
    mtm: MainThreadMarker,
    wizard: bool,
    outcome: &Outcome,
    original: &std::path::Path,
    source: &PackageSource,
) {
    if !outcome.ok {
        notify(
            mtm,
            true,
            tr("Joining did not finish", "Присоединение не завершено"),
            &outcome.message,
        );
        return;
    }
    let delete = alert(
        mtm,
        false,
        tr("You joined AEGIS", "Вы присоединились к AEGIS"),
        &format!(
            "{}\n\n{}",
            outcome.message,
            tr(
                "The invitation file cannot be used again. Delete it from this Mac?",
                "Файл приглашения больше нельзя использовать. Удалить его с этого Mac?",
            )
        ),
        &[
            tr("Delete File", "Удалить файл"),
            tr("Keep File", "Оставить файл"),
        ],
    );
    if delete == Some(0) && invite_package::remove_package(original, source).is_err() {
        notify(
            mtm,
            false,
            tr("The file was kept", "Файл сохранён"),
            tr(
                "AEGIS could not delete the invitation file because it changed or moved. Move it to the Trash yourself.",
                "AEGIS не удалось удалить файл приглашения: он изменился или был перемещён. Переместите его в Корзину сами.",
            ),
        );
    }
    if wizard {
        run_setup(mtm);
    }
}

fn finished(mtm: MainThreadMarker, kind: Kind, wizard: bool, outcome: &Outcome) {
    if !outcome.ok {
        if kind == Kind::Activate && outcome.approval_needed {
            approval_help(mtm, true);
            return;
        }
        let title = match kind {
            Kind::Connect => tr("AEGIS could not connect", "AEGIS не удалось подключиться"),
            Kind::Disconnect => tr("AEGIS could not disconnect", "AEGIS не удалось отключиться"),
            Kind::ForceStop => tr(
                "AEGIS could not stop the tunnel",
                "AEGIS не удалось остановить туннель",
            ),
            Kind::EnableGuard => tr("The leak guard is not on", "Защита от утечек не включена"),
            Kind::Activate => tr(
                "The AEGIS network extension is not on",
                "Сетевое расширение AEGIS не включено",
            ),
            Kind::Import => tr(
                "The invitation was not imported",
                "Приглашение не импортировано",
            ),
            Kind::AddVpn => tr(
                "The VPN configuration was not added",
                "Конфигурация VPN не добавлена",
            ),
        };
        notify(mtm, true, title, &outcome.message);
        return;
    }
    match kind {
        Kind::Connect | Kind::Disconnect | Kind::ForceStop => {}
        _ if wizard => run_setup(mtm),
        Kind::Import => notify(
            mtm,
            false,
            tr("Invitation imported", "Приглашение импортировано"),
            &outcome.message,
        ),
        Kind::Activate => {
            if outcome.message.contains("restart") || outcome.message.contains("перезагрузки")
            {
                notify(
                    mtm,
                    false,
                    tr("Restart needed", "Нужна перезагрузка"),
                    &outcome.message,
                );
            }
        }
        Kind::EnableGuard | Kind::AddVpn => {}
    }
}

fn copy_report(mtm: MainThreadMarker, report: &str) {
    let pasteboard = NSPasteboard::generalPasteboard(mtm);
    let _ = pasteboard.clearContents();
    let copied = pasteboard.setString_forType(
        &NSString::from_str(report),
        &NSString::from_str(PASTEBOARD_TYPE_STRING),
    );
    if copied {
        notify(
            mtm,
            false,
            tr("Diagnostics copied", "Диагностика скопирована"),
            tr(
                "Paste them into a message to the person who invited you. They hold states and error codes only: no keys, invitation, user name or full IP address.",
                "Вставьте её в сообщение тому, кто вас пригласил. В ней только состояния и коды ошибок: никаких ключей, приглашения, имени пользователя или полного IP-адреса.",
            ),
        );
    } else {
        notify(
            mtm,
            true,
            tr("Diagnostics not copied", "Диагностика не скопирована"),
            tr(
                "macOS refused the clipboard. Try again.",
                "macOS не дала доступ к буферу обмена. Повторите попытку.",
            ),
        );
    }
}

fn terminate(mtm: MainThreadMarker) {
    NSApplication::sharedApplication(mtm).terminate(None);
}

fn quit_dialog(mtm: MainThreadMarker) {
    let (_, obs) = snapshot();
    if let Some(activity) = obs.activity {
        let text = format!(
            "{} {}",
            activity.label(),
            tr(
                "It finishes in the background on its own; the tunnel and the leak guard stay as they are.",
                "Это завершится в фоне само; туннель и защита от утечек останутся как есть.",
            )
        );
        if alert(
            mtm,
            true,
            tr("AEGIS is still working", "AEGIS ещё работает"),
            &text,
            &[tr("Quit", "Завершить"), cancel()],
        ) == Some(0)
        {
            terminate(mtm);
        }
        return;
    }
    match obs.native_status() {
        Some(NativeStatus::Connected) => match alert(
            mtm,
            false,
            tr("Quit AEGIS?", "Завершить AEGIS?"),
            tr(
                "The tunnel and the leak guard keep protecting this Mac after the menu closes. To disconnect later, open AEGIS again from the Applications folder.",
                "Туннель и защита от утечек продолжат защищать этот Mac после закрытия меню. Чтобы отключиться позже, снова откройте AEGIS из папки «Программы».",
            ),
            &[
                tr("Quit and Stay Connected", "Завершить и остаться подключённым"),
                tr("Disconnect and Quit", "Отключить и завершить"),
                cancel(),
            ],
        ) {
            Some(0) => terminate(mtm),
            Some(1) => enqueue(Job::QuitAfterDisconnect),
            _ => {}
        },
        Some(status) if status.tunnel_up() => match alert(
            mtm,
            true,
            tr("The tunnel is not connected", "Туннель не подключён"),
            tr(
                "Until the tunnel connects, macOS holds your traffic so that nothing leaves outside it, and that continues after you quit. Disconnect to give the Mac its normal network back.",
                "Пока туннель не подключится, macOS задерживает трафик, чтобы ничего не ушло мимо него, и это продолжится после завершения. Отключитесь, чтобы вернуть Mac обычную сеть.",
            ),
            &[
                tr("Disconnect and Quit", "Отключить и завершить"),
                tr("Quit Anyway", "Всё равно завершить"),
                cancel(),
            ],
        ) {
            Some(0) => enqueue(Job::QuitAfterDisconnect),
            Some(1) => terminate(mtm),
            _ => {}
        },
        _ => terminate(mtm),
    }
}

fn quit_after_disconnect(mtm: MainThreadMarker, down: bool) {
    if down {
        terminate(mtm);
        return;
    }
    let choice = alert(
        mtm,
        true,
        tr(
            "AEGIS could not confirm the disconnect",
            "AEGIS не удалось подтвердить отключение",
        ),
        tr(
            "macOS has not reported the tunnel as disconnected yet. Stay open to watch it, or quit anyway.",
            "macOS ещё не сообщила об отключении туннеля. Оставьте AEGIS открытым, чтобы проследить, или всё равно завершите.",
        ),
        &[
            tr("Stay Open", "Оставить открытым"),
            tr("Quit Anyway", "Всё равно завершить"),
        ],
    );
    if choice == Some(1) {
        terminate(mtm);
    }
}

// ---------------------------------------------------------------------------
// Start.

fn app_info() -> AppInfo {
    let bundle = NSBundle::mainBundle();
    let text = |key: &str| {
        bundle
            .objectForInfoDictionaryKey(&NSString::from_str(key))
            .and_then(|value| value.downcast::<NSString>().ok())
            .map(|value| value.to_string())
    };
    let short_version = text("CFBundleShortVersionString");
    let build = text("CFBundleVersion");
    let os = NSProcessInfo::processInfo().operatingSystemVersion();
    let exe = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .unwrap_or_default();
    let inbox = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .and_then(|home| home.canonicalize().ok())
        .map(|home| home.join(invite_package::INBOX_DIR));
    AppInfo {
        version: format!(
            "{} ({})",
            short_version.as_deref().unwrap_or("unknown"),
            build.as_deref().unwrap_or("unknown")
        ),
        build,
        macos: format!(
            "{}.{}.{}",
            os.majorVersion, os.minorVersion, os.patchVersion
        ),
        macos_major: os.majorVersion,
        in_applications: menu_model::in_applications(&exe.to_string_lossy()),
        exe,
        inbox,
    }
}

/// The menu-bar app's entry point; never returns.
pub fn run() -> ! {
    // AppKit is loaded only here, so no CLI verb ever loads it.
    let appkit = unsafe { libc::dlopen(APPKIT.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
    if appkit.is_null() {
        eprintln!("menu_app_appkit_unavailable");
        std::process::exit(2);
    }
    let Some(mtm) = MainThreadMarker::new() else {
        eprintln!("main_thread_required");
        std::process::exit(2);
    };
    // v45: every menu string follows the system language from here on.
    menu_l10n::set(menu_l10n::system());
    let app_info = app_info();
    // v45: copies a quit or crash left behind still hold an unspent token.
    if let Some(inbox) = &app_info.inbox {
        invite_package::sweep_inbox(inbox);
    }
    let observation = Observation {
        in_applications: app_info.in_applications,
        app_build: app_info.build.clone(),
        ..Observation::default()
    };
    let exe = app_info.exe.clone();
    let _ = INFO.set(app_info);
    let _ = SHARED.set(Shared {
        state: Mutex::new(State {
            obs: observation,
            events: EventLog::new(60),
            jobs: VecDeque::from([Job::Refresh { full: true }]),
            last_full: None,
        }),
        wake: Condvar::new(),
    });
    let app = NSApplication::sharedApplication(mtm);
    let _ = app.setActivationPolicy(ACTIVATION_POLICY_ACCESSORY);
    let item = NSStatusBar::systemStatusBar(mtm).statusItemWithLength(VARIABLE_STATUS_ITEM_LENGTH);
    let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str("AEGIS"));
    menu.setAutoenablesItems(false);
    let controller: Retained<MenuController> =
        unsafe { msg_send![MenuController::alloc(mtm), init] };
    let delegate: &AnyObject = &controller;
    menu.setDelegate(Some(delegate));
    item.setMenu(Some(&menu));
    UI.with(|ui| {
        *ui.borrow_mut() = Some(Ui {
            item,
            menu,
            controller,
            shown: None,
            welcomed: false,
        })
    });
    render(mtm);
    if std::thread::Builder::new()
        .name("aegis-menu-worker".into())
        .spawn(move || worker(exe))
        .is_err()
    {
        eprintln!("menu_app_worker_unavailable");
        std::process::exit(2);
    }
    app.run();
    std::process::exit(0);
}
