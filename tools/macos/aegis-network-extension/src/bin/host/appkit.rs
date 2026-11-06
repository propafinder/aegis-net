//! v39 menu-bar app: the few AppKit classes and methods it uses, declared
//! with objc2's own `extern_class!`/`extern_methods!` (the macros
//! `objc2-app-kit` is generated with), so no crate is added and
//! `Cargo.lock` is unchanged. Classes resolve at run time
//! (`objc_getClass`); `menu_app::run` loads AppKit first, so CLI verbs never
//! load it. Every method here is called on the main thread only.
// The Rust names are AppKit's selectors, as in `objc2-app-kit`.
#![allow(non_snake_case)]

use objc2::rc::{Allocated, Retained};
use objc2::runtime::{AnyObject, NSObject, Sel};
use objc2::{extern_class, extern_methods, MainThreadMarker, MainThreadOnly};
use objc2_foundation::{NSArray, NSString, NSURL};

pub type CGFloat = f64;

/// `NSVariableStatusItemLength`.
pub const VARIABLE_STATUS_ITEM_LENGTH: CGFloat = -1.0;
/// `NSApplicationActivationPolicyAccessory`: no Dock icon, no app menu.
pub const ACTIVATION_POLICY_ACCESSORY: isize = 1;
/// `NSAlertFirstButtonReturn`; later buttons count up from it.
pub const ALERT_FIRST_BUTTON: isize = 1000;
/// `NSModalResponseOK`.
pub const MODAL_RESPONSE_OK: isize = 1;
/// `NSAlertStyleWarning`, `NSAlertStyleInformational`.
pub const ALERT_STYLE_WARNING: usize = 0;
pub const ALERT_STYLE_INFORMATIONAL: usize = 1;
/// `NSImageOnly`.
pub const IMAGE_ONLY: usize = 1;
/// `NSPasteboardTypeString`'s value.
pub const PASTEBOARD_TYPE_STRING: &str = "public.utf8-plain-text";

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSResponder"]
    pub struct NSResponder;
);

extern_class!(
    #[unsafe(super(NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSApplication"]
    pub struct NSApplication;
);

impl NSApplication {
    extern_methods!(
        #[unsafe(method(sharedApplication))]
        pub fn sharedApplication(mtm: MainThreadMarker) -> Retained<NSApplication>;

        #[unsafe(method(setActivationPolicy:))]
        pub fn setActivationPolicy(&self, policy: isize) -> bool;

        #[unsafe(method(activate))]
        pub fn activate(&self);

        #[unsafe(method(run))]
        pub fn run(&self);

        #[unsafe(method(terminate:))]
        pub fn terminate(&self, sender: Option<&AnyObject>);
    );
}

extern_class!(
    #[unsafe(super(NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSView"]
    pub struct NSView;
);

impl NSView {
    extern_methods!(
        #[unsafe(method(setToolTip:))]
        pub fn setToolTip(&self, tip: Option<&NSString>);
    );
}

extern_class!(
    #[unsafe(super(NSView, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSControl"]
    pub struct NSControl;
);

extern_class!(
    #[unsafe(super(NSControl, NSView, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSButton"]
    pub struct NSButton;
);

impl NSButton {
    extern_methods!(
        #[unsafe(method(setTitle:))]
        pub fn setTitle(&self, title: &NSString);

        #[unsafe(method(setImage:))]
        pub fn setImage(&self, image: Option<&NSImage>);

        #[unsafe(method(setImagePosition:))]
        pub fn setImagePosition(&self, position: usize);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSImage"]
    pub struct NSImage;
);

impl NSImage {
    extern_methods!(
        #[unsafe(method(imageWithSystemSymbolName:accessibilityDescription:))]
        pub fn imageWithSystemSymbolName_accessibilityDescription(
            mtm: MainThreadMarker,
            name: &NSString,
            description: Option<&NSString>,
        ) -> Option<Retained<NSImage>>;

        #[unsafe(method(setTemplate:))]
        pub fn setTemplate(&self, template: bool);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSStatusBar"]
    pub struct NSStatusBar;
);

impl NSStatusBar {
    extern_methods!(
        #[unsafe(method(systemStatusBar))]
        pub fn systemStatusBar(mtm: MainThreadMarker) -> Retained<NSStatusBar>;

        #[unsafe(method(statusItemWithLength:))]
        pub fn statusItemWithLength(&self, length: CGFloat) -> Retained<NSStatusItem>;
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSStatusItem"]
    pub struct NSStatusItem;
);

impl NSStatusItem {
    extern_methods!(
        /// The status item's `NSStatusBarButton` (an `NSButton`).
        #[unsafe(method(button))]
        pub fn button(&self) -> Option<Retained<NSButton>>;

        #[unsafe(method(setMenu:))]
        pub fn setMenu(&self, menu: Option<&NSMenu>);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSMenu"]
    pub struct NSMenu;
);

impl NSMenu {
    extern_methods!(
        #[unsafe(method(initWithTitle:))]
        pub fn initWithTitle(this: Allocated<Self>, title: &NSString) -> Retained<Self>;

        #[unsafe(method(addItem:))]
        pub fn addItem(&self, item: &NSMenuItem);

        #[unsafe(method(removeAllItems))]
        pub fn removeAllItems(&self);

        #[unsafe(method(setAutoenablesItems:))]
        pub fn setAutoenablesItems(&self, flag: bool);

        /// The delegate (`menuWillOpen:`) is held weakly by AppKit.
        #[unsafe(method(setDelegate:))]
        pub fn setDelegate(&self, delegate: Option<&AnyObject>);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSMenuItem"]
    pub struct NSMenuItem;
);

impl NSMenuItem {
    extern_methods!(
        #[unsafe(method(initWithTitle:action:keyEquivalent:))]
        pub fn initWithTitle_action_keyEquivalent(
            this: Allocated<Self>,
            title: &NSString,
            action: Option<Sel>,
            key_equivalent: &NSString,
        ) -> Retained<Self>;

        #[unsafe(method(separatorItem))]
        pub fn separatorItem(mtm: MainThreadMarker) -> Retained<NSMenuItem>;

        /// The target is held weakly by AppKit.
        #[unsafe(method(setTarget:))]
        pub fn setTarget(&self, target: Option<&AnyObject>);

        #[unsafe(method(setEnabled:))]
        pub fn setEnabled(&self, enabled: bool);

        #[unsafe(method(setToolTip:))]
        pub fn setToolTip(&self, tip: Option<&NSString>);

        /// v45: the More submenu.
        #[unsafe(method(setSubmenu:))]
        pub fn setSubmenu(&self, submenu: Option<&NSMenu>);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSAlert"]
    pub struct NSAlert;
);

impl NSAlert {
    extern_methods!(
        #[unsafe(method(new))]
        pub fn new(mtm: MainThreadMarker) -> Retained<NSAlert>;

        #[unsafe(method(setMessageText:))]
        pub fn setMessageText(&self, text: &NSString);

        #[unsafe(method(setInformativeText:))]
        pub fn setInformativeText(&self, text: &NSString);

        #[unsafe(method(setAlertStyle:))]
        pub fn setAlertStyle(&self, style: usize);

        #[unsafe(method(addButtonWithTitle:))]
        pub fn addButtonWithTitle(&self, title: &NSString) -> Retained<NSButton>;

        #[unsafe(method(runModal))]
        pub fn runModal(&self) -> isize;
    );
}

extern_class!(
    #[unsafe(super(NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSWindow"]
    pub struct NSWindow;
);

extern_class!(
    #[unsafe(super(NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSPanel"]
    pub struct NSPanel;
);

extern_class!(
    #[unsafe(super(NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSSavePanel"]
    pub struct NSSavePanel;
);

impl NSSavePanel {
    extern_methods!(
        #[unsafe(method(setMessage:))]
        pub fn setMessage(&self, message: Option<&NSString>);

        #[unsafe(method(setPrompt:))]
        pub fn setPrompt(&self, prompt: Option<&NSString>);

        #[unsafe(method(setCanCreateDirectories:))]
        pub fn setCanCreateDirectories(&self, flag: bool);

        /// v45: the invitation file filter (`aegis-invite`). Deprecated
        /// since macOS 12 in favour of content types, still honoured; the
        /// host checks the extension again.
        #[unsafe(method(setAllowedFileTypes:))]
        pub fn setAllowedFileTypes(&self, types: Option<&NSArray<NSString>>);

        #[unsafe(method(runModal))]
        pub fn runModal(&self) -> isize;

        #[unsafe(method(URL))]
        pub fn URL(&self) -> Option<Retained<NSURL>>;
    );
}

extern_class!(
    #[unsafe(super(NSSavePanel, NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSOpenPanel"]
    pub struct NSOpenPanel;
);

impl NSOpenPanel {
    extern_methods!(
        #[unsafe(method(openPanel))]
        pub fn openPanel(mtm: MainThreadMarker) -> Retained<NSOpenPanel>;

        #[unsafe(method(setCanChooseFiles:))]
        pub fn setCanChooseFiles(&self, flag: bool);

        #[unsafe(method(setCanChooseDirectories:))]
        pub fn setCanChooseDirectories(&self, flag: bool);

        #[unsafe(method(setAllowsMultipleSelection:))]
        pub fn setAllowsMultipleSelection(&self, flag: bool);
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSPasteboard"]
    pub struct NSPasteboard;
);

impl NSPasteboard {
    extern_methods!(
        #[unsafe(method(generalPasteboard))]
        pub fn generalPasteboard(mtm: MainThreadMarker) -> Retained<NSPasteboard>;

        #[unsafe(method(clearContents))]
        pub fn clearContents(&self) -> isize;

        #[unsafe(method(setString:forType:))]
        pub fn setString_forType(&self, string: &NSString, data_type: &NSString) -> bool;
    );
}

extern_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NSWorkspace"]
    pub struct NSWorkspace;
);

impl NSWorkspace {
    extern_methods!(
        #[unsafe(method(sharedWorkspace))]
        pub fn sharedWorkspace(mtm: MainThreadMarker) -> Retained<NSWorkspace>;

        #[unsafe(method(openURL:))]
        pub fn openURL(&self, url: &NSURL) -> bool;
    );
}
