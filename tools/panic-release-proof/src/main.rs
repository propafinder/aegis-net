//! A deliberately panicking release worker for the workspace panic policy gate.
//! This binary is never copied into a public or administrative payload.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct OwnedGuard(Arc<AtomicBool>);

impl Drop for OwnedGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn main() {
    // This is the same unwind-and-drop shape used by the production TUN worker.
    // An aborting release binary ends the process here, before the parent can
    // observe either the caught panic or the guard's rollback Drop.
    std::panic::set_hook(Box::new(|_| {}));
    let released = Arc::new(AtomicBool::new(false));
    let witness = Arc::clone(&released);
    let result = std::panic::catch_unwind(move || {
        let _owned = OwnedGuard(witness);
        panic!("intentional release-only fault fixture");
    });
    if result.is_err() && released.load(Ordering::SeqCst) {
        println!("release_panic_caught_and_guard_dropped");
    } else {
        std::process::exit(2);
    }
}
