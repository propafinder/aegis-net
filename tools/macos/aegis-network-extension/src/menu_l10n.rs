//! B-06 v45: the menu app's language. English is the base; Russian follows
//! the macOS system language (the first of the user's preferred languages,
//! which also carries a per-app language choice). The menu app sets it once
//! at start (`set(system())`); every menu string is chosen through `tr` or
//! `lang`. Host verbs keep English codes and lines; only the join's
//! administrator prompt follows the language. The diagnostics report stays
//! English: it is read by the person who invited the user.
use std::{
    cell::Cell,
    sync::atomic::{AtomicU8, Ordering},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    Ru,
}

static GLOBAL: AtomicU8 = AtomicU8::new(0);

thread_local! {
    /// Tests choose a language per thread, never the process's.
    static OVERRIDE: Cell<Option<Lang>> = const { Cell::new(None) };
}

/// The process's language (the menu app sets it once at start).
pub fn set(lang: Lang) {
    GLOBAL.store(
        match lang {
            Lang::En => 0,
            Lang::Ru => 1,
        },
        Ordering::Relaxed,
    );
}

/// The language every menu string is chosen in.
pub fn lang() -> Lang {
    OVERRIDE.with(Cell::get).unwrap_or_else(|| {
        if GLOBAL.load(Ordering::Relaxed) == 1 {
            Lang::Ru
        } else {
            Lang::En
        }
    })
}

/// `en` or `ru`, in the current language.
pub fn tr(en: &'static str, ru: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Ru => ru,
    }
}

/// The language of the user's first preferred language (`ru`, `ru-RU`,
/// `ru_RU`, any case): Russian; anything else English.
pub fn from_preferred<S: AsRef<str>>(languages: &[S]) -> Lang {
    let Some(first) = languages.first() else {
        return Lang::En;
    };
    let first = first.as_ref().trim().to_ascii_lowercase();
    let primary = first.split(['-', '_']).next().unwrap_or("");
    if primary == "ru" {
        Lang::Ru
    } else {
        Lang::En
    }
}

/// The macOS system language (`NSLocale.preferredLanguages`).
#[cfg(target_os = "macos")]
pub fn system() -> Lang {
    let languages: Vec<String> = objc2_foundation::NSLocale::preferredLanguages()
        .iter()
        .map(|language| language.to_string())
        .collect();
    from_preferred(&languages)
}

/// Run `body` with `lang` as this thread's language (tests).
#[cfg(test)]
pub(crate) fn with<T>(lang: Lang, body: impl FnOnce() -> T) -> T {
    let before = OVERRIDE.with(|cell| cell.replace(Some(lang)));
    let result = body();
    OVERRIDE.with(|cell| cell.set(before));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_follows_the_first_preferred_language_only() {
        assert_eq!(from_preferred(&["ru-RU", "en-US"]), Lang::Ru);
        assert_eq!(from_preferred(&["ru"]), Lang::Ru);
        assert_eq!(from_preferred(&["RU_ru"]), Lang::Ru);
        assert_eq!(from_preferred(&["en-RU", "ru-RU"]), Lang::En);
        assert_eq!(from_preferred(&["uk-UA"]), Lang::En);
        assert_eq!(from_preferred(&["rus"]), Lang::En);
        assert_eq!(from_preferred::<&str>(&[]), Lang::En);
    }

    #[test]
    fn a_thread_override_never_leaks() {
        assert_eq!(lang(), Lang::En);
        assert_eq!(with(Lang::Ru, || tr("Connect", "Подключить")), "Подключить");
        assert_eq!(tr("Connect", "Подключить"), "Connect");
        // The system query answers on the build host (any language).
        let _ = system();
    }
}
