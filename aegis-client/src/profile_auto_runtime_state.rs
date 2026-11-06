//! AUTO v2 state publication. Only protected Context can authorize this path.
//! The shared descriptor publisher retains the displaced original directory.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use crate::profile_auto_prepare::{OwnedTree, Role};
    use crate::profile_auto_publication::linux as fs;
    use crate::profile_auto_runtime_publication::linux::{Basis, Context, Operation};
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    #[cfg(test)]
    use zeroize::Zeroizing;
    type Result<T> = std::result::Result<T, &'static str>;
    const REFUSED: &str = "Administrative AUTO runtime state refused";

    fn captured_tree(
        raw: &OwnedTree,
        accepted: &OwnedTree,
        existing: bool,
        sealed_source: Option<&OwnedTree>,
    ) -> Result<fs::CapturedTree> {
        // Preserve the existing tree, including caches and empty directories.
        // A stock package may already have created its empty state directory;
        // Prepare can still plan one captured external state.json insertion.
        if existing {
            if raw.directories != accepted.directories {
                return Err(REFUSED);
            }
            if raw.files != accepted.files {
                let source = sealed_source.ok_or(REFUSED)?;
                let state = Path::new("state.json");
                if raw.files.contains_key(state)
                    || accepted.files.len() != raw.files.len() + 1
                    || source.files.len() != 1
                    || !source.directories.is_empty()
                    || accepted.files.get(state).ok_or(REFUSED)?.as_slice()
                        != source.files.values().next().ok_or(REFUSED)?.as_slice()
                    || raw
                        .files
                        .iter()
                        .any(|(path, bytes)| accepted.files.get(path) != Some(bytes))
                {
                    return Err(REFUSED);
                }
            }
        }
        fs::CapturedTree::new(
            accepted
                .files
                .iter()
                .map(|(p, b)| (p.clone(), b.to_vec()))
                .collect(),
            accepted.directories.clone(),
        )
    }

    struct StateGuard<'a, C: Context + ?Sized> {
        context: &'a C,
        uid: u32,
        gid: u32,
    }
    impl<C: Context + ?Sized> StateGuard<'_, C> {
        fn revalidate(&self) -> Result<()> {
            self.context.assert_old_actor_stopped()?;
            let current = self.context.runtime_identity()?;
            if (current.uid, current.gid) != (self.uid, self.gid) {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    impl<C: Context + ?Sized> fs::CaptureGuard for StateGuard<'_, C> {
        fn validate_captured_generation(
            &self,
            target: &Path,
            expected: Option<&fs::Generation>,
        ) -> Result<()> {
            self.revalidate()?;
            self.context
                .capture_guard(Role::StateTarget, Basis::SealedInitial)?
                .validate_captured_generation(target, expected)
        }
    }

    struct RollbackGuard<'a, C: Context + ?Sized> {
        context: &'a C,
    }
    impl<C: Context + ?Sized> fs::CaptureGuard for RollbackGuard<'_, C> {
        fn validate_captured_generation(
            &self,
            target: &Path,
            expected: Option<&fs::Generation>,
        ) -> Result<()> {
            self.context.assert_old_actor_stopped()?;
            self.context
                .capture_guard(Role::StateTarget, Basis::CurrentOwnReceipt)?
                .validate_captured_generation(target, expected)
        }
    }
    impl<C: Context + ?Sized> fs::OwnAbsenceChainAuthority for RollbackGuard<'_, C> {
        fn validate_original_absence_and_chain(&self, target: &Path, epoch: &str) -> Result<()> {
            self.context.assert_old_actor_stopped()?;
            self.context
                .validate_original_absence_chain(Role::StateTarget, target, epoch)
        }
    }

    pub(crate) struct RuntimeState<'a, C: Context + ?Sized> {
        context: &'a C,
    }
    impl<'a, C: Context + ?Sized> RuntimeState<'a, C> {
        pub fn new(context: &'a C) -> Self {
            Self { context }
        }
        fn target(&self) -> Result<fs::Target> {
            if unsafe { libc::geteuid() } != 0 {
                return Err(REFUSED);
            }
            self.context.ensure_sealed_parent(Role::StateTarget)?;
            let path = self.context.sealed_target(Role::StateTarget)?;
            let original = self.context.original_generation(Role::StateTarget)?;
            if original.original_source() != path || !matches!(original.kind(), 0 | 2) {
                return Err(REFUSED);
            }
            fs::Target::open(path)
        }
        pub fn commit(&self) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            let role = Role::StateTarget;
            let operation = Operation::RuntimeState;
            self.context.admit(role, operation)?;
            self.context.assert_old_actor_stopped()?;
            let identity = self.context.runtime_identity()?;
            let guard = StateGuard {
                context: self.context,
                uid: identity.uid,
                gid: identity.gid,
            };
            guard.revalidate()?;
            let target = self.target()?;
            let original = self.context.original_generation(role)?;
            let expected = match (original.kind(), self.context.guarded_initial_witness(role)?) {
                (0, Some(witness)) => Some(fs::Generation::from_guarded_witness(
                    self.context.sealed_target(role)?,
                    witness,
                    &guard,
                )?),
                (2, None) => {
                    fs::bind_captured_generation(&target, None, &guard)?;
                    None
                }
                _ => return Err(REFUSED),
            };
            if let Some(original) = &expected {
                fs::admit_supported_original_runtime_state(original)?;
            }
            let raw = self.context.raw_tree(role)?;
            let accepted = self.context.accepted_tree(role)?;
            let source = if original.kind() == 0 && raw.files != accepted.files {
                let source = self.context.original_generation(Role::StateSource)?;
                if source.kind() != 1
                    || source.original_source()
                        == self.context.sealed_target(role)?.join("state.json")
                {
                    return Err(REFUSED);
                }
                Some(self.context.raw_tree(Role::StateSource)?)
            } else {
                None
            };
            let tree = captured_tree(raw, accepted, original.kind() == 0, source)?;
            let prepared = fs::Prepared::build_policy_captured(
                target,
                expected,
                &tree,
                identity.uid,
                identity.gid,
                fs::RootMode::RuntimeState0700,
                |stage| {
                    guard.revalidate()?;
                    self.context.persist_stage(role, operation, stage)
                },
                &guard,
            )?;
            let actual = prepared.publish_captured(
                |intent| {
                    guard.revalidate()?;
                    self.context.persist_intent(role, operation, intent)
                },
                &guard,
            )?;
            guard.revalidate()?;
            self.context
                .commit_actual_receipt(role, operation, &actual)?;
            self.verify_before_activation()
        }
        fn current(&self) -> Result<(fs::Target, fs::PublicationReceipt)> {
            self.context
                .admit(Role::StateTarget, Operation::ReadPublished)?;
            let target = self.target()?;
            let admitted = self
                .context
                .authenticated_current_receipt(Role::StateTarget)?;
            let receipt = fs::reopen_own_receipt(&target, &admitted)?;
            Ok((target, receipt))
        }
        pub fn verify_before_activation(&self) -> Result<()> {
            self.context.assert_old_actor_stopped()?;
            let identity = self.context.runtime_identity()?;
            let (target, receipt) = self.current()?;
            fs::verify_runtime_state_policy(&target, &receipt, identity.uid, identity.gid)?;
            let expected = self.context.accepted_tree(Role::StateTarget)?;
            let names: BTreeSet<PathBuf> = expected.files.keys().cloned().collect();
            if fs::current_leaf_names(&target, &receipt)? != names {
                return Err(REFUSED);
            }
            let mut directories = expected.directories.clone();
            for path in expected.files.keys() {
                let mut ancestor = path.parent();
                while let Some(parent) = ancestor {
                    if parent.as_os_str().is_empty() {
                        break;
                    }
                    directories.insert(parent.to_path_buf());
                    ancestor = parent.parent();
                }
            }
            if fs::current_directory_names(&target, &receipt)? != directories {
                return Err(REFUSED);
            }
            for (path, bytes) in &expected.files {
                if fs::read_current_leaf(&target, &receipt, path)?.as_slice() != bytes.as_slice() {
                    return Err(REFUSED);
                }
            }
            fs::revalidate_current_receipt(&target, &receipt)?;
            self.context.assert_old_actor_stopped()?;
            let after = self.context.runtime_identity()?;
            if (after.uid, after.gid) != (identity.uid, identity.gid) {
                return Err(REFUSED);
            }
            Ok(())
        }
        /// Independent rollback uses a fresh phase's held stopped-unit proof,
        /// not the publication worker's expired observation. Retain both trees.
        pub fn rollback(&self) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            let role = Role::StateTarget;
            self.context.admit(role, Operation::Rollback)?;
            self.context.assert_old_actor_stopped()?;
            let (target, current) = self.current()?;
            let guard = RollbackGuard {
                context: self.context,
            };
            match self.context.original_generation(role)?.kind() {
                2 => {
                    let retired = fs::restore_original_absence_after_own_chain(
                        &target,
                        &current,
                        &guard,
                        |intent| {
                            self.context.assert_old_actor_stopped()?;
                            self.context.persist_withdrawal_intent(role, intent)
                        },
                    )?;
                    self.context.assert_old_actor_stopped()?;
                    self.context.commit_withdrawal_receipt(role, &retired)
                }
                0 => {
                    let restored = fs::restore_retained_original_tree(
                        target,
                        &current,
                        |intent| {
                            self.context.assert_old_actor_stopped()?;
                            self.context
                                .persist_intent(role, Operation::Rollback, intent)
                        },
                        &guard,
                    )?;
                    self.context.assert_old_actor_stopped()?;
                    self.context
                        .commit_actual_receipt(role, Operation::Rollback, &restored)
                }
                _ => Err(REFUSED),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeMap;
        fn tree() -> OwnedTree {
            OwnedTree {
                files: BTreeMap::from([
                    (
                        PathBuf::from("state.json"),
                        Zeroizing::new(b"fixture-state".to_vec()),
                    ),
                    (PathBuf::from("cache/item"), Zeroizing::new(vec![0, 1, 255])),
                ]),
                directories: BTreeSet::from([PathBuf::from("cache"), PathBuf::from("empty")]),
            }
        }
        #[test]
        fn existing_full_tree_including_cache_and_empty_directory_is_admitted() {
            assert!(captured_tree(&tree(), &tree(), true, None).is_ok());
        }
        #[test]
        fn existing_state_bytes_membership_and_empty_directory_changes_refuse() {
            let original = tree();
            let mut changed = tree();
            changed
                .files
                .get_mut(Path::new("cache/item"))
                .unwrap()
                .push(2);
            assert!(captured_tree(&original, &changed, true, None).is_err());
            let mut changed = tree();
            changed.files.remove(Path::new("cache/item"));
            assert!(captured_tree(&original, &changed, true, None).is_err());
            let mut changed = tree();
            changed.directories.remove(Path::new("empty"));
            assert!(captured_tree(&original, &changed, true, None).is_err());
        }
        #[test]
        fn absent_target_can_receive_sealed_prior_state_and_empty_target_is_admitted() {
            let empty = OwnedTree {
                files: BTreeMap::new(),
                directories: BTreeSet::new(),
            };
            assert!(captured_tree(&empty, &tree(), false, None).is_ok());
            assert!(captured_tree(&empty, &empty, false, None).is_ok());
        }
        fn empty_tree() -> OwnedTree {
            OwnedTree {
                files: BTreeMap::new(),
                directories: BTreeSet::new(),
            }
        }
        fn transferred_state() -> OwnedTree {
            OwnedTree {
                files: BTreeMap::from([(
                    PathBuf::from("state.json"),
                    Zeroizing::new(b"captured-external-state".to_vec()),
                )]),
                directories: BTreeSet::new(),
            }
        }
        #[test]
        fn stock_existing_empty_directory_accepts_captured_external_state() {
            assert!(captured_tree(
                &empty_tree(),
                &transferred_state(),
                true,
                Some(&transferred_state()),
            )
            .is_ok());
        }
        #[test]
        fn transfer_preserves_existing_caches_and_empty_directories() {
            let mut raw = tree();
            raw.files.remove(Path::new("state.json"));
            let mut accepted = tree();
            accepted.files.insert(
                PathBuf::from("state.json"),
                transferred_state()
                    .files
                    .remove(Path::new("state.json"))
                    .unwrap(),
            );
            assert!(captured_tree(&raw, &accepted, true, Some(&transferred_state())).is_ok());
            accepted
                .files
                .get_mut(Path::new("cache/item"))
                .unwrap()
                .push(3);
            assert!(captured_tree(&raw, &accepted, true, Some(&transferred_state())).is_err());
        }
        #[test]
        fn transfer_requires_exact_single_captured_source() {
            let raw = empty_tree();
            let accepted = transferred_state();
            assert!(captured_tree(&raw, &accepted, true, None).is_err());
            let mut source = transferred_state();
            source
                .files
                .get_mut(Path::new("state.json"))
                .unwrap()
                .push(1);
            assert!(captured_tree(&raw, &accepted, true, Some(&source)).is_err());
            let mut source = transferred_state();
            source
                .files
                .insert(PathBuf::from("extra"), Zeroizing::new(vec![1]));
            assert!(captured_tree(&raw, &accepted, true, Some(&source)).is_err());
            let mut source = transferred_state();
            source.directories.insert(PathBuf::from("extra"));
            assert!(captured_tree(&raw, &accepted, true, Some(&source)).is_err());
        }
        #[test]
        fn transfer_cannot_overwrite_or_add_other_members() {
            let raw_state = transferred_state();
            let mut replacement = transferred_state();
            replacement
                .files
                .get_mut(Path::new("state.json"))
                .unwrap()
                .push(7);
            assert!(captured_tree(&raw_state, &replacement, true, Some(&replacement)).is_err());
            assert!(captured_tree(
                &tree(),
                &transferred_state(),
                true,
                Some(&transferred_state())
            )
            .is_err());
            let raw = empty_tree();
            let mut accepted = transferred_state();
            accepted
                .files
                .insert(PathBuf::from("extra"), Zeroizing::new(vec![1]));
            assert!(captured_tree(&raw, &accepted, true, Some(&transferred_state())).is_err());
            let mut accepted = transferred_state();
            accepted.directories.insert(PathBuf::from("extra"));
            assert!(captured_tree(&raw, &accepted, true, Some(&transferred_state())).is_err());
            let mut accepted = empty_tree();
            accepted
                .files
                .insert(PathBuf::from("other.json"), Zeroizing::new(vec![1]));
            assert!(captured_tree(&raw, &accepted, true, Some(&transferred_state())).is_err());
        }
    }
}
