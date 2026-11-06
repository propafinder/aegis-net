//! Protected AUTO v2 directory-receipt state reader; nested in transaction.
//! Never falls back to original state paths or the v1 singleton receipt chain.
use super::authority::StageGuard;
use crate::profile_auto_capture::SealedStageAuthority;
use crate::profile_auto_publication::linux as fs;
use std::path::Path;
use zeroize::Zeroizing;
const REFUSED: &str = "Protected AUTO v2 owned state read refused";
type Result<T> = std::result::Result<T, &'static str>;

pub(super) struct PublishedState;
impl super::store_context::StateContext for PublishedState {
    fn read_owned_published_state(
        &self,
        stage: &StageGuard,
        relative: &Path,
    ) -> Result<Zeroizing<Vec<u8>>> {
        read_owned_published_state(stage, relative)
    }
}
fn read_owned_published_state(stage: &StageGuard, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
    SealedStageAuthority::revalidate(stage).map_err(|_| REFUSED)?;
    if stage.header.protocol != "auto-config-snapshot-v2" || stage.header.pending.is_some() {
        return Err(REFUSED);
    }
    let binding = stage.header.runtime_binding.as_ref().ok_or(REFUSED)?;
    binding.revalidate_local_generation().map_err(|_| REFUSED)?;
    let identity = binding.identity();
    let admitted = stage.publication_record("state").map_err(|_| REFUSED)?;
    let target = fs::Target::open(&stage.header.state_dir)?;
    let receipt = fs::reopen_own_receipt(&target, &admitted)?;
    fs::verify_runtime_state_policy(&target, &receipt, identity.uid(), identity.gid())?;
    let bytes = fs::read_current_leaf(&target, &receipt, relative)?;
    fs::verify_runtime_state_policy(&target, &receipt, identity.uid(), identity.gid())?;
    binding.revalidate_local_generation().map_err(|_| REFUSED)?;
    SealedStageAuthority::revalidate(stage).map_err(|_| REFUSED)?;
    Ok(bytes)
}
