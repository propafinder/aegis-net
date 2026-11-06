//! Signed web-response route identity and separate private admission-key path.
//! This type contains no credential bytes and grants no device authorization.
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Component, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebResponseSettings {
    pub authority: String,
    pub descriptor_path: String,
    pub allowed_ingress_ips: Vec<IpAddr>,
    pub credential_file: PathBuf,
}

impl WebResponseSettings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::https_bridge::valid_authority(&self.authority)
            || !crate::https_bridge::valid_path(&self.descriptor_path)
            || self.allowed_ingress_ips.is_empty()
            || self.allowed_ingress_ips.len() > 16
            || self
                .allowed_ingress_ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
            || !self.credential_file.is_absolute()
            || !self.credential_file.components().all(|c| {
                matches!(
                    c,
                    Component::Prefix(_) | Component::RootDir | Component::Normal(_)
                )
            })
        {
            return Err("web-response private route rejected");
        }
        Ok(())
    }
}
