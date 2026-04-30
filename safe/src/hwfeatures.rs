use std::collections::BTreeSet;
use std::ffi::{CStr, CString};

use crate::error;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const KNOWN_FEATURES: &[&str] = &[
    "padlock-rng",
    "padlock-aes",
    "padlock-sha",
    "padlock-mmul",
    "intel-cpu",
    "intel-fast-shld",
    "intel-bmi2",
    "intel-ssse3",
    "intel-sse4.1",
    "intel-pclmul",
    "intel-aesni",
    "intel-rdrand",
    "intel-avx",
    "intel-avx2",
    "intel-fast-vpgather",
    "intel-rdtsc",
    "intel-shaext",
    "intel-vaes-vpclmul",
];

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const KNOWN_FEATURES: &[&str] = &["arm-neon", "arm-aes", "arm-sha1", "arm-sha2", "arm-pmull"];

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
const KNOWN_FEATURES: &[&str] = &[
    "ppc-vcrypto",
    "ppc-arch_3_00",
    "ppc-arch_2_07",
    "ppc-arch_3_10",
];

#[cfg(target_arch = "s390x")]
const KNOWN_FEATURES: &[&str] = &[
    "s390x-msa",
    "s390x-msa-4",
    "s390x-msa-8",
    "s390x-msa-9",
    "s390x-vx",
];

#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "s390x"
)))]
const KNOWN_FEATURES: &[&str] = &[];

fn validate_token(token: &str) -> Result<(), u32> {
    if token == "all" || KNOWN_FEATURES.contains(&token) {
        Ok(())
    } else {
        Err(error::GPG_ERR_INV_NAME)
    }
}

pub(crate) fn sanitize_disable_request(names: &CStr) -> Result<Option<CString>, u32> {
    let mut explicit = BTreeSet::new();
    let mut saw_all = false;

    for token in names.to_string_lossy().split([':', ',']) {
        if token.is_empty() {
            continue;
        }
        validate_token(token)?;
        if token == "all" {
            saw_all = true;
        } else {
            explicit.insert(token.to_string());
        }
    }

    let mut effective = BTreeSet::new();
    if saw_all {
        for known in KNOWN_FEATURES {
            effective.insert((*known).to_string());
        }
    }

    effective.extend(explicit);

    if effective.is_empty() {
        Ok(None)
    } else {
        CString::new(effective.into_iter().collect::<Vec<_>>().join(":"))
            .map(Some)
            .map_err(|_| error::GPG_ERR_INV_ARG)
    }
}

pub(crate) fn remember_disabled_features(disabled: &mut BTreeSet<String>, names: Option<&CStr>) {
    let Some(names) = names else {
        return;
    };

    for token in names.to_string_lossy().split(':') {
        if !token.is_empty() {
            disabled.insert(token.to_string());
        }
    }
}

pub(crate) fn active_feature_names(disabled: &BTreeSet<String>) -> Vec<&'static str> {
    let enabled = |name: &str| !disabled.contains(name);
    let mut features = Vec::new();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if enabled("intel-cpu") {
            features.push("intel-cpu");
        }
        if enabled("intel-bmi2") && std::is_x86_feature_detected!("bmi2") {
            features.push("intel-bmi2");
        }
        if enabled("intel-ssse3") && std::is_x86_feature_detected!("ssse3") {
            features.push("intel-ssse3");
        }
        if enabled("intel-sse4.1") && std::is_x86_feature_detected!("sse4.1") {
            features.push("intel-sse4.1");
        }
        if enabled("intel-pclmul") && std::is_x86_feature_detected!("pclmulqdq") {
            features.push("intel-pclmul");
        }
        if enabled("intel-aesni") && std::is_x86_feature_detected!("aes") {
            features.push("intel-aesni");
        }
        if enabled("intel-rdrand") && std::is_x86_feature_detected!("rdrand") {
            features.push("intel-rdrand");
        }
        if enabled("intel-avx") && std::is_x86_feature_detected!("avx") {
            features.push("intel-avx");
        }
        if enabled("intel-avx2") && std::is_x86_feature_detected!("avx2") {
            features.push("intel-avx2");
        }
        if enabled("intel-shaext") && std::is_x86_feature_detected!("sha") {
            features.push("intel-shaext");
        }
        if enabled("intel-vaes-vpclmul")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
        {
            features.push("intel-vaes-vpclmul");
        }
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        if enabled("arm-neon") && std::arch::is_aarch64_feature_detected!("neon") {
            features.push("arm-neon");
        }
        if enabled("arm-aes") && std::arch::is_aarch64_feature_detected!("aes") {
            features.push("arm-aes");
        }
        if enabled("arm-sha1") && std::arch::is_aarch64_feature_detected!("sha2") {
            features.push("arm-sha1");
        }
        if enabled("arm-sha2") && std::arch::is_aarch64_feature_detected!("sha2") {
            features.push("arm-sha2");
        }
        if enabled("arm-pmull") && std::arch::is_aarch64_feature_detected!("pmull") {
            features.push("arm-pmull");
        }
    }

    features
}
