//! At-rest protection for long-term private key material
//! (`identity.json`, `cryptkey.dat`).
//!
//! On Windows we wrap secret blobs with DPAPI (`CryptProtectData` /
//! `CryptUnprotectData`) scoped to the **current user account**, so a copied
//! or backed-up key file cannot be read under another account or on another
//! machine. This is defense-in-depth on top of the restricted file ACL the
//! files already get — the ACL stops same-machine snooping; DPAPI stops a
//! stolen/exfiltrated file from being usable elsewhere.
//!
//! On non-Windows targets (developer/CI machines only — release ships Windows)
//! this is a transparent pass-through; the restricted ACL remains the control.
//!
//! Wire format of a protected blob: `MAGIC (8 bytes) || DPAPI ciphertext`.
//! Files without `MAGIC` are treated as legacy plaintext and are transparently
//! re-saved in protected form by the callers on next load.

/// Marker prefixing a DPAPI-wrapped blob. Lets us distinguish protected files
/// from legacy plaintext ones without a separate flag.
const MAGIC: &[u8; 8] = b"EMBRSEC1";

/// Extra entropy mixed into DPAPI so a protected blob can only be unwrapped by
/// this application's code path (not by another DPAPI consumer on the system).
const ENTROPY: &[u8] = b"ember-secret-store-v1";

/// True if `stored` is already in the protected (MAGIC-tagged) form.
pub fn is_protected(stored: &[u8]) -> bool {
    stored.len() >= MAGIC.len() && &stored[..MAGIC.len()] == MAGIC
}

/// Wrap `plaintext` for at-rest storage. On success returns
/// `MAGIC || ciphertext`. If protection is unavailable (non-Windows build, or
/// a DPAPI failure), returns the plaintext unchanged so saving never fails —
/// the restricted file ACL remains as the fallback control.
pub fn protect(plaintext: &[u8]) -> Vec<u8> {
    #[cfg(target_os = "windows")]
    {
        match win::protect(plaintext, ENTROPY) {
            Ok(ct) => {
                let mut out = Vec::with_capacity(MAGIC.len() + ct.len());
                out.extend_from_slice(MAGIC);
                out.extend_from_slice(&ct);
                return out;
            }
            Err(e) => {
                tracing::warn!(
                    "DPAPI protect failed ({e}); storing secret with restricted ACL only"
                );
            }
        }
    }
    plaintext.to_vec()
}

/// Inverse of [`protect`]. If `stored` begins with `MAGIC`, DPAPI-unprotect the
/// remainder; otherwise treat `stored` as legacy plaintext and return it
/// unchanged. Returns `Err` only when a MAGIC-tagged blob fails to decrypt
/// (wrong user/machine, or corruption) — callers treat that like a corrupt
/// secret file rather than silently rotating identity.
pub fn unprotect(stored: &[u8]) -> anyhow::Result<Vec<u8>> {
    if is_protected(stored) {
        #[cfg(target_os = "windows")]
        {
            return win::unprotect(&stored[MAGIC.len()..], ENTROPY)
                .map_err(|e| anyhow::anyhow!("DPAPI unprotect failed: {e}"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!(
                "secret file is DPAPI-protected but this is a non-Windows build; \
                 move the file back to the Windows machine that created it"
            );
        }
    }
    Ok(stored.to_vec())
}

#[cfg(target_os = "windows")]
mod win {
    use std::os::raw::c_void;

    /// Win32 `DATA_BLOB` (a.k.a. `CRYPTOAPI_BLOB`).
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    /// `CRYPTPROTECT_UI_FORBIDDEN` — never show UI; fail instead (we run headless
    /// from a network task).
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            pp_sz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    fn blob(data: &[u8]) -> DataBlob {
        DataBlob {
            // DPAPI inputs are far smaller than u32::MAX; clamp defensively.
            cb_data: data.len().min(u32::MAX as usize) as u32,
            pb_data: data.as_ptr() as *mut u8,
        }
    }

    /// Copy the Windows-allocated output blob into an owned `Vec` and release
    /// the original with `LocalFree`.
    ///
    /// # Safety
    /// `out` must be an output blob populated by a successful
    /// `CryptProtectData`/`CryptUnprotectData` call (non-null `pb_data`).
    unsafe fn take_out_blob(out: &DataBlob) -> Vec<u8> {
        let v = std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec();
        LocalFree(out.pb_data as *mut c_void);
        v
    }

    pub fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
        let in_blob = blob(plaintext);
        let ent_blob = blob(entropy);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: `in_blob`/`ent_blob` borrow live slices for the duration of
        // the call; all other pointer args are null/optional per the DPAPI
        // contract. On success Windows allocates `out.pb_data`, which
        // `take_out_blob` copies and frees.
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &ent_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err("CryptProtectData failed".to_string());
        }
        Ok(unsafe { take_out_blob(&out) })
    }

    pub fn unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
        let in_blob = blob(ciphertext);
        let ent_blob = blob(entropy);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: see `protect`. The entropy must match what was used to
        // protect, otherwise DPAPI fails and we return Err.
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &ent_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err("CryptUnprotectData failed".to_string());
        }
        Ok(unsafe { take_out_blob(&out) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_protect_unprotect() {
        let secret = b"super secret key material \x00\x01\x02";
        let wrapped = protect(secret);
        let recovered = unprotect(&wrapped).expect("unprotect");
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        // A blob without MAGIC is returned unchanged (legacy migration path).
        let legacy = b"{\"kad_id\":[1,2,3]}";
        assert!(!is_protected(legacy));
        assert_eq!(unprotect(legacy).unwrap(), legacy);
    }
}
