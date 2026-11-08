//! The cluster's shared Raft secret.
//!
//! One value, the same on every member, from which each handshake derives its
//! proofs and session key (see `transport`). Two properties matter and this
//! type enforces both:
//!
//! * **Length.** The listener answers any dialer with an HMAC of the secret
//!   over values the dialer can see, before the dialer has proved anything. A
//!   short or human-chosen secret can then be guessed offline from one
//!   recorded reply. At [`MIN_SECRET_BYTES`] random bytes there is nothing to
//!   guess, so shorter values are refused rather than warned about.
//! * **Not printed.** `Debug` is redacted, so the secret does not end up in a
//!   log line that dumps a config struct.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// Fewest bytes a shared secret may have. `openssl rand -hex 32` gives 64.
pub const MIN_SECRET_BYTES: usize = 32;

/// How to make a secret that passes, for every error message that refuses one.
const HOW_TO_GENERATE: &str = "generate one with `openssl rand -hex 32` and give the same value \
     to every member";

/// The cluster's shared secret. Cheap to clone; never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret(Arc<[u8]>);

impl SharedSecret {
    /// Accept `bytes` as the secret, or refuse it as too short.
    pub fn new(bytes: impl Into<Vec<u8>>) -> anyhow::Result<Self> {
        let bytes: Vec<u8> = bytes.into();
        if bytes.len() < MIN_SECRET_BYTES {
            anyhow::bail!(
                "the raft shared secret is {} bytes; at least {MIN_SECRET_BYTES} are required, \
                 because a short secret can be guessed offline from one handshake: {HOW_TO_GENERATE}",
                bytes.len()
            );
        }
        Ok(Self(bytes.into()))
    }

    /// Read the secret from a file that only its owner can read.
    ///
    /// A trailing newline is dropped (`openssl rand -hex 32 > file` writes
    /// one); nothing else is trimmed. A file with any group or other
    /// permission bit is refused: a secret readable by every local account is
    /// no better than one on the command line.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let meta = std::fs::metadata(path).map_err(|e| {
            anyhow::anyhow!(
                "cannot read the raft shared secret file {}: {e}",
                path.display()
            )
        })?;
        if !meta.is_file() {
            anyhow::bail!(
                "the raft shared secret file {} is not a regular file",
                path.display()
            );
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "the raft shared secret file {} has mode {mode:04o}, so other accounts can read \
                 or change it; restrict it to its owner (chmod 600)",
                path.display()
            );
        }
        let mut bytes = std::fs::read(path).map_err(|e| {
            anyhow::anyhow!(
                "cannot read the raft shared secret file {}: {e}",
                path.display()
            )
        })?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Self::new(bytes).map_err(|e| anyhow::anyhow!("{e:#} (read from {})", path.display()))
    }

    /// The raw bytes, for keying the handshake.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const GOOD: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_short_secret_is_refused_with_a_way_to_make_one() {
        let err = SharedSecret::new("hunter2").unwrap_err().to_string();
        assert!(err.contains("at least 32"), "{err}");
        assert!(err.contains("openssl rand -hex 32"), "{err}");
        assert!(
            !err.contains("hunter2"),
            "the refusal must not echo the secret: {err}"
        );
        assert!(SharedSecret::new(&GOOD.as_bytes()[..31]).is_err());
        assert!(SharedSecret::new(GOOD).is_ok());
    }

    #[test]
    fn debug_does_not_print_the_secret() {
        let s = SharedSecret::new(GOOD).unwrap();
        let shown = format!("{s:?} {:?}", Some(s.clone()));
        assert!(!shown.contains(GOOD), "{shown}");
        assert!(shown.contains("redacted"));
    }

    fn write_secret(contents: &str, mode: u32) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), contents).unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    #[test]
    fn a_secret_file_readable_by_others_is_refused() {
        let f = write_secret(GOOD, 0o644);
        let err = SharedSecret::from_file(f.path()).unwrap_err().to_string();
        assert!(err.contains("0644") && err.contains("chmod 600"), "{err}");
        let f = write_secret(GOOD, 0o640);
        assert!(SharedSecret::from_file(f.path()).is_err(), "group-readable");
    }

    #[test]
    fn an_owner_only_secret_file_is_read_without_its_newline() {
        let f = write_secret(&format!("{GOOD}\n"), 0o600);
        let s = SharedSecret::from_file(f.path()).unwrap();
        assert_eq!(s.expose(), GOOD.as_bytes());
    }

    #[test]
    fn a_short_secret_file_is_refused() {
        let f = write_secret("short\n", 0o400);
        assert!(SharedSecret::from_file(f.path()).is_err());
    }
}
