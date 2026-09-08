//! Create-new report boundaries. Restrictive Unix modes apply at creation,
//! not after customer bytes have already been exposed. Windows inherits ACLs.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use crate::AuditError;

pub(super) fn create_private_dir(path: &Path) -> Result<(), AuditError> {
    let builder = DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    // Do not reuse an existing directory or recursively create unchecked parents.
    builder.create(path)?;
    Ok(())
}

pub(super) fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), AuditError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    // Atomic create-new also rejects an existing final-component symlink.
    // Callers must still choose a trusted parent directory.
    let file = options.open(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(contents)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

pub(super) fn write_output(path: &str, contents: &str) -> Result<(), AuditError> {
    if path == "-" {
        let stdout = std::io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        writer.write_all(contents.as_bytes())?;
        writer.flush()?;
        return Ok(());
    }
    write_new_file(Path::new(path), contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;

    #[test]
    fn output_preserves_bytes_and_refuses_overwrite() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("report.json");
        let contents = "Synthetic evidence: café 😀\n".as_bytes();
        write_new_file(&path, contents)?;
        assert_eq!(fs::read(&path)?, contents);
        assert!(write_new_file(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path)?, contents);
        Ok(())
    }

    #[test]
    fn package_directory_is_create_new_and_non_recursive() -> Result<(), Box<dyn Error>> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("packet");
        create_private_dir(&path)?;
        write_new_file(&path.join("evidence.md"), b"original")?;
        assert!(create_private_dir(&path).is_err());
        assert_eq!(fs::read(path.join("evidence.md"))?, b"original");
        assert!(create_private_dir(&parent.path().join("missing/child")).is_err());
        assert!(write_new_file(&parent.path().join("missing/report"), b"x").is_err());
        assert!(!parent.path().join("missing").exists());
        Ok(())
    }

    #[test]
    fn concurrent_writers_cannot_replace_each_other() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("single-winner");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0_u8..8)
            .map(|index| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    (index, write_new_file(&path, &[index; 256]).is_ok())
                })
            })
            .collect();
        let mut winners = Vec::new();
        for handle in handles {
            let (index, won) = handle
                .join()
                .map_err(|_| std::io::Error::other("writer thread panicked"))?;
            if won {
                winners.push(index);
            }
        }
        assert_eq!(winners.len(), 1);
        assert_eq!(fs::read(path)?, vec![winners[0]; 256]);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_packets_are_private_at_creation() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("packet");
        create_private_dir(&path)?;
        write_new_file(&path.join("report"), b"synthetic")?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o077, 0);
        assert_eq!(
            fs::metadata(path.join("report"))?.permissions().mode() & 0o077,
            0
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn final_symlinks_are_not_followed_or_overwritten() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir()?;
        let original = directory.path().join("original");
        fs::write(&original, b"original")?;
        let link = directory.path().join("link");
        symlink(&original, &link)?;
        assert!(write_new_file(&link, b"replacement").is_err());
        assert_eq!(fs::read(&original)?, b"original");
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        let missing = directory.path().join("missing");
        let dangling = directory.path().join("dangling");
        symlink(&missing, &dangling)?;
        assert!(write_new_file(&dangling, b"replacement").is_err());
        assert!(!missing.exists());
        assert!(create_private_dir(&dangling).is_err());
        Ok(())
    }
}
