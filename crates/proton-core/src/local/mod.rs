//! Local filesystem scanner.
//!
//! Provides utilities for walking local directories and computing file hashes
//! for comparison with remote drive state.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;

/// A node in the local filesystem tree.
#[derive(Debug, Clone)]
pub struct LocalNode {
    pub path: PathBuf,
    pub is_file: bool,
    pub size: u64,
    pub modified_time: std::time::SystemTime,
    pub hash: Option<String>, // SHA256 hash for files, None for directories
}

impl LocalNode {
    /// Create a new LocalNode from a path.
    pub async fn from_path(path: PathBuf) -> Result<Self> {
        let metadata = fs::metadata(&path).await.map_err(|e| {
            Error::Io(format!(
                "Failed to read metadata for {}: {}",
                path.display(),
                e
            ))
        })?;

        let is_file = metadata.is_file();
        let size = metadata.len();
        let modified_time = metadata.modified().map_err(|e| {
            Error::Io(format!(
                "Failed to read modified time for {}: {}",
                path.display(),
                e
            ))
        })?;

        let hash = if is_file {
            Some(compute_file_hash(&path).await?)
        } else {
            None
        };

        Ok(Self {
            path,
            is_file,
            size,
            modified_time,
            hash,
        })
    }

    /// Get the relative path from a base directory.
    pub fn relative_path(&self, base: &Path) -> Result<PathBuf> {
        self.path
            .strip_prefix(base)
            .map(|p| p.to_path_buf())
            .map_err(|_| {
                Error::Io(format!(
                    "Path {} is not under base {}",
                    self.path.display(),
                    base.display()
                ))
            })
    }
}

/// Compute SHA256 hash of a file.
async fn compute_file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .await
        .map_err(|e| Error::Io(format!("Failed to open file {}: {}", path.display(), e)))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|e| Error::Io(format!("Failed to read file {}: {}", path.display(), e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Local filesystem client for scanning directories.
pub struct LocalClient {
    base_path: PathBuf,
}

impl LocalClient {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Recursively walk the directory and return all nodes.
    pub async fn walk_all(&self) -> Result<Vec<LocalNode>> {
        let mut nodes = Vec::new();
        self.walk_recursive(&self.base_path, &mut nodes).await?;
        Ok(nodes)
    }

    /// Recursively walk a directory.
    async fn walk_recursive(&self, dir: &Path, nodes: &mut Vec<LocalNode>) -> Result<()> {
        let mut entries = fs::read_dir(dir)
            .await
            .map_err(|e| Error::Io(format!("Failed to read directory {}: {}", dir.display(), e)))?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            Error::Io(format!(
                "Failed to read directory entry in {}: {}",
                dir.display(),
                e
            ))
        })? {
            let path = entry.path();
            let node = LocalNode::from_path(path.clone()).await?;
            let is_dir = !node.is_file;
            nodes.push(node);

            if is_dir {
                Box::pin(self.walk_recursive(&path, nodes)).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("proton-local-test-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn create_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[tokio::test]
    async fn walk_empty_dir() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let client = LocalClient::new(dir.clone());
        let nodes = client.walk_all().await.unwrap();
        assert!(nodes.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn walk_single_file() {
        let dir = temp_dir();
        create_file(&dir.join("test.txt"), "hello");
        let client = LocalClient::new(dir.clone());
        let nodes = client.walk_all().await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].is_file);
        assert_eq!(nodes[0].path.file_name().unwrap(), "test.txt");
        assert_eq!(nodes[0].size, 5);
        assert!(nodes[0].hash.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn walk_nested_dirs() {
        let dir = temp_dir();
        create_file(&dir.join("a.txt"), "hello");
        create_file(&dir.join("sub/b.txt"), "world");
        create_file(&dir.join("sub/deep/c.txt"), "deep");
        let client = LocalClient::new(dir.clone());
        let mut nodes = client.walk_all().await.unwrap();

        // Sort by path for deterministic assertions
        nodes.sort_by(|a, b| a.path.cmp(&b.path));

        // 2 directories (sub, deep) + 3 files
        assert_eq!(nodes.len(), 5);

        let files: Vec<_> = nodes.iter().filter(|n| n.is_file).collect();
        assert_eq!(files.len(), 3);
        assert!(files[0].path.ends_with("a.txt"));
        assert!(files[1].path.ends_with("b.txt"));
        assert!(files[2].path.ends_with("c.txt"));

        let dirs: Vec<_> = nodes.iter().filter(|n| !n.is_file).collect();
        assert_eq!(dirs.len(), 2);
        assert!(dirs[0].path.ends_with("sub"));
        assert!(dirs[1].path.ends_with("deep"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn walk_mixed_files_and_dirs() {
        let dir = temp_dir();
        create_file(&dir.join("root.txt"), "root file");
        create_file(&dir.join("sub/child.txt"), "child");
        create_file(&dir.join("sub/nested/grandchild.txt"), "grandchild");

        let client = LocalClient::new(dir.clone());
        let nodes = client.walk_all().await.unwrap();

        // 2 directories (sub, nested) + 3 files
        assert_eq!(nodes.len(), 5);

        let files: Vec<_> = nodes.iter().filter(|n| n.is_file).collect();
        assert_eq!(files.len(), 3);

        // Each file should have a SHA256 hash
        for node in &files {
            assert!(node.hash.is_some(), "file {:?} missing hash", node.path);
            assert!(!node.hash.as_ref().unwrap().is_empty());
        }

        // Each directory should have no hash
        let dirs: Vec<_> = nodes.iter().filter(|n| !n.is_file).collect();
        assert_eq!(dirs.len(), 2);
        for node in &dirs {
            assert!(
                node.hash.is_none(),
                "dir {:?} should not have hash",
                node.path
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn relative_paths() {
        let dir = temp_dir();
        create_file(&dir.join("sub/child.txt"), "data");
        let client = LocalClient::new(dir.clone());
        let nodes = client.walk_all().await.unwrap();
        // sub directory + child.txt
        assert_eq!(nodes.len(), 2);
        let child = nodes
            .iter()
            .find(|n| n.path.ends_with("child.txt"))
            .unwrap();
        let rel = child.relative_path(&dir).unwrap();
        assert_eq!(rel, PathBuf::from("sub/child.txt"));

        let sub = nodes.iter().find(|n| n.path.ends_with("sub")).unwrap();
        let rel = sub.relative_path(&dir).unwrap();
        assert_eq!(rel, PathBuf::from("sub"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn hash_is_deterministic() {
        let dir = temp_dir();
        create_file(&dir.join("data.bin"), "deterministic content");
        let client = LocalClient::new(dir.clone());
        let nodes = client.walk_all().await.unwrap();
        assert_eq!(nodes.len(), 1);
        let hash1 = nodes[0].hash.clone();

        // Re-read the same file
        let node2 = LocalNode::from_path(dir.join("data.bin")).await.unwrap();
        assert_eq!(hash1, node2.hash);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn walk_non_existent_dir() {
        let dir = std::env::temp_dir().join("proton-local-test-nonexistent");
        let _ = std::fs::remove_dir_all(&dir);
        let client = LocalClient::new(dir.clone());
        let result = client.walk_all().await;
        assert!(result.is_err());
    }
}
