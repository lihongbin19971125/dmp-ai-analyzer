//! DMP analysis engine — I/O layer.
//!
//! Modules: cache (SHA256 + LRU filesystem), report (Markdown generation),
//! template (prompt selection), diff (report comparison).

pub mod cache;
pub mod cdb;
pub mod report;
pub mod template;
pub mod diff;
