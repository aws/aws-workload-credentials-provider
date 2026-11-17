//! The `notify` watch on the inbox directory, bridged into the async loop.

use std::path::{Path, PathBuf};

use log::debug;
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::error::StartupError;

/// Something the watch observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// The paths named by one `notify` event.
    ///
    /// Deliberately not pre-filtered by path: the event loop decides what is
    /// a request, by its name ([`crate::inbox::is_request_file`]) and then by
    /// parsing it ([`crate::inbox::read`]). This module therefore knows nothing
    /// about request naming, and acceptance stays unit-testable without a live
    /// watcher. The only filter here is on event kind, in [`to_watch_event`].
    Paths(Vec<PathBuf>),

    /// A full rescan is needed, with the reason to log.
    Rescan(RescanReason),
}

/// Why a rescan was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RescanReason {
    /// The backend set its rescan flag: it lost track of some events.
    NeedRescan,

    /// The backend reported an error.
    WatchError(String),

    /// The inbox directory itself was removed or renamed away.
    ///
    /// The watch is then gone, or follows the moved directory while the path
    /// names something else. Neither inotify's `IN_IGNORED` nor `IN_UNMOUNT`
    /// reaches this crate through `notify`, so an unmount produces no event at
    /// all; the event loop's missed-request check on the periodic scan is what
    /// catches that.
    InboxReplaced,
}

impl RescanReason {
    /// True when the watch may no longer be delivering events.
    ///
    /// A queue overflow leaves the watch live, so it needs a rescan only.
    pub fn needs_rebind(&self) -> bool {
        !matches!(self, Self::NeedRescan)
    }
}

/// The event loop's view of the watch: an event stream that can be replaced.
///
/// A trait so that the loop's tests can drive it from a plain channel and
/// count rebinds, with no real filesystem watcher.
pub trait InboxWatcher {
    /// The current event stream. A successful [`InboxWatcher::rebind`]
    /// replaces it.
    fn events(&mut self) -> &mut mpsc::UnboundedReceiver<WatchEvent>;

    /// Replaces the watch with a fresh one on `inbox`.
    ///
    /// On `Err` the old watch, and its event stream, are kept unchanged.
    /// Never called once the event stream has ended: that is
    /// [`crate::error::RunError::WatchChannelClosed`], not a rebind.
    fn rebind(&mut self, inbox: &Path) -> notify::Result<()>;
}

/// A live watch on one inbox directory.
///
/// Dropping this stops the watch, which is the classic silent failure in this
/// design. The receiver is reachable only through [`InboxWatcher::events`],
/// taking `&mut self`, so the borrow checker keeps the watch alive for as long
/// as anything is reading from it.
pub struct InboxWatch {
    watcher: RecommendedWatcher,
    events: mpsc::UnboundedReceiver<WatchEvent>,
}

impl InboxWatch {
    /// Starts watching `inbox`.
    ///
    /// Non-recursive: only this watcher's own `inbox/` matters, and it has no
    /// subdirectories to follow.
    ///
    /// A watch that cannot be established here is a startup failure: a
    /// container that cannot watch its own inbox directory at startup is
    /// misconfigured, so this exits non-zero and lets the container be
    /// restarted. Once running, a watch that is lost is re-established by the
    /// event loop through [`InboxWatcher::rebind`], with the periodic scan
    /// covering the gap.
    pub fn start(inbox: &Path) -> Result<Self, StartupError> {
        let (watcher, events) = bind(inbox).map_err(|source| StartupError::Watch {
            path: inbox.to_path_buf(),
            source,
        })?;
        Ok(Self { watcher, events })
    }
}

impl InboxWatcher for InboxWatch {
    fn events(&mut self) -> &mut mpsc::UnboundedReceiver<WatchEvent> {
        &mut self.events
    }

    /// Drops and recreates the `notify` watcher rather than calling `watch`
    /// again on the old one.
    ///
    /// A fresh backend instance recovers a broken inotify descriptor, which
    /// is what an inotify `WatchError` means; a fresh channel discards events
    /// still queued for the old directory; and calling `watch` again on a path
    /// whose directory was replaced would leave the old watch descriptor
    /// attached to the old directory, reporting its files under the new path.
    fn rebind(&mut self, inbox: &Path) -> notify::Result<()> {
        // `notify`'s `Drop` unwraps a send to its own thread, so dropping a
        // watcher whose thread has died panics. A closed channel is the only
        // sign of that thread dying; leave such a watcher for the loop to
        // report as `WatchChannelClosed`.
        if self.events.is_closed() {
            return Err(notify::Error::generic(
                "the watch's event channel is closed",
            ));
        }

        // Built first, so a failure keeps the old watch.
        let (watcher, events) = bind(inbox)?;
        self.watcher = watcher;
        self.events = events;
        Ok(())
    }
}

/// Builds a watcher on `inbox` and the channel its events arrive on.
fn bind(inbox: &Path) -> notify::Result<(RecommendedWatcher, mpsc::UnboundedReceiver<WatchEvent>)> {
    let (tx, events) = mpsc::unbounded_channel();
    let root = inbox.to_path_buf();

    // This closure runs synchronously on notify's own thread, outside the
    // tokio runtime: it must not block and must not await. That is why the
    // channel is unbounded — `UnboundedSender::send` needs no runtime
    // context and never blocks, whereas a bounded `blocking_send` from
    // this thread could stall the backend's event pump. The bound that
    // matters is `inbox::MAX_REQUESTS_PER_SCAN`, applied where requests
    // are read.
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Some(event) = to_watch_event(&root, result) else {
            return;
        };

        // A send failure means the receiver is gone: this watch was replaced
        // by a rebind, or the loop has finished and the process is shutting
        // down.
        if tx.send(event).is_err() {
            debug!("Dropping a filesystem event: this watch was replaced or is shutting down");
        }
    })?;

    watcher.watch(inbox, RecursiveMode::NonRecursive)?;

    Ok((watcher, events))
}

/// Maps one `notify` result for the watch on `inbox` to what the loop sees,
/// or `None` to drop it.
fn to_watch_event(inbox: &Path, result: notify::Result<Event>) -> Option<WatchEvent> {
    match result {
        // The backend lost track of events. Never a silent drop: turn it into
        // a conservative rescan.
        Ok(event) if event.need_rescan() => Some(WatchEvent::Rescan(RescanReason::NeedRescan)),
        // Access events are dropped to break a busy-loop: inotify reports
        // opening the watched inbox directory as `Access(Open)` on the
        // directory itself, admitting that path opens the directory again,
        // and so on. Arrival is a rename (`Modify(Name(_))`) or `Create`.
        Ok(event) if matches!(event.kind, EventKind::Access(_)) => None,
        Ok(event) if is_self_event(inbox, &event) => {
            Some(WatchEvent::Rescan(RescanReason::InboxReplaced))
        }
        Ok(event) => Some(WatchEvent::Paths(event.paths)),
        Err(e) => Some(WatchEvent::Rescan(RescanReason::WatchError(e.to_string()))),
    }
}

/// True for the inbox directory itself being removed or renamed away.
///
/// inotify reports these as `Remove(Folder)` and `Modify(Name(From))` on the
/// watched path. Matching the exact path is unambiguous: `notify` joins a
/// child's name onto the watched path, and the parent is not watched, so no
/// other event carries the bare inbox path.
fn is_self_event(inbox: &Path, event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    ) && event.paths.iter().any(|path| path == inbox)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    use tempfile::TempDir;

    /// Long enough that a working backend never fails it, short enough that a
    /// broken one fails instead of hanging the suite.
    const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

    /// `#[tokio::test]`, not `#[test]`: the receiver is a tokio primitive, and
    /// a real watcher thread needs a real clock, so the runtime's time is not
    /// paused.
    ///
    /// Unix-only. The Windows backend's rename-over event ordering and whether
    /// it reports the destination path are unverified here, so asserting Linux
    /// semantics would be a false green there. The design does not depend on
    /// the answer: name-based acceptance, claim-on-pickup and the periodic
    /// rescan mean a missing or oddly ordered event costs latency, not
    /// correctness.
    #[tokio::test]
    async fn rename_into_place_is_reported() {
        let tmp = TempDir::new().unwrap();
        // Canonical, because macOS's FSEvents reports `/private/var/...` for a
        // temp directory under the `/var` symlink.
        let root = tmp.path().canonicalize().unwrap();
        let mut watch = InboxWatch::start(&root).unwrap();

        let destination = root.join("1728331740000-001-req-abcd.cmd");
        let temp = root.join("1728331740000-001-req-abcd.cmd.tmp");
        fs::write(&temp, "{}").unwrap();
        fs::rename(&temp, &destination).unwrap();

        let mut seen: Vec<PathBuf> = Vec::new();
        tokio::time::timeout(EVENT_TIMEOUT, async {
            while let Some(event) = watch.events().recv().await {
                if let WatchEvent::Paths(paths) = event {
                    seen.extend(paths);
                    if seen.contains(&destination) {
                        return;
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no event named the renamed file; saw {seen:?}"));
    }

    /// Regression test for the inbox busy-loop, against the real inotify
    /// backend. Linux-only: inotify is the backend that reports opens.
    ///
    /// Not timing-based: inotify delivers events in order, so once the
    /// rename's event arrives, any event from the earlier directory open has
    /// already been delivered or dropped.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn opening_the_inbox_directory_is_not_reported() {
        let tmp = TempDir::new().unwrap();
        let mut watch = InboxWatch::start(tmp.path()).unwrap();

        // What the loop's scan does: opens the watched directory itself.
        fs::read_dir(tmp.path()).unwrap().for_each(drop);

        let destination = tmp.path().join("1728331740000-001-req-abcd.cmd");
        let temp = tmp.path().join("1728331740000-001-req-abcd.cmd.tmp");
        fs::write(&temp, "{}").unwrap();
        fs::rename(&temp, &destination).unwrap();

        let mut seen: Vec<PathBuf> = Vec::new();
        tokio::time::timeout(EVENT_TIMEOUT, async {
            while let Some(event) = watch.events().recv().await {
                if let WatchEvent::Paths(paths) = event {
                    seen.extend(paths);
                    if seen.contains(&destination) {
                        return;
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no event named the renamed file; saw {seen:?}"));

        assert!(
            !seen.iter().any(|path| path == tmp.path()),
            "opening the inbox directory produced an event naming it: {seen:?}"
        );
    }

    #[tokio::test]
    async fn watch_on_a_missing_directory_fails() {
        let tmp = TempDir::new().unwrap();

        // `InboxWatch` holds a `RecommendedWatcher`, which is not `Debug`,
        // so the error cannot be taken with `unwrap_err`.
        let err = match InboxWatch::start(&tmp.path().join("absent")) {
            Ok(_) => panic!("watching a missing directory should fail"),
            Err(e) => e,
        };

        assert!(matches!(err, StartupError::Watch { .. }));
        assert!(err.to_string().contains("absent"), "{err}");
    }

    /// Writes `name` into `dir` the way the ACM provider does: a temp file
    /// renamed into place.
    #[cfg(target_os = "linux")]
    fn arrive(dir: &Path, name: &str) {
        let temp = dir.join(format!("{name}.tmp"));
        fs::write(&temp, "{}").unwrap();
        fs::rename(&temp, dir.join(name)).unwrap();
    }

    /// True when `event` names a file called `name`, in any directory.
    #[cfg(target_os = "linux")]
    fn names(event: &WatchEvent, name: &str) -> bool {
        matches!(event, WatchEvent::Paths(paths)
            if paths.iter().any(|path| path.file_name().is_some_and(|n| n == name)))
    }

    /// Receives until `done` accepts an event, and returns every event seen,
    /// that one included. Panics on timeout or a closed channel.
    #[cfg(target_os = "linux")]
    async fn collect_until(
        watch: &mut InboxWatch,
        mut done: impl FnMut(&WatchEvent) -> bool,
    ) -> Vec<WatchEvent> {
        let mut seen = Vec::new();
        let finished = tokio::time::timeout(EVENT_TIMEOUT, async {
            while let Some(event) = watch.events().recv().await {
                let stop = done(&event);
                seen.push(event);
                if stop {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(
            finished.ok(),
            Some(true),
            "the expected event never came; saw {seen:?}"
        );
        seen
    }

    /// `rmdir` of the watched inbox is reported as `InboxReplaced`, and after
    /// the directory is recreated a rebind reports files in the new one.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rebind_after_the_inbox_is_recreated_reports_new_files() {
        let tmp = TempDir::new().unwrap();
        let inbox = tmp.path().join("inbox");
        fs::create_dir(&inbox).unwrap();
        let mut watch = InboxWatch::start(&inbox).unwrap();

        fs::remove_dir(&inbox).unwrap();
        collect_until(&mut watch, |event| {
            *event == WatchEvent::Rescan(RescanReason::InboxReplaced)
        })
        .await;

        fs::create_dir(&inbox).unwrap();
        watch.rebind(&inbox).unwrap();

        arrive(&inbox, "new.cmd");
        collect_until(&mut watch, |event| names(event, "new.cmd")).await;
    }

    /// The leaked-watch-descriptor regression. Renaming the inbox away is
    /// reported as `InboxReplaced`; after a rebind onto a new directory at the
    /// same path, a file arriving in the renamed-away directory is not
    /// reported, and one arriving in the new directory is.
    ///
    /// Not timing-based: `old.cmd` is written first. A descriptor still
    /// attached to the old directory would share the new watch's inotify
    /// instance, which delivers in order, so its event would arrive before
    /// `new.cmd`'s.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rebind_does_not_report_the_renamed_away_directory() {
        let tmp = TempDir::new().unwrap();
        let inbox = tmp.path().join("inbox");
        let old = tmp.path().join("inbox.old");
        fs::create_dir(&inbox).unwrap();
        let mut watch = InboxWatch::start(&inbox).unwrap();

        fs::rename(&inbox, &old).unwrap();
        collect_until(&mut watch, |event| {
            *event == WatchEvent::Rescan(RescanReason::InboxReplaced)
        })
        .await;

        fs::create_dir(&inbox).unwrap();
        watch.rebind(&inbox).unwrap();

        arrive(&old, "old.cmd");
        arrive(&inbox, "new.cmd");
        let seen = collect_until(&mut watch, |event| names(event, "new.cmd")).await;

        assert!(
            !seen.iter().any(|event| names(event, "old.cmd")),
            "a file in the renamed-away directory was reported: {seen:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_failed_rebind_keeps_the_old_watch() {
        let tmp = TempDir::new().unwrap();
        let mut watch = InboxWatch::start(tmp.path()).unwrap();

        assert!(watch.rebind(&tmp.path().join("absent")).is_err());

        arrive(tmp.path(), "kept.cmd");
        collect_until(&mut watch, |event| names(event, "kept.cmd")).await;
    }
}

/// The kind filter, driven through the same function the watcher's closure
/// calls. Cross-platform: no live watcher.
#[cfg(test)]
mod filter_tests {
    use super::*;
    use notify::event::{
        AccessKind, AccessMode, CreateKind, Flag, MetadataKind, RemoveKind, RenameMode,
    };

    fn inbox() -> PathBuf {
        PathBuf::from("/requests/watcher_id_1/inbox")
    }

    fn request() -> PathBuf {
        inbox().join("1728331740000-001-req-abcd.cmd")
    }

    fn event(kind: EventKind, paths: &[PathBuf]) -> notify::Result<Event> {
        let mut event = Event::new(kind);
        for path in paths {
            event = event.add_path(path.clone());
        }
        Ok(event)
    }

    #[test]
    fn access_events_are_dropped() {
        for kind in [
            AccessKind::Open(AccessMode::Any),
            AccessKind::Close(AccessMode::Read),
            AccessKind::Close(AccessMode::Write),
            AccessKind::Read,
            AccessKind::Any,
        ] {
            for path in [inbox(), request()] {
                assert_eq!(
                    to_watch_event(
                        &inbox(),
                        event(EventKind::Access(kind), std::slice::from_ref(&path))
                    ),
                    None,
                    "{kind:?} on {path:?} should be dropped"
                );
            }
        }
    }

    #[test]
    fn create_and_rename_events_are_forwarded() {
        let temp = inbox().join("1728331740000-001-req-abcd.cmd.tmp");
        let cases = [
            (EventKind::Create(CreateKind::File), vec![request()]),
            (EventKind::Create(CreateKind::Any), vec![request()]),
            (
                EventKind::Modify(ModifyKind::Name(RenameMode::To)),
                vec![request()],
            ),
            (
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                vec![temp, request()],
            ),
        ];
        for (kind, paths) in cases {
            assert_eq!(
                to_watch_event(&inbox(), event(kind, &paths)),
                Some(WatchEvent::Paths(paths.clone())),
                "{kind:?} should be forwarded"
            );
        }
    }

    /// A lost-events flag wins over the kind filter, so a rescan is never
    /// dropped along with an Access event.
    #[test]
    fn need_rescan_is_kept_even_on_an_access_event() {
        let flagged = event(
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            &[inbox()],
        )
        .map(|event| event.set_flag(Flag::Rescan));
        assert_eq!(
            to_watch_event(&inbox(), flagged),
            Some(WatchEvent::Rescan(RescanReason::NeedRescan))
        );
    }

    #[test]
    fn errors_become_rescans() {
        assert!(matches!(
            to_watch_event(&inbox(), Err(notify::Error::generic("boom"))),
            Some(WatchEvent::Rescan(RescanReason::WatchError(message))) if message.contains("boom")
        ));
    }

    /// inotify's `DELETE_SELF` and `MOVE_SELF` on the watched directory.
    #[test]
    fn removing_or_renaming_the_inbox_itself_is_inbox_replaced() {
        for kind in [
            EventKind::Remove(RemoveKind::Folder),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
        ] {
            assert_eq!(
                to_watch_event(&inbox(), event(kind, &[inbox()])),
                Some(WatchEvent::Rescan(RescanReason::InboxReplaced)),
                "{kind:?} on the inbox should be InboxReplaced"
            );
        }
    }

    /// The same kinds on a child are ordinary arrivals and departures.
    #[test]
    fn removing_or_renaming_a_child_is_forwarded() {
        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Folder),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
        ] {
            assert_eq!(
                to_watch_event(&inbox(), event(kind, &[request()])),
                Some(WatchEvent::Paths(vec![request()])),
                "{kind:?} on a child should be forwarded"
            );
        }
    }

    /// Only a removal or rename of the inbox is a self-event: anything else
    /// naming it is forwarded, and `admit`'s name check ignores it.
    #[test]
    fn other_events_on_the_inbox_are_forwarded() {
        for kind in [
            EventKind::Create(CreateKind::Folder),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
        ] {
            assert_eq!(
                to_watch_event(&inbox(), event(kind, &[inbox()])),
                Some(WatchEvent::Paths(vec![inbox()])),
                "{kind:?} on the inbox should be forwarded"
            );
        }
    }

    #[test]
    fn only_need_rescan_skips_the_rebind() {
        assert!(!RescanReason::NeedRescan.needs_rebind());
        assert!(RescanReason::WatchError("boom".to_string()).needs_rebind());
        assert!(RescanReason::InboxReplaced.needs_rebind());
    }
}
