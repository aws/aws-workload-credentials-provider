//! Bounded, drop-oldest in-memory queue for telemetry records.
//!
//! The queue is bounded by item count and by total byte weight, since items
//! vary widely in size. When either bound is exceeded it evicts the oldest
//! items instead of blocking, so a stalled drain never blocks producers or
//! grows memory without bound. `push` returns what it evicts so the caller can
//! count it.
//!
//! A `std::sync::Mutex`, not a tokio one, guards the data. It is never held
//! across an `.await` or during I/O, so blocking on it briefly can't stall the
//! async runtime, and a blocking `lock()`, unlike `try_lock`, doesn't drop
//! records under contention.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// A FIFO queue bounded by item count and total byte weight that evicts the
/// oldest items when full.
///
/// Every method takes `&self`, so share it as `Arc<BoundedQueue<T>>`. A
/// poisoned lock is recovered, not propagated, so telemetry never crashes the
/// agent.
#[derive(Debug)]
pub struct BoundedQueue<T> {
    max_events: usize,
    max_bytes: usize,
    /// Byte weight of an item, for the `max_bytes` bound. It must return the
    /// same value for an item at push and at removal, or the running total
    /// drifts.
    weight: fn(&T) -> usize,
    inner: Mutex<Inner<T>>,
}

#[derive(Debug)]
struct Inner<T> {
    items: VecDeque<T>,
    /// Sum of `weight` over `items`, kept up to date so `push` stays O(1).
    bytes: usize,
}

impl<T> BoundedQueue<T> {
    /// Creates a queue of at most `max_events` items and `max_bytes` total
    /// weight, sizing each item with `weight`. The bounds are `NonZeroUsize`
    /// because a zero bound would drop every item.
    pub fn new(max_events: NonZeroUsize, max_bytes: NonZeroUsize, weight: fn(&T) -> usize) -> Self {
        Self {
            max_events: max_events.get(),
            max_bytes: max_bytes.get(),
            weight,
            inner: Mutex::new(Inner {
                items: VecDeque::new(),
                bytes: 0,
            }),
        }
    }

    /// Enqueues `item`, then evicts the oldest items until the queue fits within
    /// both bounds. Returns the evicted items (oldest first), empty if none.
    ///
    /// If `item` alone exceeds `max_bytes` it is dropped without enqueueing and
    /// returned as the sole element.
    pub fn push(&self, item: T) -> Vec<T> {
        let w = (self.weight)(&item);
        let mut inner = self.lock();

        // An item over `max_bytes` can never fit, so don't evict the queue for it.
        if w > self.max_bytes {
            return vec![item];
        }

        inner.items.push_back(item);
        inner.bytes += w;

        let mut evicted = Vec::new();
        while inner.items.len() > self.max_events || inner.bytes > self.max_bytes {
            // The new item fits on its own (checked above, and
            // max_events >= 1), so it always survives and the loop ends.
            let Some(old) = inner.items.pop_front() else {
                break;
            };
            inner.bytes -= (self.weight)(&old);
            evicted.push(old);
        }
        evicted
    }

    /// Removes and returns all queued items in FIFO order, leaving it empty.
    pub fn drain(&self) -> Vec<T> {
        let mut inner = self.lock();
        inner.bytes = 0;
        inner.items.drain(..).collect()
    }

    /// Removes and returns up to `n` items in FIFO order.
    pub fn drain_up_to(&self, n: usize) -> Vec<T> {
        let weight = self.weight;
        let mut inner = self.lock();
        let take = n.min(inner.items.len());
        let drained: Vec<T> = inner.items.drain(..take).collect();
        for item in &drained {
            inner.bytes -= weight(item);
        }
        drained
    }

    /// Hands the oldest item, if there is one, to `take`, and returns what
    /// `take` makes of it. When `take` gives the item back instead, it stays
    /// at the front, so it must be unchanged to keep its weight. `take` runs
    /// under the queue's lock, so it must be quick.
    pub fn take_front<U>(&self, take: impl FnOnce(T) -> Result<U, T>) -> Option<U> {
        let weight = self.weight;
        let mut inner = self.lock();
        let item = inner.items.pop_front()?;
        let item_weight = weight(&item);
        match take(item) {
            Ok(taken) => {
                inner.bytes -= item_weight;
                Some(taken)
            }
            Err(item) => {
                inner.items.push_front(item);
                None
            }
        }
    }

    /// Number of items currently queued.
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// Whether the queue is currently empty.
    pub fn is_empty(&self) -> bool {
        self.lock().items.is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        // Recover from poison: a panicked producer must not wedge telemetry.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    /// Weight 1, for testing the count bound.
    fn unit(_: &u64) -> usize {
        1
    }

    /// Weight equal to the item's value, for testing the byte bound.
    fn identity(n: &u64) -> usize {
        *n as usize
    }

    #[test]
    fn drains_in_fifo_order() {
        let q = BoundedQueue::new(nz(4), nz(1024), unit);
        assert!(q.push(1).is_empty());
        assert!(q.push(2).is_empty());
        assert!(q.push(3).is_empty());
        assert_eq!(q.len(), 3);
        assert_eq!(q.drain(), vec![1, 2, 3]);
        assert!(q.is_empty());
    }

    #[test]
    fn full_queue_drops_oldest() {
        let q = BoundedQueue::new(nz(3), nz(1024), unit);
        assert!(q.push(1).is_empty());
        assert!(q.push(2).is_empty());
        assert!(q.push(3).is_empty());
        // Full on count: next push evicts the oldest and returns it.
        assert_eq!(q.push(4), vec![1]);
        assert_eq!(q.push(5), vec![2]);
        assert_eq!(q.drain(), vec![3, 4, 5]); // newest kept
    }

    #[test]
    fn byte_bound_evicts_until_fit() {
        // max_bytes = 10, weight = value. Count bound is out of the way.
        let q = BoundedQueue::new(nz(100), nz(10), identity);
        assert!(q.push(4).is_empty()); // bytes 4
        assert!(q.push(4).is_empty()); // bytes 8
        assert_eq!(q.push(4), vec![4]); // bytes would be 12 > 10: evict oldest → 8
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn oversized_item_is_dropped_without_enqueue() {
        let q = BoundedQueue::new(nz(100), nz(10), identity);
        assert!(q.push(4).is_empty());
        // 20 > max_bytes (10): dropped outright, queue untouched.
        assert_eq!(q.push(20), vec![20]);
        assert_eq!(q.len(), 1);
        assert_eq!(q.drain(), vec![4]);
    }

    #[test]
    fn one_push_can_evict_several() {
        let q = BoundedQueue::new(nz(100), nz(10), identity);
        for _ in 0..4 {
            assert!(q.push(2).is_empty()); // total weight 8, all fit
        }
        // Pushing 8 (would be 16 > 10) evicts the oldest until it fits again.
        assert_eq!(q.push(8), vec![2, 2, 2]);
        assert_eq!(q.drain(), vec![2, 8]);
    }

    #[test]
    fn drain_up_to_updates_byte_total() {
        let q = BoundedQueue::new(nz(100), nz(10), identity);
        assert!(q.push(4).is_empty());
        assert!(q.push(4).is_empty());
        assert_eq!(q.drain_up_to(1), vec![4]);
        // 4 + 6 == 10 fits only if drain_up_to lowered the total, and a total
        // of exactly max_bytes fits.
        assert!(q.push(6).is_empty());
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn take_front_takes_the_oldest_only_when_asked_and_updates_the_byte_total() {
        let q = BoundedQueue::new(nz(100), nz(10), identity);
        assert!(q.push(3).is_empty());
        assert!(q.push(4).is_empty());
        let odd = |n: u64| if n % 2 == 1 { Ok(n * 10) } else { Err(n) };
        assert_eq!(q.take_front(odd), Some(30));
        // 4 + 6 == 10 fits only if taking 3 lowered the byte total to 4.
        assert!(q.push(6).is_empty());
        // Given back, 4 stays at the front.
        assert_eq!(q.take_front(odd), None);
        assert_eq!(q.drain(), vec![4, 6]);
        assert_eq!(q.take_front(Ok::<u64, u64>), None);
    }

    #[test]
    fn drain_up_to_takes_at_most_n_in_order() {
        let q = BoundedQueue::new(nz(8), nz(1024), unit);
        for i in 0..5 {
            q.push(i);
        }
        assert_eq!(q.drain_up_to(2), vec![0, 1]);
        assert_eq!(q.drain_up_to(10), vec![2, 3, 4]); // clamps to what's left
        assert!(q.is_empty());
    }

    #[test]
    fn concurrent_push_and_drain_conserve_every_item() {
        const PRODUCERS: u64 = 4;
        const PER_PRODUCER: u64 = 25_000;
        let q = Arc::new(BoundedQueue::new(nz(64), nz(1 << 20), unit));
        let stop = Arc::new(AtomicBool::new(false));

        let mut producers = Vec::new();
        for _ in 0..PRODUCERS {
            let q = Arc::clone(&q);
            producers.push(std::thread::spawn(move || {
                let mut dropped = 0u64;
                for _ in 0..PER_PRODUCER {
                    dropped += q.push(1u64).len() as u64;
                }
                dropped
            }));
        }

        let drainer = {
            let q = Arc::clone(&q);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut drained = 0u64;
                loop {
                    let done = stop.load(Ordering::Acquire);
                    drained += q.drain().len() as u64;
                    if done {
                        break;
                    }
                }
                drained
            })
        };

        let mut dropped = 0u64;
        for producer in producers {
            dropped += producer.join().unwrap();
        }
        stop.store(true, Ordering::Release);
        let drained = drainer.join().unwrap();

        // Each push is drained, dropped, or still queued, exactly once. The
        // drain after `stop` sees every push (join + Acquire).
        let remaining = q.len() as u64;
        assert_eq!(drained + dropped + remaining, PRODUCERS * PER_PRODUCER);
    }
}
