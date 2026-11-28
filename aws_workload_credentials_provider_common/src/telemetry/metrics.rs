//! Lock-free metric primitives shared by the telemetry capabilities.
//!
//! Recording is atomic operations on slots allocated at construction, so it
//! never allocates or locks. Each capability builds its own registry from these
//! primitives; a snapshot swaps counters and histograms to zero, reads gauges,
//! and produces wire [`Metric`]s.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// A monotonic counter, reset to zero when taken.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn incr(&self) {
        self.add(1);
    }
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    /// Takes the count as a wire metric and resets it to zero.
    pub fn take_metric(&self, name: &'static str) -> Metric {
        Metric::counter(name, self.take())
    }
    fn take(&self) -> u64 {
        self.0.swap(0, Ordering::Relaxed)
    }
}

/// A point-in-time value. Read, not reset, by the snapshot.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    pub fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
    /// Reads the value as a wire metric.
    pub fn metric(&self, name: &'static str) -> Metric {
        Metric::gauge(name, self.get())
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A cumulative latency histogram in milliseconds with fixed bucket bounds.
/// Taking it resets the buckets and sum. The sum is kept in microseconds so it
/// fits an atomic integer.
#[derive(Debug)]
pub struct CumulativeHistogram {
    bounds: &'static [f64],
    /// One slot per bound plus an overflow slot, so each observation
    /// increments exactly one slot. That keeps the snapshot lock-free and
    /// monotonic.
    counts: Vec<AtomicU64>,
    sum_us: AtomicU64,
}

impl CumulativeHistogram {
    pub fn new(bounds: &'static [f64]) -> Self {
        debug_assert!(
            bounds.windows(2).all(|w| w[0] < w[1]),
            "histogram bounds must ascend: {bounds:?}"
        );
        Self {
            bounds,
            // bounds.len() + 1: the extra slot is the overflow (`+Inf`) bucket.
            counts: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_us: AtomicU64::new(0),
        }
    }

    /// Records `value_ms` in the first bucket it is `<=`, or in the overflow
    /// slot, and adds it to the sum.
    pub fn observe(&self, value_ms: f64) {
        let i = self
            .bounds
            .iter()
            .position(|&b| value_ms <= b)
            .unwrap_or(self.bounds.len());
        self.counts[i].fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add((value_ms * 1000.0) as u64, Ordering::Relaxed);
    }

    /// Takes the histogram as a wire metric and resets it.
    pub fn take_metric(&self, name: &'static str) -> Metric {
        let (counts, sum, count) = self.take();
        Metric::histogram(name, self.bounds, counts, sum, count)
    }

    /// Resets all state and returns the cumulative count per bound, the sum in
    /// ms, and the total count (the implicit `+Inf` bucket).
    ///
    /// `count` comes from the same cumulative pass, not a separate atomic, so
    /// the counts stay non-decreasing and `count >= counts.last()` under
    /// concurrent `observe`.
    fn take(&self) -> (Vec<u64>, f64, u64) {
        let mut cumulative = 0u64;
        let mut counts: Vec<u64> = self
            .counts
            .iter()
            .map(|c| {
                cumulative += c.swap(0, Ordering::Relaxed);
                cumulative
            })
            .collect();
        let sum_ms = self.sum_us.swap(0, Ordering::Relaxed) as f64 / 1000.0;
        // The last cumulative entry includes the overflow slot, so it is the
        // total. Pop it so `counts` matches `bounds` 1:1. It always exists (see
        // `new`).
        let count = counts.pop().unwrap_or(0);
        (counts, sum_ms, count)
    }
}

/// A closed set of values for one metric dimension, implemented on a fieldless
/// enum. Each value gets its own pre-allocated slot, and only its `as_str()`
/// value can appear on the wire.
pub trait Label: Copy + Debug + 'static {
    /// Wire key of the dimension, e.g. `reason`.
    const KEY: &'static str;
    /// Every value, in slot order: `ALL[v.index()] == v`.
    const ALL: &'static [Self];
    /// This value's slot.
    fn index(self) -> usize;
    /// Wire value of this dimension value.
    fn as_str(self) -> &'static str;
}

/// Checks the [`Label`] contract once, at construction, in debug builds: every
/// value's `index()` is its position in `ALL`, and no two values share a wire
/// value.
fn debug_check_label<L: Label>() {
    for (i, value) in L::ALL.iter().enumerate() {
        debug_assert_eq!(value.index(), i, "Label ALL/index mismatch for {value:?}");
        for earlier in &L::ALL[..i] {
            debug_assert_ne!(
                earlier.as_str(),
                value.as_str(),
                "duplicate Label wire value for {value:?}"
            );
        }
    }
}

/// The slot for `label`. A value missing from `ALL`, or one whose `index()`
/// points at another value's slot, is a broken `Label` impl: caught in debug
/// builds, and in release either a no-op or a count under the wrong value.
fn slot<L: Label, T>(slots: &[T], label: L) -> Option<&T> {
    let i = label.index();
    debug_assert!(
        L::ALL.get(i).is_some_and(|v| v.as_str() == label.as_str()),
        "{label:?} has no slot in Label::ALL"
    );
    slots.get(i)
}

/// A counter with one slot per value of a [`Label`].
#[derive(Debug)]
pub struct LabeledCounter<L: Label> {
    slots: Box<[Counter]>,
    _label: PhantomData<L>,
}

impl<L: Label> Default for LabeledCounter<L> {
    fn default() -> Self {
        debug_check_label::<L>();
        Self {
            slots: L::ALL.iter().map(|_| Counter::default()).collect(),
            _label: PhantomData,
        }
    }
}

impl<L: Label> LabeledCounter<L> {
    pub fn incr(&self, label: L) {
        self.add(label, 1);
    }
    pub fn add(&self, label: L, n: u64) {
        if let Some(counter) = slot(&self.slots, label) {
            counter.add(n);
        }
    }
    /// Returns one metric per label value, zero included, and resets every slot.
    pub fn take_metrics(&self, name: &'static str) -> Vec<Metric> {
        L::ALL
            .iter()
            .zip(self.slots.iter())
            .map(|(label, counter)| counter.take_metric(name).with_label(L::KEY, label.as_str()))
            .collect()
    }
}

/// A [`CumulativeHistogram`] with one slot per value of a [`Label`].
#[derive(Debug)]
pub struct LabeledHistogram<L: Label> {
    slots: Box<[CumulativeHistogram]>,
    _label: PhantomData<L>,
}

impl<L: Label> LabeledHistogram<L> {
    pub fn new(bounds: &'static [f64]) -> Self {
        debug_check_label::<L>();
        Self {
            slots: L::ALL
                .iter()
                .map(|_| CumulativeHistogram::new(bounds))
                .collect(),
            _label: PhantomData,
        }
    }
    pub fn observe(&self, label: L, value_ms: f64) {
        if let Some(histogram) = slot(&self.slots, label) {
            histogram.observe(value_ms);
        }
    }
    /// Returns one metric per label value, zero included, and resets every slot.
    pub fn take_metrics(&self, name: &'static str) -> Vec<Metric> {
        L::ALL
            .iter()
            .zip(self.slots.iter())
            .map(|(label, histogram)| {
                histogram
                    .take_metric(name)
                    .with_label(L::KEY, label.as_str())
            })
            .collect()
    }
}

/// A metric on the wire: name, typed value and dimensions. Only the primitives
/// above build one, so names are static and dimension values come from a
/// [`Label`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Metric {
    name: &'static str,
    #[serde(flatten)]
    value: MetricValue,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    dimensions: BTreeMap<&'static str, &'static str>,
}

/// The typed value of a [`Metric`], tagged by `type` on the wire.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MetricValue {
    Counter {
        value: u64,
    },
    Gauge {
        value: u64,
    },
    /// `buckets` are the finite upper bounds and `counts[i]` is the cumulative
    /// number of observations `<= buckets[i]`. `count` is the total, the
    /// implicit `+Inf` bucket. `sum` is the total in ms. An observation during
    /// a snapshot can land its count and sum in different snapshots, so they
    /// agree only summed across snapshots.
    Histogram {
        buckets: Vec<f64>,
        counts: Vec<u64>,
        sum: f64,
        count: u64,
    },
}

impl Metric {
    fn counter(name: &'static str, value: u64) -> Self {
        Self::new(name, MetricValue::Counter { value })
    }
    fn gauge(name: &'static str, value: u64) -> Self {
        Self::new(name, MetricValue::Gauge { value })
    }
    fn histogram(
        name: &'static str,
        bounds: &[f64],
        counts: Vec<u64>,
        sum: f64,
        count: u64,
    ) -> Self {
        Self::new(
            name,
            MetricValue::Histogram {
                buckets: bounds.to_vec(),
                counts,
                sum,
                count,
            },
        )
    }
    fn new(name: &'static str, value: MetricValue) -> Self {
        Self {
            name,
            value,
            dimensions: BTreeMap::new(),
        }
    }
    fn with_label(mut self, key: &'static str, value: &'static str) -> Self {
        self.dimensions.insert(key, value);
        self
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn value(&self) -> &MetricValue {
        &self.value
    }
    pub fn dimensions(&self) -> &BTreeMap<&'static str, &'static str> {
        &self.dimensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Reason {
        QueueFull,
        CircuitBreaker,
    }

    impl Label for Reason {
        const KEY: &'static str = "reason";
        const ALL: &'static [Self] = &[Self::QueueFull, Self::CircuitBreaker];
        fn index(self) -> usize {
            self as usize
        }
        fn as_str(self) -> &'static str {
            match self {
                Self::QueueFull => "queue_full",
                Self::CircuitBreaker => "circuit_breaker",
            }
        }
    }

    #[test]
    fn counter_adds_and_resets_on_take() {
        let c = Counter::default();
        c.incr();
        c.add(4);
        assert_eq!(c.take(), 5);
        assert_eq!(c.take(), 0);
    }

    #[test]
    fn gauge_reads_without_reset() {
        let g = Gauge::default();
        g.set(42);
        assert_eq!(g.get(), 42);
        assert_eq!(g.get(), 42);
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_reset() {
        let h = CumulativeHistogram::new(&[1.0, 10.0, 100.0]);
        h.observe(0.5); // <=1
        h.observe(7.0); // <=10
        h.observe(7.0); // <=10
        h.observe(5000.0); // above the last bound: overflow, counted only in `count`
        let (counts, sum, count) = h.take();
        assert_eq!(counts, vec![1, 3, 3]);
        assert_eq!(count, 4);
        assert_eq!(sum, 0.5 + 7.0 + 7.0 + 5000.0);
        let (counts, _, count) = h.take();
        assert_eq!(counts, vec![0, 0, 0]);
        assert_eq!(count, 0);
    }

    #[test]
    fn histogram_overflow_counts_toward_total_only() {
        let h = CumulativeHistogram::new(&[1.0, 10.0]);
        h.observe(0.5);
        h.observe(5000.0);
        let (counts, sum, count) = h.take();
        assert_eq!(counts, vec![1, 1]);
        assert_eq!(count, 2);
        assert_eq!(count - counts.last().unwrap(), 1);
        assert_eq!(sum, 0.5 + 5000.0);
    }

    #[test]
    fn histogram_stays_monotonic_under_concurrent_observe() {
        const PER_THREAD: u64 = 50_000;
        let hist = CumulativeHistogram::new(&[1.0, 10.0, 100.0]);
        let hist = &hist;
        let stop = AtomicBool::new(false);

        std::thread::scope(|s| {
            // Half the threads hit the first bucket, half overflow the last
            // bound, so `count` and the finite buckets diverge.
            let observers: Vec<_> = (0..4)
                .map(|t| {
                    let value = if t % 2 == 0 { 0.5 } else { 5000.0 };
                    s.spawn(move || {
                        for _ in 0..PER_THREAD {
                            hist.observe(value);
                        }
                    })
                })
                .collect();

            let taker = s.spawn(|| {
                let mut drained = 0u64;
                loop {
                    // Acquire pairs with the Release store after the observers
                    // join, so the final take sees every increment.
                    let done = stop.load(Ordering::Acquire);
                    let (counts, _sum, count) = hist.take();
                    assert!(
                        counts.windows(2).all(|w| w[0] <= w[1]),
                        "finite buckets must be non-decreasing: {counts:?}"
                    );
                    assert!(
                        count >= *counts.last().unwrap(),
                        "total (+Inf) must be >= last finite bucket: count={count}, {counts:?}"
                    );
                    drained += count;
                    if done {
                        break;
                    }
                }
                drained
            });

            for observer in observers {
                observer.join().unwrap();
            }
            stop.store(true, Ordering::Release);
            // Every observation is counted exactly once across all snapshots.
            assert_eq!(taker.join().unwrap(), 4 * PER_THREAD);
        });
    }

    #[test]
    fn labeled_counter_emits_every_value_including_zero_and_resets() {
        let c = LabeledCounter::<Reason>::default();
        c.add(Reason::QueueFull, 3);
        let json = serde_json::to_value(c.take_metrics("drops")).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                { "name": "drops", "type": "counter", "value": 3,
                  "dimensions": { "reason": "queue_full" } },
                { "name": "drops", "type": "counter", "value": 0,
                  "dimensions": { "reason": "circuit_breaker" } },
            ])
        );
        let after: Vec<u64> = c
            .take_metrics("drops")
            .iter()
            .map(|m| match m.value() {
                MetricValue::Counter { value } => *value,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(after, vec![0, 0]);
    }

    #[test]
    fn labeled_histogram_records_per_value() {
        let h = LabeledHistogram::<Reason>::new(&[1.0, 10.0]);
        h.observe(Reason::CircuitBreaker, 7.0);
        let metrics = h.take_metrics("latency");
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].dimensions()["reason"], "queue_full");
        assert_eq!(
            *metrics[0].value(),
            MetricValue::Histogram {
                buckets: vec![1.0, 10.0],
                counts: vec![0, 0],
                sum: 0.0,
                count: 0
            }
        );
        assert_eq!(metrics[1].dimensions()["reason"], "circuit_breaker");
        assert_eq!(
            *metrics[1].value(),
            MetricValue::Histogram {
                buckets: vec![1.0, 10.0],
                counts: vec![0, 1],
                sum: 7.0,
                count: 1
            }
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "histogram bounds must ascend")]
    fn descending_bounds_are_caught_in_debug() {
        let _ = CumulativeHistogram::new(&[10.0, 1.0]);
    }

    /// A hand-written `Label` that leaves `B` out of `ALL`.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum MissingValue {
        A,
        B,
    }

    impl Label for MissingValue {
        const KEY: &'static str = "k";
        const ALL: &'static [Self] = &[MissingValue::A];
        fn index(self) -> usize {
            self as usize
        }
        fn as_str(self) -> &'static str {
            match self {
                MissingValue::A => "a",
                MissingValue::B => "b",
            }
        }
    }

    /// A hand-written `Label` that lists a value twice.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Duplicated {
        A,
    }

    impl Label for Duplicated {
        const KEY: &'static str = "k";
        const ALL: &'static [Self] = &[Duplicated::A, Duplicated::A];
        fn index(self) -> usize {
            self as usize
        }
        fn as_str(self) -> &'static str {
            "a"
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "has no slot")]
    fn value_missing_from_all_is_caught_in_debug() {
        LabeledCounter::<MissingValue>::default().incr(MissingValue::B);
    }

    /// A hand-written `Label` whose missing value `B` points at `A`'s slot.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Aliased {
        A,
        B,
    }

    impl Label for Aliased {
        const KEY: &'static str = "k";
        const ALL: &'static [Self] = &[Aliased::A];
        fn index(self) -> usize {
            0
        }
        fn as_str(self) -> &'static str {
            match self {
                Aliased::A => "a",
                Aliased::B => "b",
            }
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "has no slot")]
    fn value_aliased_to_another_slot_is_caught_in_debug() {
        LabeledCounter::<Aliased>::default().incr(Aliased::B);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ALL/index mismatch")]
    fn duplicate_value_in_all_is_caught_in_debug() {
        let _ = LabeledCounter::<Duplicated>::default();
    }

    /// A hand-written `Label` whose distinct values share one wire value.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum SameWire {
        A,
        B,
    }

    impl Label for SameWire {
        const KEY: &'static str = "k";
        const ALL: &'static [Self] = &[SameWire::A, SameWire::B];
        fn index(self) -> usize {
            self as usize
        }
        fn as_str(self) -> &'static str {
            "same"
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "duplicate Label wire value")]
    fn duplicate_wire_value_is_caught_in_debug() {
        let _ = LabeledCounter::<SameWire>::default();
    }

    #[test]
    fn unlabeled_metric_omits_dimensions() {
        let json = serde_json::to_value(Metric::counter("requests", 1)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "name": "requests", "type": "counter", "value": 1 })
        );
    }
}
