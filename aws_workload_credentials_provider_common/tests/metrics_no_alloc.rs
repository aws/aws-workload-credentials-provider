//! Checks that recording into the metric primitives never allocates. A
//! counting global allocator counts allocations on the current thread only, so
//! tests running in parallel don't disturb each other.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use aws_workload_credentials_provider_common::telemetry::{
    Counter, CumulativeHistogram, Gauge, Label, LabeledCounter, LabeledHistogram,
};

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations_during(f: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|n| n.set(0));
    COUNTING.with(|c| c.set(true));
    f();
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.with(Cell::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Hit,
    Miss,
}

impl Label for Outcome {
    const KEY: &'static str = "outcome";
    const ALL: &'static [Self] = &[Self::Hit, Self::Miss];
    fn index(self) -> usize {
        self as usize
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
}

#[test]
fn recording_never_allocates() {
    let counter = Counter::default();
    let gauge = Gauge::default();
    let histogram = CumulativeHistogram::new(&[1.0, 10.0]);
    let labeled_counter = LabeledCounter::<Outcome>::default();
    let labeled_histogram = LabeledHistogram::<Outcome>::new(&[1.0, 10.0]);

    // Positive control: the harness does see an allocation.
    assert!(allocations_during(|| drop(std::hint::black_box(Vec::<u8>::with_capacity(8)))) > 0);

    let allocations = allocations_during(|| {
        for _ in 0..1_000 {
            counter.incr();
            counter.add(2);
            gauge.set(7);
            histogram.observe(3.0);
            histogram.observe(5_000.0);
            labeled_counter.incr(Outcome::Hit);
            labeled_counter.add(Outcome::Miss, 2);
            labeled_histogram.observe(Outcome::Miss, 3.0);
        }
    });

    assert_eq!(allocations, 0);
}
