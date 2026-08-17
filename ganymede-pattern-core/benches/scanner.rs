//! Throughput coverage for representative fixed-width scanning workloads.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ganymede_pattern_core::{PatternBuf, PointerWidth, Scanner};
use std::hint::black_box;

/// One Criterion context while the pattern scanning benchmark suite is registered.
struct Suite<'criterion>(&'criterion mut Criterion);

impl<'criterion> Suite<'criterion> {
    /// Bind Criterion to the benchmark suite and register scanner workloads.
    fn run(target_criterion: &'criterion mut Criterion) {
        Self(target_criterion).scanner();
    }

    /// Benchmark literal, anchored, and masked-probe plans over the same one-megabyte haystack.
    fn scanner(self) {
        let Self(target_criterion) = self;
        let mut haystack = vec![0x90u8; 1024 * 1024];
        let insertion = haystack.len() - 128;

        haystack[insertion..insertion + 8]
            .copy_from_slice(&[0x48, 0x8b, 0x01, 0x02, 0x89, 0xab, 0xcd, 0xef]);

        let cases = [
            ("literal", "48 8B 01 02 89 AB CD EF"),
            ("anchor", "48 8B ? ? 89 ? ? EF"),
            ("masked", "4? ?B ? ? 8? ? ?D ?F"),
        ];
        let mut group = target_criterion.benchmark_group("scanner");

        group.throughput(Throughput::Bytes(haystack.len() as u64));

        for (name, source) in cases {
            let pattern = PatternBuf::parse(source).expect("benchmark pattern should parse");
            let scanner = Scanner::new(pattern.as_pattern(), PointerWidth::U64);

            group.bench_function(name, |target_bencher| {
                target_bencher.iter(|| scanner.find(black_box(&haystack)));
            });
        }

        group.finish();
    }
}

criterion_group!(benches, Suite::run);
criterion_main!(benches);
