#ifndef __PERF_TEST_H__
#define __PERF_TEST_H__

// Run all rproto performance tests (throughput, latency, stress with noise,
// concurrent channels). Requires virtual ports /tmp/perf_emu{1..3}_{tx,rx}.
void run_perf_tests(void);

#endif  // __PERF_TEST_H__
