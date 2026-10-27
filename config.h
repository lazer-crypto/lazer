/*
 * TARGET: GENERIC, AMD64
 * Architecture target. Defaults to AMD64 on x86-64 and to the portable
 * GENERIC code paths elsewhere (e.g. arm64).
 */
#ifndef TARGET
#if defined(__x86_64__) || defined(_M_X64)
#define TARGET TARGET_AMD64
#else
#define TARGET TARGET_GENERIC
#endif
#endif

/*
 * RNG: SHAKE128, AES256CTR
 * Use Shake128 or AES-256-CTR for pseudorandom generation.
 */
#define RNG RNG_AES256CTR

/*
 * ASSERT: ENABLED, DISABLED
 * Enable or diasble assertions.
 */
#define ASSERT ASSERT_DISABLED

/*
 * TIMERS: ENABLED, DISABLED
 * Run timers and print the results.
 */
#define TIMERS TIMERS_DISABLED

/*
 * DEBUGINFO: ENABLED, DISABLED
 * Print out debug information.
 */
#define DEBUGINFO DEBUGINFO_DISABLED

/*
 * VALGRIND: ENABLED, DISABLED
 * Build and run valgrind tests.
 * Requires valgrind installation.
 * Requires ASSERT_DISABLED
 */
#define VALGRIND VALGRIND_DISABLED
