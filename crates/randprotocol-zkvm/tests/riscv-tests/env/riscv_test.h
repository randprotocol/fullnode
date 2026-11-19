/* The Rand zkVM's environment for riscv-tests (ZKVM-118), in place of the suite's own `env/p`.
 *
 * The official environment boots through machine-mode CSRs and reports through `tohost`; this
 * machine has neither. Only the frame around a test changes — where it starts and how it says
 * pass or fail. The test bodies (`isa/rv64ui/*.S`, `isa/rv64um/*.S`, through their `rv32ui` /
 * `rv32um` wrappers) and `isa/macros/scalar/test_macros.h` are upstream's, unmodified.
 *
 *   pass: WRITE_OUTPUT(slot 0, 1), HALT          -> outputs = [1, 0, 0, ...]
 *   fail: WRITE_OUTPUT(slot 1, TESTNUM), HALT    -> outputs = [0, n, 0, ...], n the failing case
 *
 * `a7` is loaded last before each `ecall`, which is the shape `rand-guest check` resolves. */
#ifndef RAND_RISCV_TEST_H
#define RAND_RISCV_TEST_H

#define RVTEST_RV32U
#define RVTEST_RV64U
#define TESTNUM gp

#define RVTEST_CODE_BEGIN \
    .section .text._start, "ax", @progbits; \
    .globl _start; \
_start:

#define RVTEST_CODE_END

#define RVTEST_PASS \
    li a0, 0; \
    li a1, 1; \
    li a7, 1; \
    ecall; \
    li a7, 0; \
    ecall; \
1:  j 1b

#define RVTEST_FAIL \
    li a0, 1; \
    mv a1, TESTNUM; \
    li a7, 1; \
    ecall; \
    li a7, 0; \
    ecall; \
1:  j 1b

#define RVTEST_DATA_BEGIN
#define RVTEST_DATA_END

#endif
