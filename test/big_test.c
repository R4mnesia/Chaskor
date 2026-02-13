#include <stdio.h>
#include <stdint.h>

void test_zeroing() {
    int a;
    asm volatile (
        "xor %%eax, %%eax\n"   // xor reg, reg (zeroing)
        "mov %%eax, %0\n"
        : "=r"(a)
        :
        : "eax"
    );
}

void test_reg_reg() {
    int a = 0x11;
    int b = 0x22;

    asm volatile (
        "xor %%eax, %%ebx\n"   // xor reg, reg (mix)
        :
        : "a"(a), "b"(b)
    );
}

void test_reg_imm() {
    int a = 0x41;
    asm volatile (
        "xor $0x33, %%eax\n"   // xor reg, imm
        : "+a"(a)
    );
}

void test_mem_imm() {
    uint8_t buf[] = { 'H', 'e', 'l', 'l', 'o', 0 };

    for (int i = 0; buf[i]; i++) {
        buf[i] ^= 0x55;        // xor BYTE PTR [mem], imm
    }
}

void test_mem_reg() {
    uint8_t buf[] = { 'A', 'B', 'C', 'D', 0 };
    uint8_t key = 0x20;

    for (int i = 0; buf[i]; i++) {
        buf[i] ^= key;         // xor BYTE PTR [mem], reg
    }
}

void test_dword_mem() {
    uint32_t data = 0x11223344;
    data ^= 0xAABBCCDD;        // xor DWORD PTR [mem], imm
}

void test_qword_mem() {
    uint64_t data = 0x1122334455667788ULL;
    data ^= 0xCAFEBABECAFEBABEULL;  // xor QWORD PTR [mem], imm
}

void test_stack_mem() {
    uint32_t local = 0x12345678;
    local ^= 0xDEADBEEF;       // xor [rsp+off], imm
}

void test_pointer_xor() {
    uint8_t buf[] = "XOR STRING TEST";
    uint8_t *p = buf;

    while (*p) {
        *p ^= 0x13;            // xor [reg], imm
        p++;
    }
}

int main() {
    test_zeroing();
    test_reg_reg();
    test_reg_imm();
    test_mem_imm();
    test_mem_reg();
    test_dword_mem();
    test_qword_mem();
    test_stack_mem();
    test_pointer_xor();

    return 0;
}

