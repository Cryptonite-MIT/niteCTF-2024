#include <unistd.h>
#include <syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>

// System structure
/*
    registers - 1 byte
        normal: a,b,c,d
        instruction pointer: i
        flags: f
    code - 0x7f bytes
    memory - 0x7f bytes
*/

typedef struct main_state {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
    uint8_t f;
    int8_t i;
    uint8_t memory[0x100];
    uint8_t code[0x80];
} main_state;

enum reg_code {
    REG_A = 0xe1,
    REG_B = 0xe2,
    REG_C = 0xe3,
    REG_D = 0xe4,
    REG_I = 0xfe,
    REG_F = 0xfd
};

/* Needs to be single digit numbers < 8 */
enum flag_code {
    FLAG_TR = 0,
    FLAG_EQ = 1,
    FLAG_NE = 2,
    FLAG_GT = 3,
    FLAG_LT = 4,
    FLAG_ZE = 5
};

enum sys_code {
    CUS_SYS_OPEN  = 0x23,
    CUS_SYS_READ  = 0x2d,
    CUS_SYS_WRITE = 0x2e,
    CUS_SYS_EXIT  = 0x25
};

enum op_code {
    OPCODE_LD_REG_COD = 0x28,
    OPCODE_LD_REG_MEM = 0x2a,
    OPCODE_ST_REG_MEM = 0x24,
    OPCODE_CMP        = 0x22,
    OPCODE_JMP        = 0x2b,
    OPCODE_SYS        = 0xff,
    OPCODE_NOP        = 0x91,
    OPCODE_MOV        = 0xaa,
    OPCODE_ADD        = 0x30,
    OPCODE_SUB        = 0x20,
    OPCODE_MUL        = 0x5e,
    OPCODE_XOR        = 0xba,
    OPCODE_OR         = 0xb9,
    OPCODE_AND        = 0xbf,
    OPCODE_NOR        = 0x26,
    OPCODE_NAND       = 0x2c,
    OPCODE_SHL        = 0x5a,
    OPCODE_SHR        = 0x67,
    OPCODE_ROR        = 0x72,
    OPCODE_ROL        = 0x8f,
    OPCODE_INV        = 0x98,
    OPCODE_NUM        = 0xdd,
};

/*
    Helper functions
    Get Address
    Get register
    Crash
    Init - seccomp + flush
*/

void protect() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_read, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_write, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_open, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_exit, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_exit_group, 0);
    seccomp_load(ctx);
}

void init() {
    setvbuf(stdin, NULL, 2, 0);
	setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
}

// Crash for anything that doesn't follow
void crash() {
    syscall(SYS_exit, 1);
}


/* Store values to registers */
void store_register(main_state* main_state, uint8_t register_code, uint8_t value) {
    switch(register_code) {
        case REG_A:
            main_state->a = value;
            break;
        case REG_B:
            main_state->b = value;
            break;
        case REG_C:
            main_state->c = value;
            break;
        case REG_D:
            main_state->d = value;
            break;
        default:
            crash();
    }
}

/* Get value in register */
uint8_t get_register(main_state* main_state, uint8_t register_code) {
    switch(register_code) {
        case REG_A:
            return main_state->a;
        case REG_B:
            return main_state->b;
        case REG_C:
            return main_state->c;
        case REG_D:
            return main_state->d;
        default:
            crash();
    }
}

/* Check flag value  */
bool check_flag(main_state* main_state, uint8_t flag_value) {
    switch(flag_value) {
        case FLAG_TR:
            return true;
        case FLAG_EQ:
            return main_state->f & (1 << FLAG_EQ);
        case FLAG_GT:
            return main_state->f & (1 << FLAG_GT);
        case FLAG_LT:
            return main_state->f & (1 << FLAG_LT);
        case FLAG_NE:
            return main_state->f & (1 << FLAG_NE);
        case FLAG_ZE:
            return main_state->f & (1 << FLAG_ZE);
        default:
            crash();
    }
}
/* Store value at address in memory */
void store_memory(main_state* main_state, uint8_t addr, uint8_t value) {
    if (addr >= sizeof(main_state->memory)) {
        crash();
    }
    main_state->memory[addr] = value;
}

/* Get value at address in memory */
uint8_t get_memory(main_state* main_state, uint8_t addr) {
    if (addr >= sizeof(main_state->memory)) {
        crash();
    }
    return main_state->memory[addr];
}

uint8_t* get_memory_pointer(main_state* main_state, uint8_t addr) {
    if (addr >= sizeof(main_state->memory)) {
        crash();
    }
    return &(main_state->memory[addr]);
}

/* Compare two registers and update the flag accordingly */
void compare_flag(main_state* main_state, uint8_t val_1, uint8_t val_2) {
    main_state->f = 0;
    if (val_1 == val_2) {
        main_state->f |= 1 << FLAG_EQ;
    }
    if (val_1 > val_2) {
        main_state->f |= 1 << FLAG_GT;
    }
    if (val_1 < val_2) {
        main_state->f |= 1 << FLAG_LT;
    }
    if (val_1 != val_2) {
        main_state->f |= 1 << FLAG_NE;
    }
    if (!val_1 && !val_2) {
        main_state->f |= 1 << FLAG_ZE;
    }
}


void jump_flag_register(main_state* main_state, uint8_t flag, uint8_t reg_addr) {
    if (check_flag(main_state, flag)){
        main_state->i = get_register(main_state, reg_addr);
    }
}

void interpret_open(main_state* main_state) {
    uint8_t addr_register = get_register(main_state, REG_A);
    uint8_t* pathname = get_memory_pointer(main_state, addr_register);
    uint8_t fd = syscall(SYS_open, pathname, O_RDONLY);
    store_register(main_state, REG_A, fd);
}

void interpret_read(main_state* main_state) {
    uint8_t fd = get_register(main_state, REG_A);
    uint8_t addr_register = get_register(main_state, REG_B);
    uint8_t* memory = get_memory_pointer(main_state, addr_register);
    uint8_t count = get_register(main_state, REG_C);
    uint8_t output = syscall(SYS_read, fd, memory, count);
    store_register(main_state, REG_A, output);
}

void interpret_write(main_state* main_state){
    uint8_t fd = get_register(main_state, REG_A);
    uint8_t addr_register = get_register(main_state, REG_B);
    uint8_t* memory = get_memory_pointer(main_state, addr_register);
    uint8_t count = get_register(main_state, REG_C);
    uint8_t output = syscall(SYS_write, fd, memory, count);
    store_register(main_state, REG_A, output);
}

void interpret_exit(main_state* main_state) {
    uint8_t exit_code = get_register(main_state, REG_A);
    syscall(SYS_exit, exit_code);
}



// Opcode functions
/*
    LOAD FROM CODE
    LOAD FROM MEMORY
    STORE TO MEMORY
    COMPARE REGISTERS
        flag -> EQ, NE, GE, LE, GT, LT
    JUMP FLAG
        flag -> EQ, NE, GE, LE, GT, LT
    NOP
    ADD
    SUB
    XOR
    XNOR
    SHR
    SHL
    NOR
    NAND
    OR
    AND
    SYSCALL
        - open
        - read
        - write
        - exit
*/

void load_register_from_code(main_state* main_state) {
    uint8_t reg_code = main_state->code[main_state->i++];
    uint8_t value = main_state->code[main_state->i++];
    store_register(main_state, reg_code, value);
}

void load_register_from_memory(main_state* main_state) {
    uint8_t reg_code = main_state->code[main_state->i++];
    uint8_t address = main_state->code[main_state->i++];
    uint8_t value = get_memory(main_state, address);
    store_register(main_state, reg_code, value);
}

void store_register_to_memory(main_state* main_state) {
    uint8_t reg_code = main_state->code[main_state->i++];
    uint8_t address = main_state->code[main_state->i++];
    uint8_t value = get_register(main_state, reg_code);
    store_memory(main_state, address, value);
}

void compare_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    compare_flag(main_state, val_1, val_2);
}

void jump_on_flag(main_state* main_state) {
    uint8_t flag_value = main_state->code[main_state->i++];
    uint8_t address = main_state->code[main_state->i++];
    jump_flag_register(main_state, flag_value, address);
}

/* Hahahahaha NOP Hahahahahha */
void nop(main_state* main_state) {
    return;
}

void custom_sys(main_state* main_state) {
    uint8_t sys_code = main_state->code[main_state->i++];
    switch(sys_code) {
        case CUS_SYS_OPEN:
            interpret_open(main_state);
            break;
        case CUS_SYS_READ:
            interpret_read(main_state);
            break;
        case CUS_SYS_WRITE:
            interpret_write(main_state);
            break;
        case CUS_SYS_EXIT:
            interpret_exit(main_state);
            break;
        default:
            crash();
    }
}

void mov_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, val_2);
}

void add_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    int8_t val_1 = (int8_t)get_register(main_state, reg_1);
    int8_t val_2 = (int8_t)get_register(main_state, reg_2);
    store_register(main_state, reg_1, (uint8_t)(val_1 + val_2));
}

void sub_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = (int8_t)get_register(main_state, reg_1);
    uint8_t val_2 = (int8_t)get_register(main_state, reg_2);
    store_register(main_state, reg_1, (uint8_t)(val_1 - val_2));
}

void mul_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    int8_t val_1 = (int8_t)get_register(main_state, reg_1);
    int8_t val_2 = (int8_t)get_register(main_state, reg_2);
    store_register(main_state, reg_1, (uint8_t)(val_1 * val_2));
}

void xor_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, val_1 ^ val_2);
}

void shr_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, val_1 >> val_2);
}

void shl_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, val_1 << val_2);
}

void inv_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    store_register(main_state, reg_1, -1 * ( val_1 % 255 ) - 1);
}

// Rotate right (ROR)
void ror_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    val_2 &= 0x07;
    store_register(main_state, reg_1, (val_1 >> val_2) | (val_1 << (8 - val_2)));
}

// Rotate left (ROL)
void rol_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    val_2 &= 0x07;
    store_register(main_state, reg_1, (val_1 << val_2) | (val_1 >> (8 - val_2)));
}


void nor_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, ~(val_1 | val_2));
}

void nand_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, ~(val_1 & val_2));
}

void or_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, (val_1 | val_2));
}

void and_registers(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t reg_2 = main_state->code[main_state->i++];
    uint8_t val_1 = get_register(main_state, reg_1);
    uint8_t val_2 = get_register(main_state, reg_2);
    store_register(main_state, reg_1, (val_1 & val_2));
}

void interpret_number(main_state* main_state) {
    uint8_t reg_1 = main_state->code[main_state->i++];
    uint8_t address = main_state->code[main_state->i++];
    uint8_t* pointer = get_memory_pointer(main_state, address);
    // Change to use signed int before converting to uint8_t
    store_register(main_state, reg_1, (uint8_t)((int8_t)atoi(pointer)));
}

// Opcode switch-case
void opcode_run(main_state* main_state, uint8_t opcode) {
    switch(opcode) {
        case OPCODE_LD_REG_COD:
            load_register_from_code(main_state);
            break;
        case OPCODE_LD_REG_MEM:
            load_register_from_memory(main_state);
            break;
        case OPCODE_ST_REG_MEM:
            store_register_to_memory(main_state);
            break;
        case OPCODE_CMP:
            compare_registers(main_state);
            break;
        case OPCODE_JMP:
            jump_on_flag(main_state);
            break;
        case OPCODE_SYS:
            custom_sys(main_state);
            break;
        case OPCODE_MOV:
            mov_registers(main_state);
            break;
        case OPCODE_ADD:
            add_registers(main_state);
            break;
        case OPCODE_SUB:
            sub_registers(main_state);
            break;
        case OPCODE_MUL:
            mul_registers(main_state);
            break;
        case OPCODE_NOP:
            nop(main_state);
            break;
        case OPCODE_OR:
            or_registers(main_state);
            break;
        case OPCODE_AND:
            and_registers(main_state);
            break;
        case OPCODE_NOR:
            nor_registers(main_state);
            break;
        case OPCODE_NAND:
            nand_registers(main_state);
            break;
        case OPCODE_SHL:
            shl_registers(main_state);
            break;
        case OPCODE_SHR:
            shr_registers(main_state);
            break;
        case OPCODE_ROL:
            rol_registers(main_state);
            break;
        case OPCODE_ROR:
            ror_registers(main_state);
            break;
        case OPCODE_INV:
            inv_registers(main_state);
            break;
        case OPCODE_NUM:
            interpret_number(main_state);
            break;
        default:
            crash();
    }
}

// Main loop

void interpreter_loop(main_state* main_state) {
    while(true) {
        uint8_t opcode = main_state->code[main_state->i++];
        opcode_run(main_state, opcode);
    }
}

// Memory layout:
uint8_t vm_mem[] = {
    0x63, 0x68, 0x6f, 0x6f, 0x73, 0x65, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x70, 0x61, 0x74, 0x68, 0x20, 0x28, 0x30, 0x2d, 0x33, 0x29, 0x3a, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x77, 0x61, 0x73, 0x20, 0x61, 0x20, 0x67, 0x61, 0x74, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x77, 0x69, 0x73, 0x68, 0x65, 0x73, 0x0a, 0x61, 0x20, 0x67, 0x61, 0x74, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x77, 0x69, 0x73, 0x68, 0x65, 0x73, 0x3a, 0x20, 0x73, 0x61, 0x64, 0x6c, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x61, 0x74, 0x65, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6c, 0x6f, 0x73, 0x74, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x73, 0x74, 0x0a, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x77, 0x20, 0x77, 0x65, 0x20, 0x65, 0x78, 0x69, 0x74, 0x2e, 0x2e, 0x2e, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Main loop// Program code:
uint8_t vm_code[] = {
    0x28, 0xe1, 0x01,      // Load stdout (1) into register A,
    0x28, 0xe2, 0x00,      // Load address of 'choice prompt' into register B,
    0x28, 0xe3, 0x18,      // Load length 24 into register C,
    0xff, 0x2e,            // Write syscall to print 'choice prompt',
    0x28, 0xe1, 0x00,      // Load stdin (0) into register A,
    0x28, 0xe2, 0x98,      // Load input buffer address (0x50) into register B,
    0x28, 0xe3, 0x02,      // Load read length (2 bytes) into register C,
    0xff, 0x2d,            // Read syscall to get user input,
    0xdd, 0xe1, 0x98,      // Convert string at 0x50 to integer,
    0x28, 0xe2, 0x19,      // a
    0x5e, 0xe1, 0xe2,      // MUL B with A save A
    0x28, 0xe2, 0x28,      // b
    0x30, 0xe1, 0xe2,      // Add B to A    
    0x2b, 0x00, 0xe1,
    // a switch case knockoff using ax+b


    // case 0
    0x28, 0xe1, 0x01,      // Load stdout (1) into register A,
    0x28, 0xe2, 0x18,      // Load address of 'path zero message' into register B,
    0x28, 0xe3, 0x28,      // Load length 40 into register C,
    0xff, 0x2e,            // Write syscall to print 'path zero message',
    0x2b, 0x00, 0xe4,      // Jump back to start for choice

    0x91, 0x91, 0x91,      // NOP sled
    0x91, 0x91, 0x91,
    0x91, 0x91, 0x91,
    0x91, 0x91,

    // case 1
    0x28, 0xe1, 0x01,      // Load stdout (1) into register A,
    0x28, 0xe2, 0x40,      // Load address of 'path one message' into register B,
    0x28, 0xe3, 0x1d,      // Load length 29 into register C,
    0xff, 0x2e,            // Write syscall to print 'path one message',

    0x28, 0xe1, 0x00,      // Load stdin (0) into register A,
    0x28, 0xe2, 0xa0,      // Load input buffer address (0x00) into register B,
    0x28, 0xe3, 0x60,      // Load read length into register C,
    0xff, 0x2d,            // Read syscall to get user input,
    0x2b, 0x00, 0xe4,      // Jump back to start for choice



    // case 2
    0x28, 0xe1, 0x01,      // Load stdout (1) into register A,
    0x28, 0xe2, 0x5d,      // Load address of 'path two message' into register B,
    0x28, 0xe3, 0x27,      // Load length 39 into register C,
    0xff, 0x2e,            // Write syscall to print 'path two message',
    0x2b, 0x00, 0xe4,      // Jump back to start for choice

    0x91, 0x91, 0x91,      // NOP sled
    0x91, 0x91, 0x91,
    0x91, 0x91, 0x91,
    0x91, 0x91,

    // case 3
    0x28, 0xe1, 0x01,      // Load stdout (1) into register A,
    0x28, 0xe2, 0x84,      // Load address of 'path three message' into register B,
    0x28, 0xe3, 0x13,      // Load length 19 into register C,
    0xff, 0x2e,            // Write syscall to print 'path three message',
    0xff, 0x25             // Exit syscall to terminate program
};

int main() {
    init();
    protect();
    main_state the_state;
    memset(&the_state, 0, sizeof(the_state));
    memcpy(the_state.code, vm_code, sizeof(vm_code));
    memcpy(the_state.memory, vm_mem, sizeof(vm_mem));
    interpreter_loop(&the_state);
    syscall(SYS_exit, 0);
}
