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
    int16_t i;
    uint8_t memory[0x100];
    uint8_t code[0x8000];
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

uint8_t input_code[] = {
    // Store "Enter flag: " in memory at address 0x20
    0x28, 0xe1, 0x45,      // 'E'
    0x24, 0xe1, 0x20,      // OPCODE_ST_REG_MEM: Store 'E' at memory address 0x20
    0x28, 0xe1, 0x6e,      // 'n'
    0x24, 0xe1, 0x21,      // OPCODE_ST_REG_MEM: Store 'n' at memory address 0x21
    0x28, 0xe1, 0x74,      // 't'
    0x24, 0xe1, 0x22,      // OPCODE_ST_REG_MEM: Store 't'
    0x28, 0xe1, 0x65,      // 'e'
    0x24, 0xe1, 0x23,      // OPCODE_ST_REG_MEM: Store 'e'
    0x28, 0xe1, 0x72,      // 'r'
    0x24, 0xe1, 0x24,      // OPCODE_ST_REG_MEM: Store 'r'
    0x28, 0xe1, 0x20,      // ' '
    0x24, 0xe1, 0x25,      // OPCODE_ST_REG_MEM: Store ' '
    0x28, 0xe1, 0x66,      // 'f'
    0x24, 0xe1, 0x26,      // OPCODE_ST_REG_MEM: Store 'f'
    0x28, 0xe1, 0x6c,      // 'l'
    0x24, 0xe1, 0x27,      // OPCODE_ST_REG_MEM: Store 'l'
    0x28, 0xe1, 0x61,      // 'a'
    0x24, 0xe1, 0x28,      // OPCODE_ST_REG_MEM: Store 'a'
    0x28, 0xe1, 0x67,      // 'g'
    0x24, 0xe1, 0x29,      // OPCODE_ST_REG_MEM: Store 'g'
    0x28, 0xe1, 0x3a,      // ':'
    0x24, 0xe1, 0x2a,      // OPCODE_ST_REG_MEM: Store ':'
    0x28, 0xe1, 0x20,      // ' '
    0x24, 0xe1, 0x2b,      // OPCODE_ST_REG_MEM: Store ' '


    0x28, 0xe1, 0x01,      // OPCODE_LD_REG_COD: Load 1 (stdout) into register A
    0x28, 0xe2, 0x20,      // OPCODE_LD_REG_COD: Load memory address 0x20 into register B
    0x28, 0xe3, 0xc,      // OPCODE_LD_REG_COD: Load 12 (length of "Enter flag: ") into register C
    0xff, 0x2e,            // OPCODE_SYS with CUS_SYS_WRITE

    // WRONG SECTION

    0x28, 0xe1, 0x69,      // 
    0x2b, 0x0, 0xe1,      // Skip if normal flow 86 87 88

    // INTO WRONG SECTION

    0x28, 0xe1, 0x01,      // OPCODE_LD_REG_COD: Load 1 (stdout) into register A
    0x28, 0xe2, 0x00,      // OPCODE_LD_REG_COD: Load memory address 0x20 into register B
    0x28, 0xe3, 0x06,      // OPCODE_LD_REG_COD: Load 12 (length of "Wrong\n") into register C
    0xff, 0x2e,            // OPCODE_SYS with CUS_SYS_WRITE

    0x28, 0xe1, 0x0,
    0xff, 0x25,          // EXIT

    // Read 34 characters input and store in memory
    0x28, 0xe1, 0x00,      // Load register A with the file descriptor (we will assume stdin is 0 for simplicity)
    0x28, 0xe2, 0xbf,      // Load register B with memory address 0x30 where the input will be stored
    0x28, 0xe3, 0x23,      // Load register C with 34 (number of characters to read)
    0xff, 0x2d,            // OPCODE_SYS with CUS_SYS_READ

    0x28, 0xe1, 0x43,      // Load 'C' into register A
    0x24, 0xe1, 0x10,      // Store 'C' at 10
    0x28, 0xe1, 0x6f,      // Load 'o' into register A
    0x24, 0xe1, 0x11,      // Store 'o' at 11
    0x28, 0xe1, 0x72,      // Load 'r' into register A
    0x24, 0xe1, 0x12,      // Store 'r' at 12
    0x28, 0xe1, 0x72,      // Load 'r' into register A
    0x24, 0xe1, 0x13,      // Store 'r' at 13
    0x28, 0xe1, 0x65,      // Load 'e' into register A
    0x24, 0xe1, 0x14,      // Store 'e' at 14
    0x28, 0xe1, 0x63,      // Load 'c' into register A
    0x24, 0xe1, 0x15,      // Store 'c' at 15
    0x28, 0xe1, 0x74,      // Load 't' into register A
    0x24, 0xe1, 0x16,      // Store 't' at 16
    0x28, 0xe1, 0x0a,      // Load '' into register A
    0x24, 0xe1, 0x17,      // Store '' at 17
    0x28, 0xe1, 0x57,      // Load 'W' into register A
    0x24, 0xe1, 0x00,      // Store 'W' at 00
    0x28, 0xe1, 0x72,      // Load 'r' into register A
    0x24, 0xe1, 0x01,      // Store 'r' at 01
    0x28, 0xe1, 0x6f,      // Load 'o' into register A
    0x24, 0xe1, 0x02,      // Store 'o' at 02
    0x28, 0xe1, 0x6e,      // Load 'n' into register A
    0x24, 0xe1, 0x03,      // Store 'n' at 03
    0x28, 0xe1, 0x67,      // Load 'g' into register A
    0x24, 0xe1, 0x04,      // Store 'g' at 04
    0x28, 0xe1, 0x0a,      // Load '\n' into register A
    0x24, 0xe1, 0x05,      // Store '\n' at 05


    0x2a, 0xe1, 0xbf,      // Load 0xbf into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xbf,      // Store e1 into 0xbf
    0x2a, 0xe1, 0xbf,      // Load memory address 0xbf into register 1
    0x28, 0xe2, 0x3f,      // Load the value 0x3f into register e2
    0x2a, 0xe3, 0xbf,      // Load memory address 0xbf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xbf,      // Store e1 into 0xbf
    0x2a, 0xe1, 0xbf,      // Load 0xbf into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xbf,      // Store e1 into 0xbf
    0x2a, 0xe1, 0xbf,      // Load memory address 0xbf into register 1
    0x28, 0xe2, 0xa7,      // Load the value 0xa7 into register e2
    0x2a, 0xe3, 0xbf,      // Load memory address 0xbf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xbf,      // Store e1 into 0xbf

    0x2a, 0xe1, 0xc0,      // Load 0xc0 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc0,      // Store e1 into 0xc0
    0x2a, 0xe1, 0xc0,      // Load memory address 0xc0 into register 1
    0x28, 0xe2, 0x40,      // Load the value 0x40 into register e2
    0x2a, 0xe3, 0xc0,      // Load memory address 0xc0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc0,      // Store e1 into 0xc0
    0x2a, 0xe1, 0xc0,      // Load 0xc0 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc0,      // Store e1 into 0xc0
    0x2a, 0xe1, 0xc0,      // Load memory address 0xc0 into register 1
    0x28, 0xe2, 0xa8,      // Load the value 0xa8 into register e2
    0x2a, 0xe3, 0xc0,      // Load memory address 0xc0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc0,      // Store e1 into 0xc0

    0x2a, 0xe1, 0xc1,      // Load 0xc1 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc1,      // Store e1 into 0xc1
    0x2a, 0xe1, 0xc1,      // Load memory address 0xc1 into register 1
    0x28, 0xe2, 0x41,      // Load the value 0x41 into register e2
    0x2a, 0xe3, 0xc1,      // Load memory address 0xc1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc1,      // Store e1 into 0xc1
    0x2a, 0xe1, 0xc1,      // Load 0xc1 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc1,      // Store e1 into 0xc1
    0x2a, 0xe1, 0xc1,      // Load memory address 0xc1 into register 1
    0x28, 0xe2, 0xa9,      // Load the value 0xa9 into register e2
    0x2a, 0xe3, 0xc1,      // Load memory address 0xc1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc1,      // Store e1 into 0xc1

    0x2a, 0xe1, 0xc2,      // Load 0xc2 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc2,      // Store e1 into 0xc2
    0x2a, 0xe1, 0xc2,      // Load memory address 0xc2 into register 1
    0x28, 0xe2, 0x42,      // Load the value 0x42 into register e2
    0x2a, 0xe3, 0xc2,      // Load memory address 0xc2 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc2,      // Store e1 into 0xc2
    0x2a, 0xe1, 0xc2,      // Load 0xc2 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc2,      // Store e1 into 0xc2
    0x2a, 0xe1, 0xc2,      // Load memory address 0xc2 into register 1
    0x28, 0xe2, 0xaa,      // Load the value 0xaa into register e2
    0x2a, 0xe3, 0xc2,      // Load memory address 0xc2 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc2,      // Store e1 into 0xc2

    0x2a, 0xe1, 0xc3,      // Load 0xc3 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc3,      // Store e1 into 0xc3
    0x2a, 0xe1, 0xc3,      // Load memory address 0xc3 into register 1
    0x28, 0xe2, 0x43,      // Load the value 0x43 into register e2
    0x2a, 0xe3, 0xc3,      // Load memory address 0xc3 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc3,      // Store e1 into 0xc3
    0x2a, 0xe1, 0xc3,      // Load 0xc3 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc3,      // Store e1 into 0xc3
    0x2a, 0xe1, 0xc3,      // Load memory address 0xc3 into register 1
    0x28, 0xe2, 0xab,      // Load the value 0xab into register e2
    0x2a, 0xe3, 0xc3,      // Load memory address 0xc3 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc3,      // Store e1 into 0xc3

    0x2a, 0xe1, 0xc4,      // Load 0xc4 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc4,      // Store e1 into 0xc4
    0x2a, 0xe1, 0xc4,      // Load memory address 0xc4 into register 1
    0x28, 0xe2, 0x44,      // Load the value 0x44 into register e2
    0x2a, 0xe3, 0xc4,      // Load memory address 0xc4 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc4,      // Store e1 into 0xc4
    0x2a, 0xe1, 0xc4,      // Load 0xc4 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc4,      // Store e1 into 0xc4
    0x2a, 0xe1, 0xc4,      // Load memory address 0xc4 into register 1
    0x28, 0xe2, 0xac,      // Load the value 0xac into register e2
    0x2a, 0xe3, 0xc4,      // Load memory address 0xc4 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc4,      // Store e1 into 0xc4

    0x2a, 0xe1, 0xc5,      // Load 0xc5 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc5,      // Store e1 into 0xc5
    0x2a, 0xe1, 0xc5,      // Load memory address 0xc5 into register 1
    0x28, 0xe2, 0x45,      // Load the value 0x45 into register e2
    0x2a, 0xe3, 0xc5,      // Load memory address 0xc5 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc5,      // Store e1 into 0xc5
    0x2a, 0xe1, 0xc5,      // Load 0xc5 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc5,      // Store e1 into 0xc5
    0x2a, 0xe1, 0xc5,      // Load memory address 0xc5 into register 1
    0x28, 0xe2, 0xad,      // Load the value 0xad into register e2
    0x2a, 0xe3, 0xc5,      // Load memory address 0xc5 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc5,      // Store e1 into 0xc5

    0x2a, 0xe1, 0xc6,      // Load 0xc6 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc6,      // Store e1 into 0xc6
    0x2a, 0xe1, 0xc6,      // Load memory address 0xc6 into register 1
    0x28, 0xe2, 0x46,      // Load the value 0x46 into register e2
    0x2a, 0xe3, 0xc6,      // Load memory address 0xc6 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc6,      // Store e1 into 0xc6
    0x2a, 0xe1, 0xc6,      // Load 0xc6 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc6,      // Store e1 into 0xc6
    0x2a, 0xe1, 0xc6,      // Load memory address 0xc6 into register 1
    0x28, 0xe2, 0xae,      // Load the value 0xae into register e2
    0x2a, 0xe3, 0xc6,      // Load memory address 0xc6 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc6,      // Store e1 into 0xc6

    0x2a, 0xe1, 0xc7,      // Load 0xc7 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc7,      // Store e1 into 0xc7
    0x2a, 0xe1, 0xc7,      // Load memory address 0xc7 into register 1
    0x28, 0xe2, 0x47,      // Load the value 0x47 into register e2
    0x2a, 0xe3, 0xc7,      // Load memory address 0xc7 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc7,      // Store e1 into 0xc7
    0x2a, 0xe1, 0xc7,      // Load 0xc7 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc7,      // Store e1 into 0xc7
    0x2a, 0xe1, 0xc7,      // Load memory address 0xc7 into register 1
    0x28, 0xe2, 0xaf,      // Load the value 0xaf into register e2
    0x2a, 0xe3, 0xc7,      // Load memory address 0xc7 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc7,      // Store e1 into 0xc7

    0x2a, 0xe1, 0xc8,      // Load 0xc8 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc8,      // Store e1 into 0xc8
    0x2a, 0xe1, 0xc8,      // Load memory address 0xc8 into register 1
    0x28, 0xe2, 0x48,      // Load the value 0x48 into register e2
    0x2a, 0xe3, 0xc8,      // Load memory address 0xc8 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc8,      // Store e1 into 0xc8
    0x2a, 0xe1, 0xc8,      // Load 0xc8 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc8,      // Store e1 into 0xc8
    0x2a, 0xe1, 0xc8,      // Load memory address 0xc8 into register 1
    0x28, 0xe2, 0xb0,      // Load the value 0xb0 into register e2
    0x2a, 0xe3, 0xc8,      // Load memory address 0xc8 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc8,      // Store e1 into 0xc8

    0x2a, 0xe1, 0xc9,      // Load 0xc9 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xc9,      // Store e1 into 0xc9
    0x2a, 0xe1, 0xc9,      // Load memory address 0xc9 into register 1
    0x28, 0xe2, 0x49,      // Load the value 0x49 into register e2
    0x2a, 0xe3, 0xc9,      // Load memory address 0xc9 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc9,      // Store e1 into 0xc9
    0x2a, 0xe1, 0xc9,      // Load 0xc9 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xc9,      // Store e1 into 0xc9
    0x2a, 0xe1, 0xc9,      // Load memory address 0xc9 into register 1
    0x28, 0xe2, 0xb1,      // Load the value 0xb1 into register e2
    0x2a, 0xe3, 0xc9,      // Load memory address 0xc9 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xc9,      // Store e1 into 0xc9

    0x2a, 0xe1, 0xca,      // Load 0xca into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xca,      // Store e1 into 0xca
    0x2a, 0xe1, 0xca,      // Load memory address 0xca into register 1
    0x28, 0xe2, 0x4a,      // Load the value 0x4a into register e2
    0x2a, 0xe3, 0xca,      // Load memory address 0xca into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xca,      // Store e1 into 0xca
    0x2a, 0xe1, 0xca,      // Load 0xca into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xca,      // Store e1 into 0xca
    0x2a, 0xe1, 0xca,      // Load memory address 0xca into register 1
    0x28, 0xe2, 0xb2,      // Load the value 0xb2 into register e2
    0x2a, 0xe3, 0xca,      // Load memory address 0xca into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xca,      // Store e1 into 0xca

    0x2a, 0xe1, 0xcb,      // Load 0xcb into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xcb,      // Store e1 into 0xcb
    0x2a, 0xe1, 0xcb,      // Load memory address 0xcb into register 1
    0x28, 0xe2, 0x4b,      // Load the value 0x4b into register e2
    0x2a, 0xe3, 0xcb,      // Load memory address 0xcb into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcb,      // Store e1 into 0xcb
    0x2a, 0xe1, 0xcb,      // Load 0xcb into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xcb,      // Store e1 into 0xcb
    0x2a, 0xe1, 0xcb,      // Load memory address 0xcb into register 1
    0x28, 0xe2, 0xb3,      // Load the value 0xb3 into register e2
    0x2a, 0xe3, 0xcb,      // Load memory address 0xcb into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcb,      // Store e1 into 0xcb

    0x2a, 0xe1, 0xcc,      // Load 0xcc into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xcc,      // Store e1 into 0xcc
    0x2a, 0xe1, 0xcc,      // Load memory address 0xcc into register 1
    0x28, 0xe2, 0x4c,      // Load the value 0x4c into register e2
    0x2a, 0xe3, 0xcc,      // Load memory address 0xcc into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcc,      // Store e1 into 0xcc
    0x2a, 0xe1, 0xcc,      // Load 0xcc into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xcc,      // Store e1 into 0xcc
    0x2a, 0xe1, 0xcc,      // Load memory address 0xcc into register 1
    0x28, 0xe2, 0xb4,      // Load the value 0xb4 into register e2
    0x2a, 0xe3, 0xcc,      // Load memory address 0xcc into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcc,      // Store e1 into 0xcc

    0x2a, 0xe1, 0xcd,      // Load 0xcd into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xcd,      // Store e1 into 0xcd
    0x2a, 0xe1, 0xcd,      // Load memory address 0xcd into register 1
    0x28, 0xe2, 0x4d,      // Load the value 0x4d into register e2
    0x2a, 0xe3, 0xcd,      // Load memory address 0xcd into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcd,      // Store e1 into 0xcd
    0x2a, 0xe1, 0xcd,      // Load 0xcd into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xcd,      // Store e1 into 0xcd
    0x2a, 0xe1, 0xcd,      // Load memory address 0xcd into register 1
    0x28, 0xe2, 0xb5,      // Load the value 0xb5 into register e2
    0x2a, 0xe3, 0xcd,      // Load memory address 0xcd into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcd,      // Store e1 into 0xcd

    0x2a, 0xe1, 0xce,      // Load 0xce into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xce,      // Store e1 into 0xce
    0x2a, 0xe1, 0xce,      // Load memory address 0xce into register 1
    0x28, 0xe2, 0x4e,      // Load the value 0x4e into register e2
    0x2a, 0xe3, 0xce,      // Load memory address 0xce into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xce,      // Store e1 into 0xce
    0x2a, 0xe1, 0xce,      // Load 0xce into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xce,      // Store e1 into 0xce
    0x2a, 0xe1, 0xce,      // Load memory address 0xce into register 1
    0x28, 0xe2, 0xb6,      // Load the value 0xb6 into register e2
    0x2a, 0xe3, 0xce,      // Load memory address 0xce into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xce,      // Store e1 into 0xce

    0x2a, 0xe1, 0xcf,      // Load 0xcf into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xcf,      // Store e1 into 0xcf
    0x2a, 0xe1, 0xcf,      // Load memory address 0xcf into register 1
    0x28, 0xe2, 0x4f,      // Load the value 0x4f into register e2
    0x2a, 0xe3, 0xcf,      // Load memory address 0xcf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcf,      // Store e1 into 0xcf
    0x2a, 0xe1, 0xcf,      // Load 0xcf into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xcf,      // Store e1 into 0xcf
    0x2a, 0xe1, 0xcf,      // Load memory address 0xcf into register 1
    0x28, 0xe2, 0xb7,      // Load the value 0xb7 into register e2
    0x2a, 0xe3, 0xcf,      // Load memory address 0xcf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xcf,      // Store e1 into 0xcf

    0x2a, 0xe1, 0xd0,      // Load 0xd0 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd0,      // Store e1 into 0xd0
    0x2a, 0xe1, 0xd0,      // Load memory address 0xd0 into register 1
    0x28, 0xe2, 0x50,      // Load the value 0x50 into register e2
    0x2a, 0xe3, 0xd0,      // Load memory address 0xd0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd0,      // Store e1 into 0xd0
    0x2a, 0xe1, 0xd0,      // Load 0xd0 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd0,      // Store e1 into 0xd0
    0x2a, 0xe1, 0xd0,      // Load memory address 0xd0 into register 1
    0x28, 0xe2, 0xb8,      // Load the value 0xb8 into register e2
    0x2a, 0xe3, 0xd0,      // Load memory address 0xd0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd0,      // Store e1 into 0xd0

    0x2a, 0xe1, 0xd1,      // Load 0xd1 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd1,      // Store e1 into 0xd1
    0x2a, 0xe1, 0xd1,      // Load memory address 0xd1 into register 1
    0x28, 0xe2, 0x51,      // Load the value 0x51 into register e2
    0x2a, 0xe3, 0xd1,      // Load memory address 0xd1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd1,      // Store e1 into 0xd1
    0x2a, 0xe1, 0xd1,      // Load 0xd1 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd1,      // Store e1 into 0xd1
    0x2a, 0xe1, 0xd1,      // Load memory address 0xd1 into register 1
    0x28, 0xe2, 0xb9,      // Load the value 0xb9 into register e2
    0x2a, 0xe3, 0xd1,      // Load memory address 0xd1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd1,      // Store e1 into 0xd1

    0x2a, 0xe1, 0xd2,      // Load 0xd2 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd2,      // Store e1 into 0xd2
    0x2a, 0xe1, 0xd2,      // Load memory address 0xd2 into register 1
    0x28, 0xe2, 0x52,      // Load the value 0x52 into register e2
    0x2a, 0xe3, 0xd2,      // Load memory address 0xd2 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd2,      // Store e1 into 0xd2
    0x2a, 0xe1, 0xd2,      // Load 0xd2 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd2,      // Store e1 into 0xd2
    0x2a, 0xe1, 0xd2,      // Load memory address 0xd2 into register 1
    0x28, 0xe2, 0xba,      // Load the value 0xba into register e2
    0x2a, 0xe3, 0xd2,      // Load memory address 0xd2 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd2,      // Store e1 into 0xd2

    0x2a, 0xe1, 0xd3,      // Load 0xd3 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd3,      // Store e1 into 0xd3
    0x2a, 0xe1, 0xd3,      // Load memory address 0xd3 into register 1
    0x28, 0xe2, 0x53,      // Load the value 0x53 into register e2
    0x2a, 0xe3, 0xd3,      // Load memory address 0xd3 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd3,      // Store e1 into 0xd3
    0x2a, 0xe1, 0xd3,      // Load 0xd3 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd3,      // Store e1 into 0xd3
    0x2a, 0xe1, 0xd3,      // Load memory address 0xd3 into register 1
    0x28, 0xe2, 0xbb,      // Load the value 0xbb into register e2
    0x2a, 0xe3, 0xd3,      // Load memory address 0xd3 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd3,      // Store e1 into 0xd3

    0x2a, 0xe1, 0xd4,      // Load 0xd4 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd4,      // Store e1 into 0xd4
    0x2a, 0xe1, 0xd4,      // Load memory address 0xd4 into register 1
    0x28, 0xe2, 0x54,      // Load the value 0x54 into register e2
    0x2a, 0xe3, 0xd4,      // Load memory address 0xd4 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd4,      // Store e1 into 0xd4
    0x2a, 0xe1, 0xd4,      // Load 0xd4 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd4,      // Store e1 into 0xd4
    0x2a, 0xe1, 0xd4,      // Load memory address 0xd4 into register 1
    0x28, 0xe2, 0xbc,      // Load the value 0xbc into register e2
    0x2a, 0xe3, 0xd4,      // Load memory address 0xd4 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd4,      // Store e1 into 0xd4

    0x2a, 0xe1, 0xd5,      // Load 0xd5 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd5,      // Store e1 into 0xd5
    0x2a, 0xe1, 0xd5,      // Load memory address 0xd5 into register 1
    0x28, 0xe2, 0x55,      // Load the value 0x55 into register e2
    0x2a, 0xe3, 0xd5,      // Load memory address 0xd5 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd5,      // Store e1 into 0xd5
    0x2a, 0xe1, 0xd5,      // Load 0xd5 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd5,      // Store e1 into 0xd5
    0x2a, 0xe1, 0xd5,      // Load memory address 0xd5 into register 1
    0x28, 0xe2, 0xbd,      // Load the value 0xbd into register e2
    0x2a, 0xe3, 0xd5,      // Load memory address 0xd5 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd5,      // Store e1 into 0xd5

    0x2a, 0xe1, 0xd6,      // Load 0xd6 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd6,      // Store e1 into 0xd6
    0x2a, 0xe1, 0xd6,      // Load memory address 0xd6 into register 1
    0x28, 0xe2, 0x56,      // Load the value 0x56 into register e2
    0x2a, 0xe3, 0xd6,      // Load memory address 0xd6 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd6,      // Store e1 into 0xd6
    0x2a, 0xe1, 0xd6,      // Load 0xd6 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd6,      // Store e1 into 0xd6
    0x2a, 0xe1, 0xd6,      // Load memory address 0xd6 into register 1
    0x28, 0xe2, 0xbe,      // Load the value 0xbe into register e2
    0x2a, 0xe3, 0xd6,      // Load memory address 0xd6 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd6,      // Store e1 into 0xd6

    0x2a, 0xe1, 0xd7,      // Load 0xd7 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd7,      // Store e1 into 0xd7
    0x2a, 0xe1, 0xd7,      // Load memory address 0xd7 into register 1
    0x28, 0xe2, 0x57,      // Load the value 0x57 into register e2
    0x2a, 0xe3, 0xd7,      // Load memory address 0xd7 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd7,      // Store e1 into 0xd7
    0x2a, 0xe1, 0xd7,      // Load 0xd7 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd7,      // Store e1 into 0xd7
    0x2a, 0xe1, 0xd7,      // Load memory address 0xd7 into register 1
    0x28, 0xe2, 0xbf,      // Load the value 0xbf into register e2
    0x2a, 0xe3, 0xd7,      // Load memory address 0xd7 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd7,      // Store e1 into 0xd7

    0x2a, 0xe1, 0xd8,      // Load 0xd8 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd8,      // Store e1 into 0xd8
    0x2a, 0xe1, 0xd8,      // Load memory address 0xd8 into register 1
    0x28, 0xe2, 0x58,      // Load the value 0x58 into register e2
    0x2a, 0xe3, 0xd8,      // Load memory address 0xd8 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd8,      // Store e1 into 0xd8
    0x2a, 0xe1, 0xd8,      // Load 0xd8 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd8,      // Store e1 into 0xd8
    0x2a, 0xe1, 0xd8,      // Load memory address 0xd8 into register 1
    0x28, 0xe2, 0xc0,      // Load the value 0xc0 into register e2
    0x2a, 0xe3, 0xd8,      // Load memory address 0xd8 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd8,      // Store e1 into 0xd8

    0x2a, 0xe1, 0xd9,      // Load 0xd9 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xd9,      // Store e1 into 0xd9
    0x2a, 0xe1, 0xd9,      // Load memory address 0xd9 into register 1
    0x28, 0xe2, 0x59,      // Load the value 0x59 into register e2
    0x2a, 0xe3, 0xd9,      // Load memory address 0xd9 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd9,      // Store e1 into 0xd9
    0x2a, 0xe1, 0xd9,      // Load 0xd9 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xd9,      // Store e1 into 0xd9
    0x2a, 0xe1, 0xd9,      // Load memory address 0xd9 into register 1
    0x28, 0xe2, 0xc1,      // Load the value 0xc1 into register e2
    0x2a, 0xe3, 0xd9,      // Load memory address 0xd9 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xd9,      // Store e1 into 0xd9

    0x2a, 0xe1, 0xda,      // Load 0xda into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xda,      // Store e1 into 0xda
    0x2a, 0xe1, 0xda,      // Load memory address 0xda into register 1
    0x28, 0xe2, 0x5a,      // Load the value 0x5a into register e2
    0x2a, 0xe3, 0xda,      // Load memory address 0xda into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xda,      // Store e1 into 0xda
    0x2a, 0xe1, 0xda,      // Load 0xda into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xda,      // Store e1 into 0xda
    0x2a, 0xe1, 0xda,      // Load memory address 0xda into register 1
    0x28, 0xe2, 0xc2,      // Load the value 0xc2 into register e2
    0x2a, 0xe3, 0xda,      // Load memory address 0xda into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xda,      // Store e1 into 0xda

    0x2a, 0xe1, 0xdb,      // Load 0xdb into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xdb,      // Store e1 into 0xdb
    0x2a, 0xe1, 0xdb,      // Load memory address 0xdb into register 1
    0x28, 0xe2, 0x5b,      // Load the value 0x5b into register e2
    0x2a, 0xe3, 0xdb,      // Load memory address 0xdb into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdb,      // Store e1 into 0xdb
    0x2a, 0xe1, 0xdb,      // Load 0xdb into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xdb,      // Store e1 into 0xdb
    0x2a, 0xe1, 0xdb,      // Load memory address 0xdb into register 1
    0x28, 0xe2, 0xc3,      // Load the value 0xc3 into register e2
    0x2a, 0xe3, 0xdb,      // Load memory address 0xdb into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdb,      // Store e1 into 0xdb

    0x2a, 0xe1, 0xdc,      // Load 0xdc into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xdc,      // Store e1 into 0xdc
    0x2a, 0xe1, 0xdc,      // Load memory address 0xdc into register 1
    0x28, 0xe2, 0x5c,      // Load the value 0x5c into register e2
    0x2a, 0xe3, 0xdc,      // Load memory address 0xdc into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdc,      // Store e1 into 0xdc
    0x2a, 0xe1, 0xdc,      // Load 0xdc into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xdc,      // Store e1 into 0xdc
    0x2a, 0xe1, 0xdc,      // Load memory address 0xdc into register 1
    0x28, 0xe2, 0xc4,      // Load the value 0xc4 into register e2
    0x2a, 0xe3, 0xdc,      // Load memory address 0xdc into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdc,      // Store e1 into 0xdc

    0x2a, 0xe1, 0xdd,      // Load 0xdd into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xdd,      // Store e1 into 0xdd
    0x2a, 0xe1, 0xdd,      // Load memory address 0xdd into register 1
    0x28, 0xe2, 0x5d,      // Load the value 0x5d into register e2
    0x2a, 0xe3, 0xdd,      // Load memory address 0xdd into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdd,      // Store e1 into 0xdd
    0x2a, 0xe1, 0xdd,      // Load 0xdd into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xdd,      // Store e1 into 0xdd
    0x2a, 0xe1, 0xdd,      // Load memory address 0xdd into register 1
    0x28, 0xe2, 0xc5,      // Load the value 0xc5 into register e2
    0x2a, 0xe3, 0xdd,      // Load memory address 0xdd into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdd,      // Store e1 into 0xdd

    0x2a, 0xe1, 0xde,      // Load 0xde into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xde,      // Store e1 into 0xde
    0x2a, 0xe1, 0xde,      // Load memory address 0xde into register 1
    0x28, 0xe2, 0x5e,      // Load the value 0x5e into register e2
    0x2a, 0xe3, 0xde,      // Load memory address 0xde into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xde,      // Store e1 into 0xde
    0x2a, 0xe1, 0xde,      // Load 0xde into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xde,      // Store e1 into 0xde
    0x2a, 0xe1, 0xde,      // Load memory address 0xde into register 1
    0x28, 0xe2, 0xc6,      // Load the value 0xc6 into register e2
    0x2a, 0xe3, 0xde,      // Load memory address 0xde into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xde,      // Store e1 into 0xde

    0x2a, 0xe1, 0xdf,      // Load 0xdf into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xdf,      // Store e1 into 0xdf
    0x2a, 0xe1, 0xdf,      // Load memory address 0xdf into register 1
    0x28, 0xe2, 0x5f,      // Load the value 0x5f into register e2
    0x2a, 0xe3, 0xdf,      // Load memory address 0xdf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdf,      // Store e1 into 0xdf
    0x2a, 0xe1, 0xdf,      // Load 0xdf into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xdf,      // Store e1 into 0xdf
    0x2a, 0xe1, 0xdf,      // Load memory address 0xdf into register 1
    0x28, 0xe2, 0xc7,      // Load the value 0xc7 into register e2
    0x2a, 0xe3, 0xdf,      // Load memory address 0xdf into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xdf,      // Store e1 into 0xdf

    0x2a, 0xe1, 0xe0,      // Load 0xe0 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xe0,      // Store e1 into 0xe0
    0x2a, 0xe1, 0xe0,      // Load memory address 0xe0 into register 1
    0x28, 0xe2, 0x60,      // Load the value 0x60 into register e2
    0x2a, 0xe3, 0xe0,      // Load memory address 0xe0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xe0,      // Store e1 into 0xe0
    0x2a, 0xe1, 0xe0,      // Load 0xe0 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xe0,      // Store e1 into 0xe0
    0x2a, 0xe1, 0xe0,      // Load memory address 0xe0 into register 1
    0x28, 0xe2, 0xc8,      // Load the value 0xc8 into register e2
    0x2a, 0xe3, 0xe0,      // Load memory address 0xe0 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xe0,      // Store e1 into 0xe0

    0x2a, 0xe1, 0xe1,      // Load 0xe1 into e1
    0x28, 0xe2, 0x01,      // Load 1 into e2
    0x8f, 0xe1, 0xe2,      // ROL
    0x24, 0xe1, 0xe1,      // Store e1 into 0xe1
    0x2a, 0xe1, 0xe1,      // Load memory address 0xe1 into register 1
    0x28, 0xe2, 0x61,      // Load the value 0x61 into register e2
    0x2a, 0xe3, 0xe1,      // Load memory address 0xe1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xe1,      // Store e1 into 0xe1
    0x2a, 0xe1, 0xe1,      // Load 0xe1 into e1
    0x28, 0xe2, 0x02,      // Load 2 into e2
    0x72, 0xe1, 0xe2,      // ROR
    0x24, 0xe1, 0xe1,      // Store e1 into 0xe1
    0x2a, 0xe1, 0xe1,      // Load memory address 0xe1 into register 1
    0x28, 0xe2, 0xc9,      // Load the value 0xc9 into register e2
    0x2a, 0xe3, 0xe1,      // Load memory address 0xe1 into register 3
    0x26, 0xe3, 0xe2,      // e3 = A NOR B
    0x26, 0xe1, 0xe3,      // e1 = A NOR (A NOR B)
    0x26, 0xe2, 0xe3,      // e2 = B NOR (A NOR B)
    0x26, 0xe1, 0xe2,      // e1 = final val
    0x98, 0xe1,            // do some dumb overflow shit fixing
    0x24, 0xe1, 0xe1,      // Store e1 into 0xe1

    0x28, 0xe1, 0x5f,      // Load encrypted byte at 0x5f into reg A
    0x2a, 0xe2, 0xbf,      // Load input byte at 0xbf into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x0c,      // Load encrypted byte at 0x0c into reg A
    0x2a, 0xe2, 0xc0,      // Load input byte at 0xc0 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xc3,      // Load encrypted byte at 0xc3 into reg A
    0x2a, 0xe2, 0xc1,      // Load input byte at 0xc1 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x88,      // Load encrypted byte at 0x88 into reg A
    0x2a, 0xe2, 0xc2,      // Load input byte at 0xc2 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xc6,      // Load encrypted byte at 0xc6 into reg A
    0x2a, 0xe2, 0xc3,      // Load input byte at 0xc3 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x8a,      // Load encrypted byte at 0x8a into reg A
    0x2a, 0xe2, 0xc4,      // Load input byte at 0xc4 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xe4,      // Load encrypted byte at 0xe4 into reg A
    0x2a, 0xe2, 0xc5,      // Load input byte at 0xc5 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x06,      // Load encrypted byte at 0x06 into reg A
    0x2a, 0xe2, 0xc6,      // Load input byte at 0xc6 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xd1,      // Load encrypted byte at 0xd1 into reg A
    0x2a, 0xe2, 0xc7,      // Load input byte at 0xc7 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x3a,      // Load encrypted byte at 0x3a into reg A
    0x2a, 0xe2, 0xc8,      // Load input byte at 0xc8 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x79,      // Load encrypted byte at 0x79 into reg A
    0x2a, 0xe2, 0xc9,      // Load input byte at 0xc9 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x8f,      // Load encrypted byte at 0x8f into reg A
    0x2a, 0xe2, 0xca,      // Load input byte at 0xca into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xd1,      // Load encrypted byte at 0xd1 into reg A
    0x2a, 0xe2, 0xcb,      // Load input byte at 0xcb into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x08,      // Load encrypted byte at 0x08 into reg A
    0x2a, 0xe2, 0xcc,      // Load input byte at 0xcc into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x5c,      // Load encrypted byte at 0x5c into reg A
    0x2a, 0xe2, 0xcd,      // Load input byte at 0xcd into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x12,      // Load encrypted byte at 0x12 into reg A
    0x2a, 0xe2, 0xce,      // Load input byte at 0xce into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xfc,      // Load encrypted byte at 0xfc into reg A
    0x2a, 0xe2, 0xcf,      // Load input byte at 0xcf into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x97,      // Load encrypted byte at 0x97 into reg A
    0x2a, 0xe2, 0xd0,      // Load input byte at 0xd0 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x74,      // Load encrypted byte at 0x74 into reg A
    0x2a, 0xe2, 0xd1,      // Load input byte at 0xd1 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x17,      // Load encrypted byte at 0x17 into reg A
    0x2a, 0xe2, 0xd2,      // Load input byte at 0xd2 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xf5,      // Load encrypted byte at 0xf5 into reg A
    0x2a, 0xe2, 0xd3,      // Load input byte at 0xd3 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xb3,      // Load encrypted byte at 0xb3 into reg A
    0x2a, 0xe2, 0xd4,      // Load input byte at 0xd4 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xde,      // Load encrypted byte at 0xde into reg A
    0x2a, 0xe2, 0xd5,      // Load input byte at 0xd5 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x84,      // Load encrypted byte at 0x84 into reg A
    0x2a, 0xe2, 0xd6,      // Load input byte at 0xd6 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xd9,      // Load encrypted byte at 0xd9 into reg A
    0x2a, 0xe2, 0xd7,      // Load input byte at 0xd7 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xcc,      // Load encrypted byte at 0xcc into reg A
    0x2a, 0xe2, 0xd8,      // Load input byte at 0xd8 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xad,      // Load encrypted byte at 0xad into reg A
    0x2a, 0xe2, 0xd9,      // Load input byte at 0xd9 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xcd,      // Load encrypted byte at 0xcd into reg A
    0x2a, 0xe2, 0xda,      // Load input byte at 0xda into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xba,      // Load encrypted byte at 0xba into reg A
    0x2a, 0xe2, 0xdb,      // Load input byte at 0xdb into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0xe9,      // Load encrypted byte at 0xe9 into reg A
    0x2a, 0xe2, 0xdc,      // Load input byte at 0xdc into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x25,      // Load encrypted byte at 0x25 into reg A
    0x2a, 0xe2, 0xdd,      // Load input byte at 0xdd into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x49,      // Load encrypted byte at 0x49 into reg A
    0x2a, 0xe2, 0xde,      // Load input byte at 0xde into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x80,      // Load encrypted byte at 0x80 into reg A
    0x2a, 0xe2, 0xdf,      // Load input byte at 0xdf into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal
    0x28, 0xe1, 0x6e,      // Load encrypted byte at 0x6e into reg A
    0x2a, 0xe2, 0xe0,      // Load input byte at 0xe0 into reg B
    0x28, 0xe3, 0x59,      // Load jump amount in C
    0x22, 0xe1, 0xe2,      // Compare reg A and B
    0x2b, 0x02, 0xe3,      // Jump to wrong message if not equal

    0x28, 0xe1, 0x01,      // OPCODE_LD_REG_COD: Load 1 (stdout) into register A
    0x28, 0xe2, 0x10,      // OPCODE_LD_REG_COD: Load memory address 0x20 into register B
    0x28, 0xe3, 0x0c,      // OPCODE_LD_REG_COD: Load 12 (length of "Enter flag: ") into register C
    0xff, 0x2e,            // OPCODE_SYS with CUS_SYS_WRITE

    0x28, 0xe1, 0x0,
    0xff, 0x25,
};

int main() {
    init();
    protect();
    main_state the_state;
    memset(&the_state, 0, sizeof(the_state));
    memcpy(the_state.code, input_code, sizeof(input_code));
    interpreter_loop(&the_state);
    syscall(SYS_exit, 0);
}
