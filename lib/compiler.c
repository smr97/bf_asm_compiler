#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <utils/stack.h>

#include <compiler.h>
#include <dbg.h>

/* Conventions used in the generated code:
 %rip is the instruction pointer
 %rdx is the pointer to current memory cell (rdx wasn't chosen for any
 particular reason) */

typedef void (*jitted_code)();

/* Allocs a RWX page using mmap. */
void *alloc_executable_memory(size_t size) {
  void *ptr = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(ptr != MAP_FAILED && ptr != NULL, "Couldn't mmap RWX page");

  return ptr;

error:
  return NULL;
}

/* Convert brainfuck instruction to x64 code, returned in **code, with code size
 size in *size. Invalid brainfuck instructions (aka comments) returns NULL Note:
 asm files that generated the x64 hex are in the asm/ directory */
static void code_for_instruction(unsigned char instruction,
                                 unsigned char **code, char **english, size_t *size) {
  switch (instruction) {
  case '>':
    *code = "\x48\x83\xc2\x01"; // code for cc++, aka   add rdx, 1
    *english = "add rdx, 0x1\n\0";
    *size = 4;
    return;
  case '<':
    *code = "\x48\x83\xea\x01"; // code for cc--, aka   sub rdx, 1
    *english = "sub rdx, 0x1\n\0";
    *size = 4;
    return;

  case '+':
    *code = "\x80\x02\x01"; // code for (*cc)++, aka add [rdx], 1
    *english = "add BYTE PTR [rdx], 0x1\n\0";
    *size = 3;
    return;
  case '-':
    *code = "\x80\x2a\x01"; // (*cc)--
    *english = "sub BYTE PTR [rdx], 0x1\n\0";
    *size = 3;
    return;
  case '.':
    *code = "\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xd6\x52\xba\x01"
            "\x00\x00\x00\x0f\x05\x5a"; // print char stored at [rdx]
    *english = "mov eax, 0x1 \n mov edi, 0x1 \n mov rsi, rdx \n push rdx \n mov edx, 0x1 \n syscall \n pop rdx\n\0";
    *size = 22;
    return;
  default:
    *code = NULL;
    *size = -1;
  }
}

// TODO: refactor the code generation process to be instruction type agnostic
size_t compute_machine_code_size(unsigned char *command, size_t command_size) {
  size_t size = 3; // size for setting up rdx + ret
  unsigned char dummy[64];
  char english[100];

  for (unsigned char *cur_command = command;
       cur_command < command + command_size; cur_command++) {
    if (*cur_command == '[') {
      size += 5;
    } else if (*cur_command == ']') {
      size += 9;
    } else {
      size_t tmp = 0;
      code_for_instruction(*cur_command, (void *)&dummy, (char**)&english, &tmp);
      size += tmp;
    }
  }
  return size;
}

/* This function compiles and execute the `size` brainfucks instructions in
 * `command`
 */
void jit_run(unsigned char *command, size_t command_size) {
  // create the data space of the program
  unsigned char *begin_cells = calloc(1, PLAYGROUND_CELLS);
  check_mem(begin_cells);

  size_t code_size = compute_machine_code_size(command, command_size);
  unsigned char *big_chunk = alloc_executable_memory(code_size);
  unsigned char *code = big_chunk;
  char* english = malloc(code_size * 20);
  char* base_english = english;

  // add code to set rdx to address of playground
  code[0] = 0x48;
  code[1] = 0xba;
  code += 2;
  memcpy(code, &begin_cells, sizeof(unsigned char *));
  code += sizeof(unsigned char *);

  stack *jumpback_stack = stack_create(sizeof(unsigned char *));

  for (unsigned char *cur_command = command;
       cur_command < command + command_size; cur_command++) {
    // debug("decoding command #%d", ++n);
    unsigned char *ins_code = NULL;
    char* this_english = NULL;
    size_t size;

    if (*cur_command == '[') {
      // will be filled later by the corresponding '['
      unsigned char base[5] = "\xe9 FLL";

      ins_code = base;
      size = 5;

      // note the current position (offset from start) for later use
      unsigned char *next_ins = (unsigned char *)(code + size - big_chunk);
      stack_push(jumpback_stack, &next_ins);
    } else if (*cur_command == ']') {
      check(!stack_empty(jumpback_stack), "Mismatched '[' or ']' in input");

      // jump is implemented in the form of jmp [RIP + const]
      unsigned char *addr;
      stack_pop(jumpback_stack, &addr);
      addr += (size_t)big_chunk;

      size = 9;
      // jump address relative to next instruction => needs to account for size
      // of current jump instruction
      uint32_t jump_offset = addr - code - size;
      debug("Making a %d bytes jump", jump_offset);
      unsigned char base[9] = "\x80\x3a\x00\x0f\x85    ";
      memcpy(&base[5], &jump_offset, 4);

      ins_code = base;

      // now we also need to make the previous [ unconditionnaly jump here
      // just putting the current address there, relatively speaking
      uint32_t forward_offset = -(addr - code);
      memcpy(addr - 4, &forward_offset, 4);

    } else {
      // it's not a branch instruction, nothing special to do
      code_for_instruction(*cur_command, &ins_code, &this_english, &size);
    }

    // copy instruction to executable page
    // ignoring comments
    if (ins_code) {
      memcpy(code, ins_code, size);
      if (this_english) {
        memcpy(english, this_english, strlen(this_english));
        english += strlen(this_english);
      }
      code += size;
    }
  }

  // add `ret` to exit cleanly:
  code[0] = 0xc3;
  code++;

  FILE *codefile = fopen("./asm/test", "wb");
  FILE *engfile = fopen("./asm/test_eng.asm", "w");

  int ret = fwrite(big_chunk, sizeof(char), code_size, codefile);
  int ret1 = fwrite(base_english, sizeof(char), english - base_english + 1, engfile);
  if (ret != code_size)
    printf("write failed\n");

  jitted_code func = (jitted_code)big_chunk;

  debug("Running compiled code.");
  func();

error:
  if (begin_cells) {
    free(begin_cells);
  }
  return;
}
