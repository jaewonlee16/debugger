#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/personality.h>

#include "snudbg.h"
#include "procmaps.h"
#include <errno.h>

ADDR_T get_image_baseaddr(int pid);


int num_bps = 0;
breakpoint_t bps[MAX_BPS];

/* HINT: No need to change this function */
void die(char* message) {
    WARN("Failed with message: '%s'\n", message);
    exit(-1);
}

/* HINT: No need to change this function */
void handle_regs(struct user_regs_struct *regs) {
    fprintf(stdout, "\t");
    PRINT_REG(rax);
    PRINT_REG(rbx);
    PRINT_REG(rcx);
    PRINT_REG(rdx);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(rbp);
    PRINT_REG(rsp);
    PRINT_REG(rsi);
    PRINT_REG(rdi);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(r8);
    PRINT_REG(r9);
    PRINT_REG(r10);
    PRINT_REG(r11);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(r12);
    PRINT_REG(r13);
    PRINT_REG(r14);
    PRINT_REG(r15);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(rip);
    PRINT_REG(eflags);
    fprintf(stdout, "\n");
}

/* HINT: No need to change this function */
void no_aslr(void) {
    unsigned long pv = PER_LINUX | ADDR_NO_RANDOMIZE;

    if (personality(pv) < 0) {
        if (personality(pv) < 0) {
            die("Failed to disable ASLR");
        }
    }
    return;
}

/* HINT: No need to change this function */
void tracee(char* cmd[]) {
    LOG("Tracee with pid=%d\n", getpid());

    no_aslr();
    
    if(ptrace(PTRACE_TRACEME, NULL, NULL, NULL)<0){
        die("Error traceing myself");
    }

    LOG("Loading the executable [%s]\n", cmd[0]);
    execvp(cmd[0], cmd);
}

/* INSTRUCTION: YOU SHOULD NOT CHANGE THIS FUNCTION */    
void dump_addr_in_hex(const ADDR_T addr, const void* data, size_t size) {
    uint i;
    for (i=0; i<size/16; i++) {
        printf("\t %llx ", addr+(i*16));
        for (uint j=0; j<16; j++) {
            printf("%02x ", ((unsigned char*)data)[i*16+j]);
        }
        printf("\n");
    }

    if (size%16 != 0) {
        // the rest
        printf("\t %llx ", addr+(i*16));
        for (uint j=0; j<size%16; j++) {
            printf("%02x ", ((unsigned char*)data)[i*16+j]);
        }
        printf("\n");
    }
}

/* HINT: No need to change this function */
void handle_help(void) {
    LOG("Available commands: \n");
    LOG("\t regs | get [REG] | set [REG] [value]\n");
    LOG("\t read [addr] [size] | write [addr] [value] [size]\n");
    LOG("\t step | continue | break [addr]\n");
    LOG("\t help\n");
    return;
}

void set_debug_state(int pid, enum debugging_state state) {
    if(state == SINGLE_STEP) {
        if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)<0) {
            die("Error tracing syscalls");
        }
    } else if (state == NON_STOP) {
        // TODO
    }
    return;
}


/* 
   Read the memory from @pid at the address @addr with the length @len.
   The data read from @pid will be written to @buf.
*/

void handle_read(int pid, ADDR_T addr, unsigned char *buf, size_t len) {
    long word = 0;
    size_t bytesRead = 0;
    unsigned char *current_bufp = buf;

    while (bytesRead < len) {
        if ((word = ptrace(PTRACE_PEEKDATA, pid, addr + bytesRead, NULL)) == -1 && errno != 0){
		printf("ptrace PEEKDATA error\n");
		break;
	}
        
        size_t bytesToCopy = sizeof(word) < (len - bytesRead) ? sizeof(word) : (len - bytesRead);
        memcpy(current_bufp, &word, bytesToCopy);
        bytesRead += bytesToCopy;
        current_bufp += bytesToCopy;
    }

    // Optional: print the memory data
    dump_addr_in_hex(addr, buf, bytesRead);
}

/* 
   Write the memory to @pid at the address @addr with the length @len.
   The data to be written is placed in @buf.
*/
void handle_write(int pid, ADDR_T addr, unsigned char *buf, size_t len) {
    long word = 0;
    size_t bytesRead = 0;
    unsigned char *current_bufp = buf;

    while (bytesRead < len) {
	// read chunk first
	word = ptrace(PTRACE_PEEKDATA, pid, addr + bytesRead, NULL);
	
	// copy buf to chunk
        size_t bytesToCopy = sizeof(word) < (len - bytesRead) ? sizeof(word) : (len - bytesRead);
        memcpy(&word, current_bufp, bytesToCopy);

	// write chunk
        ptrace(PTRACE_POKEDATA, pid, addr + bytesRead, word);

	// update pointer
        bytesRead += bytesToCopy;
        current_bufp += bytesToCopy;
    }
}

/* 
   Install the software breakpoint at @addr to pid @pid.
*/
void handle_break(int pid, ADDR_T addr) {
    // TODO
    TODO_UNUSED(pid);
    TODO_UNUSED(addr);
}

#define CMPGET_REG(REG_TO_CMP)                   \
    if (strcmp(reg_name, #REG_TO_CMP)==0) {      \
        printf("\t");                            \
        PRINT_REG(REG_TO_CMP);                   \
        printf("\n");                            \
    }

/* HINT: No need to change this function */
void handle_get(char *reg_name, struct user_regs_struct *regs) {
    CMPGET_REG(rax); CMPGET_REG(rbx); CMPGET_REG(rcx); CMPGET_REG(rdx);
    CMPGET_REG(rbp); CMPGET_REG(rsp); CMPGET_REG(rsi); CMPGET_REG(rdi);
    CMPGET_REG(r8);  CMPGET_REG(r9);  CMPGET_REG(r10); CMPGET_REG(r11);
    CMPGET_REG(r12); CMPGET_REG(r13); CMPGET_REG(r14); CMPGET_REG(r15);
    CMPGET_REG(rip); CMPGET_REG(eflags);
    return;
}

#define CMPSET_REG(REG_TO_CMP)             \
    if (strcmp(reg_name, #REG_TO_CMP)==0) {      \
        regs->REG_TO_CMP = value;                \
    }

/*
  Set the register @reg_name with the value @value.
  @regs is assumed to be holding the current register values of @pid.
*/
void handle_set(char *reg_name, unsigned long value,
                struct user_regs_struct *regs, int pid) {
    // TODO
    
    CMPSET_REG(rax); CMPSET_REG(rbx); CMPSET_REG(rcx); CMPSET_REG(rdx);
    CMPSET_REG(rbp); CMPSET_REG(rsp); CMPSET_REG(rsi); CMPSET_REG(rdi);
    CMPSET_REG(r8);  CMPSET_REG(r9);  CMPSET_REG(r10); CMPSET_REG(r11);
    CMPSET_REG(r12); CMPSET_REG(r13); CMPSET_REG(r14); CMPSET_REG(r15);
    CMPSET_REG(rip); CMPSET_REG(eflags);
	set_registers(pid, regs);
    return;
}


void stringToUnsignedCharArray(const char *input, int byteSize, unsigned char buf[]) {
    int inputLength = byteSize*2;
    // Initialize buf with zeros
    memset(buf, 0, byteSize);
    char temp_array[3];

    // Convert each pair of characters to unsigned char and store in reverse order
    for (int i = 0; i < inputLength; i += 2) {
        // int shift = (inputLength - i - 2)*4;
    	memset(temp_array, 0, 2);
	memcpy(temp_array, input + i, 2);
	temp_array[2] = '\0';
	long temp = strtol(temp_array, NULL, 16);
        buf[(inputLength - i - 2) / 2] = (unsigned char)temp;
    }

    for (int i = 0; i < byteSize; i++){
    }
}

void generateCharArray(const char *input, int size, char *output) {
    int inputLength = strlen(input);

    // Check if the specified size is sufficient
    if (size >= inputLength) {
    	// Calculate the number of zeros to prepend
    	int zerosToPrepend = size - inputLength;

    	// Fill the output array with zeros and copy the input string
    	memset(output, '0', zerosToPrepend);
    	strcpy(output + zerosToPrepend, input);
    }
    else{

    	memcpy(output, input, size);
    }
}

void prompt_user(int child_pid, struct user_regs_struct *regs,
                 ADDR_T baseaddr) {
    TODO_UNUSED(child_pid);
    TODO_UNUSED(baseaddr);

    const char* prompt_symbol = ">>> ";

    for(;;) {
        fprintf(stdout, "%s", prompt_symbol);
        char action[1024];
        scanf("%1024s", action);

        if(strcmp("regs", action)==0) {
            handle_regs(regs);
            continue;
        }

        if(strcmp("help", action)==0 || strcmp("h", action)==0) {
            handle_help();
            continue;
        }

        if(strcmp("get", action)==0) {
            // TODO
	    char input_reg[10];
	    scanf("%10s", input_reg);
	    handle_get(input_reg, regs);
	    continue;

	    // ------- MUST CHECK ---------------------------------------------//
	    // what if undefined registers? -> it doesn't assert error
	

        }

        if(strcmp("set", action)==0) {
            // TODO
		char input_reg[10];
		scanf("%10s", input_reg);
		long value;
		scanf("%ld", &value);

		handle_set(input_reg, value, regs, child_pid);
		continue;
		
        }

        if(strcmp("read", action)==0 || strcmp("r", action)==0) {
            // TODO
		ADDR_T input_addr;
		scanf("%llx", &input_addr);
		unsigned int input_size;
		scanf("%x", &input_size);

		unsigned char buf[MAX_RW];

		ADDR_T base_addr = get_image_baseaddr(child_pid);

		LOG("HANDLE CMD: read [%llx][%llx] [%d]\n", input_addr, input_addr + base_addr, input_size);

		handle_read(child_pid, base_addr + input_addr, buf, input_size);
		continue;

	}

        if(strcmp("write", action)==0 || strcmp("w", action)==0) {
            // TODO
		ADDR_T input_addr;
		scanf("%llx", &input_addr);

		char value[MAX_RW + 2];
		unsigned char buf[MAX_RW];
		scanf("%1026s", value);

		unsigned int input_size;
		scanf("%x", &input_size);

		char value_array[MAX_RW];
		generateCharArray(value + 2, 2 * input_size, value_array);

		ADDR_T base_addr = get_image_baseaddr(child_pid);
		LOG("HANDLE CMD: write [%llx][%llx] [%s] <= [%x]\n", input_addr, input_addr + base_addr, value_array, input_size);

		stringToUnsignedCharArray(value_array, input_size, buf);
		//longLongToUnsignedCharArray(value, buf);
		handle_write(child_pid, base_addr + input_addr, buf, input_size);
		continue;
        }

        if(strcmp("break", action)==0 || strcmp("b", action)==0) {
            // TODO
        }

        if(strcmp("step", action)==0 || strcmp("s", action)==0) {
            // TODO
        }

        if(strcmp("continue", action)==0 || strcmp("c", action)==0) {
            // TODO
        }

        if(strcmp("quit", action)==0 || strcmp("q", action)==0) {
            LOG("HANDLE CMD: quit\n");
            exit(0);
        }

        WARN("Not available commands\n");
    }
}


/*
  Get the current registers of @pid, and store it to @regs.
*/
void get_registers(int pid, struct user_regs_struct *regs) {
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs)<0) {
        die("Error getting registers");
    }
    return;
}


/*
  Set the registers of @pid with @regs.
*/
void set_registers(int pid, struct user_regs_struct *regs) {
    // TODO
        if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		fprintf(stdout, "ptrace setregs error");
}


/*
  Get the base address of the main binary image, 
  loaded to the process @pid.
  This base address is the virtual address.
*/

/*
ADDR_T get_image_baseaddr(int pid) {
    hr_procmaps** procmap = construct_procmaps(pid);
    ADDR_T baseaddr = 0;
    // TODO
    TODO_UNUSED(procmap);
    return baseaddr;
}
*/

ADDR_T get_image_baseaddr(int pid) {
    hr_procmaps** procmap = construct_procmaps(pid);
    ADDR_T baseaddr = 0;

    if (procmap != NULL) {
        int i = 0;
        while (procmap[i] != NULL) {
            // Checking if the map is executable and has a pathname
            if ((procmap[i]->perms & PERMS_EXECUTE) && procmap[i]->pathname != NULL) {
                // Assuming the main executable's pathname does not contain typical shared library patterns
                if (strstr(procmap[i]->pathname, ".so") == NULL && strstr(procmap[i]->pathname, "[") == NULL) {
                    baseaddr = procmap[i]->addr_begin;
                    break;
                }
            }
            i++;
        }
    }

    // Cleanup if needed
    // free_procmaps(procmap); // Uncomment if there's a function to free the procmaps array

    return baseaddr;
}

/*
  Perform the job if the software breakpoint is fired.
  This includes to restore the original value at the breakpoint address.
*/
void handle_break_post(int pid, struct user_regs_struct *regs) {
    // TODO
    TODO_UNUSED(pid);
    TODO_UNUSED(regs);
}


/* HINT: No need to change this function */
void tracer(int child_pid) {
    int child_status;

    LOG("Tracer with pid=%d\n", getpid());

    wait(&child_status);

    ADDR_T baseaddr = get_image_baseaddr(child_pid);

    int steps_count = 0;
    struct user_regs_struct tracee_regs;
    set_debug_state(child_pid, SINGLE_STEP);

    while(1) {
        wait(&child_status);
        steps_count += 1;

        if(WIFEXITED(child_status)) {
            LOG("Exited in %d steps with status=%d\n",
                steps_count, child_status);
            break;
        }
        get_registers(child_pid, &tracee_regs);

        LOG("[step %d] rip=%llx child_status=%d\n", steps_count,
            tracee_regs.rip, child_status);

        handle_break_post(child_pid, &tracee_regs);
        prompt_user(child_pid, &tracee_regs, baseaddr);
    }
}

/* HINT: No need to change this function */
int main(int argc, char* argv[]) {
    char* usage = "USAGE: ./snudbg <cmd>";

    if (argc < 2){
        die(usage);
    }

    int pid = fork();

    switch (pid) {
    case -1:
        die("Error forking");
        break;
    case 0:
        tracee(argv+1);
        break;
    default:
        tracer(pid);
        break;
    }
    return 0;
}





































