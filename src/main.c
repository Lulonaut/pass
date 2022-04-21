#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <crypt.h>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define FILE_NAME "pass.json"
#define DEBUG 0
#define PORT        7922
#define MAX_LINE    1000
#define LISTENQ     1024

int client_conn;

int string_eq(char *str, ...);

void write_json(cJSON *json);

char *get_password(char *prompt);

char *base64encode(const void *data, int length);

char *base64decode(const void *data, int length);

ssize_t read_string(int sockd, void *vptr, size_t maxlen, int stop_on_new_line);

ssize_t write_string(int sockd, const void *vptr, size_t n);

int starts_with(char *string, char *prefix);

void list_passwords(char buffer[], cJSON *json);

void add_entry(char buffer[], cJSON *json, AES_KEY enc_key);

void get_entry(char buffer[], cJSON *json, AES_KEY dec_key);

void print_usage(char *prog_name);

void cleanup();

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--daemon") == 0) {
        FILE *fp;
        fp = fopen(FILE_NAME, "r");
        fflush(stdout);
        if (fp == 0) {
            FILE *new_file;
            new_file = fopen(FILE_NAME, "w");
            fputs("{}", new_file);
            fclose(new_file);
            fp = fopen(FILE_NAME, "r");
        }

        char *file_buffer;
        long length;
        fseek(fp, 0, SEEK_END);
        length = ftell(fp);
        fseek(fp, 0, 0);
        file_buffer = malloc(length);
        if (file_buffer) {
            fread(file_buffer, 1, length, fp);
        } else {
            fputs("Error while reading file.\n", stderr);
            return 1;
        }
        fclose(fp);

        cJSON *json = cJSON_Parse(file_buffer);
        free(file_buffer);
        if (json == NULL) {
            fputs("Malformed json, delete the file or correct the errors.\n", stderr);
            return 1;
        }
        if (!cJSON_HasObjectItem(json, "passwords")) {
            cJSON_AddObjectToObject(json, "passwords");
        }
        if (!cJSON_HasObjectItem(json, "master_password")) {
            puts("You don't have a master password set.\nPlease enter one now:");
            char *password = get_password("Password:");

            char *salt = crypt_gensalt("$y$", 0, NULL, -1);
            char *result = crypt(password, salt);
            cJSON_AddStringToObject(json, "master_password", result);
            write_json(json);
            puts("Password saved.");
            free(password);
        }
        char *master_password;
        while (1) {
            master_password = get_password("Master password:");
            char *stored_hash = cJSON_GetStringValue(cJSON_GetObjectItem(json, "master_password"));
            char *check = crypt(master_password, stored_hash);
            if (strcmp(check, stored_hash) != 0) {
                puts("Invalid password, try again!");
            } else {
                break;
            }
        }
        unsigned char key[128];
        strcpy(key, master_password);

        AES_KEY enc_key, dec_key;
        AES_set_encrypt_key(key, 128, &enc_key);
        AES_set_decrypt_key(key, 128, &dec_key);

        int list_s, conn_s;
        struct sockaddr_in servaddr;
        char buffer[MAX_LINE];

        if ((list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            fputs("Error creating listening socket.\n", stderr);
            return 1;
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(PORT);

        if (bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
            fputs("Error calling bind\n", stderr);
            return 1;
        }

        if (listen(list_s, LISTENQ) < 0) {
            fputs("Error calling listen\n", stderr);
            return 1;
        }

        fputs("Now accepting connections...\n", stderr);
        while (1) {
            if ((conn_s = accept(list_s, NULL, NULL)) < 0) {
                fputs("Error calling accept.\n", stderr);
                return 1;
            }

            read_string(conn_s, buffer, MAX_LINE - 1, 1);
            buffer[strcspn(buffer, "\n")] = '\0';
            if (strcmp(buffer, "list") == 0) {
                list_passwords(buffer, json);
            } else if (starts_with(buffer, "add") == 0) {
                add_entry(buffer, json, enc_key);
            } else if (starts_with(buffer, "get") == 0) {
                get_entry(buffer, json, dec_key);
            } else {
                strcpy(buffer, "Unknown command");
            }

            write_string(conn_s, buffer, strlen(buffer));
            close(conn_s);
        }
    } else {
        struct sockaddr_in servaddr;
        char buffer[MAX_LINE];
        char *szAddress = "127.0.0.1";

        if ((client_conn = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            fputs("Error creating socket\n", stderr);
            return 1;
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(PORT);

        inet_aton(szAddress, &servaddr.sin_addr);

        if (connect(client_conn, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
            printf("Daemon is not running. Start it with: %s --daemon\n", argv[0]);
            return 1;
        }
        atexit(cleanup);

        if (argc == 1) {
            print_usage(argv[0]);
            return 1;
        }

        if (strcmp(argv[1], "list") == 0) {
            if (argc != 2) {
                fputs("Warning: Ignoring additional arguments\n", stderr);
            }
            strcpy(buffer, argv[1]);
            goto write;
        }

        if (strcmp(argv[1], "add") == 0) {
            if (argc != 6) {
                printf("Usage: %s add key website username password", argv[0]);
                return 1;
            }
            sprintf(buffer, "%s %s %s %s %s %s", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
            goto write;
        }

        if (strcmp(argv[1], "get") == 0) {
            if (argc != 3) {
                printf("Usage: %s get key", argv[0]);
                return 1;
            }
            sprintf(buffer, "%s %s", argv[1], argv[2]);
            goto write;
        }

        write:
        strcat(buffer, "\n");
        write_string(client_conn, buffer, strlen(buffer));
        read_string(client_conn, buffer, MAX_LINE - 1, 0);
        puts(buffer);
        return 0;
    }
}

/*
 * compares all arguments against the first string using strcmp
 */
int string_eq(char *str, ...) {
    va_list arg;
    va_start(arg, str);
    char *comp = str;

    str = va_arg(arg, char*);
    while (str) {
        if (strcmp(comp, str) == 0) {
            (void) arg;
            return 0;
        } else {
            str = va_arg(arg, char*);
        }
    }
    (void) arg;
    return 1;
}

/*
 * writes the provided object to the file or prints it in debug mode
 */
void write_json(cJSON *json) {
    char *json_string = cJSON_Print(json);
    cJSON_Minify(json_string);

#if DEBUG == 1
    puts(json_string);
    puts("NOT WRITING");
#else
    FILE *fp;
    fp = fopen(FILE_NAME, "w");
    if (fp == 0) {
        fputs("Error while opening file\n", stderr);
        exit(1);
    }
    fputs(json_string, fp);
    fclose(fp);
#endif
}

/*
 * Asks the user for a password with the provided prompt (no echo)
 */
char *get_password(char *prompt) {
    int size = 128;
    char *ret = malloc(size * sizeof(char));
    struct termios oflags, nflags;
    char password[size];

    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    tcsetattr(fileno(stdin), TCSANOW, &nflags);

    fputs(prompt, stdout);
    fgets(password, size, stdin);
    password[strcspn(password, "\n")] = '\0';
    tcsetattr(fileno(stdin), TCSANOW, &oflags);
    strcpy(ret, password);
    return ret;
}

char *base64encode(const void *data, int length) {
    BIO *b64_bio, *mem_bio;
    BUF_MEM *mem_bio_mem_ptr;
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64_bio, data, length);
    BIO_flush(b64_bio);
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);
    BIO_set_close(mem_bio, BIO_NOCLOSE);
    BIO_free_all(b64_bio);
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';
    return (*mem_bio_mem_ptr).data;
}

char *base64decode(const void *data, int length) {
    BIO *b64_bio, *mem_bio;
    char *base64_decoded = calloc((length * 3) / 4 + 1, sizeof(char));
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_write(mem_bio, data, length);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_byte_index = 0;
    while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) {
        decoded_byte_index++;
    }
    BIO_free_all(b64_bio);
    return base64_decoded;
}

/*
 * reads a string from the provided socket
 */
ssize_t read_string(int sockd, void *vptr, size_t maxlen, int stop_on_new_line) {
    ssize_t n, rc;
    char c, *buffer;

    buffer = vptr;

    for (n = 1; n < (long) maxlen; n++) {
        if ((rc = read(sockd, &c, 1)) == 1) {
            *buffer++ = c;
            if (stop_on_new_line && c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;
            else
                break;
        } else {
            if (errno == EINTR)
                continue;
            return -1;
        }
    }

    *buffer = 0;
    return n;
}

/*
 * writes a string to the provided socket
 */
ssize_t write_string(int sockd, const void *vptr, size_t n) {
    size_t nleft = n;
    ssize_t nwritten;
    const char *buffer;

    buffer = vptr;

    while (nleft > 0) {
        if ((nwritten = write(sockd, buffer, nleft)) <= 0) {
            if (errno == EINTR)
                nwritten = 0;
            else
                return -1;
        }
        nleft -= nwritten;
        buffer += nwritten;
    }

    return (long) n;
}

/*
 * Checks if string starts with prefix
 */
int starts_with(char *string, char *prefix) {
    while (*prefix) {
        if (*prefix != *string) return 1;
        prefix++;
        string++;
    }
    return 0;
}

/*
 * Lists all passwords in a short format and writes the output to buffer
 */
void list_passwords(char *buffer, cJSON *json) {
    cJSON *passwords = cJSON_GetObjectItem(json, "passwords");
    memset(buffer, 0, MAX_LINE);
    cJSON *current_element = NULL;
    cJSON_ArrayForEach(current_element, passwords) {
        char *line = malloc(MAX_LINE * sizeof(char));
        cJSON *username_item = cJSON_GetObjectItem(current_element, "username");
        cJSON *website_item = cJSON_GetObjectItem(current_element, "website");
        sprintf(line, "%s:%s:%s\n", current_element->string, cJSON_GetStringValue(username_item),
                cJSON_GetStringValue(website_item));
        strcat(buffer, line);
    }
    if (strlen(buffer) == 0) {
        strcpy(buffer, "No saved passwords.");
    }
}

/*
 * Adds a new password using info from buffer and writes any output to buffer
 */
void add_entry(char *buffer, cJSON *json, AES_KEY enc_key) {
    cJSON *passwords = cJSON_GetObjectItem(json, "passwords");
    char *split;
    strtok(buffer, " ");
    split = strtok(NULL, " ");

    //TODO its up to the client to not cause a segfault here
    char *name = (char *) malloc(MAX_LINE);
    strcpy(name, split);
    split = strtok(NULL, " ");

    char *website = (char *) malloc(MAX_LINE);
    strcpy(website, split);
    split = strtok(NULL, " ");

    char *username = (char *) malloc(MAX_LINE);
    strcpy(username, split);
    split = strtok(NULL, " ");

    char *pass = (char *) malloc(MAX_LINE);
    strcpy(pass, split);
    pass[strcspn(pass, "\n")] = '\0';

    unsigned char to_encrypt[strlen(pass)];
    unsigned char enc_out[80];
    strcpy(to_encrypt, pass);
    AES_encrypt(to_encrypt, enc_out, &enc_key);
    char *base64 = base64encode(enc_out, 80);

    memset(buffer, 0, MAX_LINE);
    cJSON *new_entry = cJSON_CreateObject();
    cJSON_AddStringToObject(new_entry, "website", website);
    cJSON_AddStringToObject(new_entry, "username", username);
    cJSON_AddStringToObject(new_entry, "password", base64);

    memset(buffer, 0, MAX_LINE);
    if (cJSON_HasObjectItem(passwords, name)) {
        strcpy(buffer, "Name already taken");
        return;
    } else {
        puts("Adding!");
        cJSON_AddItemToObject(passwords, name, new_entry);
        write_json(json);
    }
    free(name);
    free(website);
    free(username);
    free(pass);
    strcpy(buffer, "ok");
}

void get_entry(char *buffer, cJSON *json, AES_KEY dec_key) {
    cJSON *passwords = cJSON_GetObjectItem(json, "passwords");
    char *split;
    strtok(buffer, " ");
    split = strtok(NULL, " ");
    char *name = split;
    if (cJSON_HasObjectItem(passwords, name)) {
        cJSON *entry = cJSON_GetObjectItem(passwords, name);
        cJSON *password_entry = cJSON_GetObjectItem(entry, "password");
        char *encrypted_password = cJSON_GetStringValue(password_entry);
        char *base64_dec = base64decode(encrypted_password, strlen(encrypted_password));

        unsigned char to_decrypt[128];
        unsigned char dec_out[80];
        strcpy(to_decrypt, base64_dec);
        AES_decrypt(to_decrypt, dec_out, &dec_key);
        strcpy(buffer, dec_out);
    } else {
        strcpy(buffer, "Unknown name");
    }
}

void print_usage(char *prog_name) {
    printf("Usage: %s [list, add, get] ...\n", prog_name);
}

void cleanup() {
    close(client_conn);
}
