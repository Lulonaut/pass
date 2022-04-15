#include <cjson/cJSON.h>
#include <crypt.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <termios.h>

#define FILE_NAME "pass.json"
#define DEBUG 0

int string_eq(char *str, ...);

void write_json(cJSON *json);

char *user_input(char *prompt, int allow_whitespaces);

char *get_password(char *prompt);

char *base64encode(const void *b64_encode_this, int length);

char *base64decode(const void *b64_decode_this, int length);


int main() {
    FILE *fp;
    fp = fopen(FILE_NAME, "r");
    if (fp == 0) {
        FILE *new_file;
        new_file = fopen(FILE_NAME, "w");
        fputs("{}", new_file);
        fclose(new_file);
        fp = fopen(FILE_NAME, "r");
    }

    char *buffer;
    long length;
    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, 0);
    buffer = malloc(length);
    if (buffer) {
        fread(buffer, 1, length, fp);
    } else {
        fputs("Error while reading file.\n", stderr);
        return 1;
    }
    fclose(fp);

    cJSON *json = cJSON_Parse(buffer);
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

    cJSON *passwords = cJSON_GetObjectItemCaseSensitive(json, "passwords");

    while (1) {
        char input[1000];
        fputs(">", stdout);
        if (fgets(input, 1000, stdin) == NULL) {
            //end of stdin
            break;
        }
        //fgets also gets the \n at the end
        input[strcspn(input, "\n")] = '\0';
        if (string_eq(input, "q", "quit", NULL) == 0) {
            break;
        } else if (string_eq(input, "l", "list", NULL) == 0) {
            cJSON *current_element = NULL;
            cJSON_ArrayForEach(current_element, passwords) {
                cJSON *username_item = cJSON_GetObjectItem(current_element, "username");
                cJSON *website_item = cJSON_GetObjectItem(current_element, "website");
                printf("%s:%s:%s\n", current_element->string, cJSON_GetStringValue(username_item),
                       cJSON_GetStringValue(website_item));
            }
        } else if (string_eq(input, "add", "a", "new", NULL) == 0) {
            char *name = user_input("name (used as key, no whitespaces):", 0);
            char *website = user_input("Website name:", 1);
            char *username = user_input("Username:", 1);
            char *pass = get_password("password:");
            pass[strcspn(pass, "\n")] = '\0';

            unsigned char to_encrypt[strlen(pass)];
            unsigned char enc_out[80];
            strcpy(to_encrypt, pass);
            AES_encrypt(to_encrypt, enc_out, &enc_key);
            char *base64 = base64encode(enc_out, 80);

            cJSON *new_entry = cJSON_CreateObject();
            cJSON_AddStringToObject(new_entry, "website", website);
            cJSON_AddStringToObject(new_entry, "username", username);
            cJSON_AddStringToObject(new_entry, "password", base64);

            cJSON_AddItemToObject(passwords, name, new_entry);
            write_json(json);
        } else if (string_eq(input, "get", "g", NULL) == 0) {
            char *name = user_input("Key?", 0);
            if (cJSON_HasObjectItem(passwords, name)) {
                cJSON *entry = cJSON_GetObjectItem(passwords, name);
                cJSON *password_entry = cJSON_GetObjectItem(entry, "password");
                char *encrypted_password = cJSON_GetStringValue(password_entry);
                char *base64_dec = base64decode(encrypted_password, strlen(encrypted_password));

                unsigned char to_decrypt[128];
                unsigned char dec_out[80];
                strcpy(to_decrypt, base64_dec);
                AES_decrypt(to_decrypt, dec_out, &dec_key);
                puts(dec_out);
            } else {
                puts("Unknown key.");
            }
        } else {
            puts("Unknown command");
        }
    }

    write_json(json);
    fflush(stdout);
    return 0;
}

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

char *user_input(char *prompt, int allow_whitespaces) {
    char *res = malloc(128 * sizeof(char));
    while (1) {
        fputs(prompt, stdout);
        char input[128];
        fgets(input, 128, stdin);
        if (!allow_whitespaces) {
            int contains_whitespace = strchr(input, ' ') != 0;
            if (contains_whitespace) {
                puts("Input contained whitespaces, try again.");
                continue;
            }
        }
        strcpy(res, input);
        break;
    }
    res[strcspn(res, "\n")] = '\0';
    return res;
}

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

char *base64encode(const void *b64_encode_this, int length) {
    BIO *b64_bio, *mem_bio;
    BUF_MEM *mem_bio_mem_ptr;
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64_bio, b64_encode_this, length);
    BIO_flush(b64_bio);
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);
    BIO_set_close(mem_bio, BIO_NOCLOSE);
    BIO_free_all(b64_bio);
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';
    return (*mem_bio_mem_ptr).data;
}

char *base64decode(const void *b64_decode_this, int length) {
    BIO *b64_bio, *mem_bio;
    char *base64_decoded = calloc((length * 3) / 4 + 1, sizeof(char));
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_write(mem_bio, b64_decode_this, length);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_byte_index = 0;
    while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) {
        decoded_byte_index++;
    }
    BIO_free_all(b64_bio);
    return base64_decoded;
}