#include <cjson/cJSON.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

//int string_eq(char *strings[], char check[], ...);
int string_eq(char *str, ...);


int main() {
    FILE *fp;
    fp = fopen("pass.json", "r");
    if (fp == 0) {
        pclose(fp);
        FILE *new_file;
        new_file = fopen("pass.json", "w");
        fputs("{}", new_file);
        fclose(new_file);
        fp = fopen("pass.json", "r");
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
        fputs("Malformed json, delete the file or correct the errors.", stderr);
        return 1;
    }
    if (!cJSON_HasObjectItem(json, "passwords")) {
        cJSON_AddObjectToObject(json, "passwords");
    }
    cJSON *passwords = cJSON_GetObjectItemCaseSensitive(json, "passwords");

    while (1) {
        char input[1000];
        puts(">");
        fgets(input, 1000, stdin);
        //fgets also gets the \n at the end
        input[strlen(input) - 1] = '\0';

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
        }
    }

    char *json_string = cJSON_Print(json);
    cJSON_Minify(json_string);
//    printf("%s\n", json_string);
    fflush(stdout);
    return 0;
}

//int string_eq(char *strings[], char check[], ...) {
//    int i = 0;
//    while (strings[i]) {
//        if (strcmp(strings[i], check) == 0) {
//            return 0;
//        }
//        i++;
//    }
//    return 1;
//}

int string_eq(char *str, ...) {
    va_list arg;
    va_start(arg, str);
    char *comp = str;

    str = va_arg(arg, char*);
    while (str) {
        if (strcmp(comp, str) == 0) {
            return 0;
        } else {
            str = va_arg(arg, char*);
        }
    }
    ((void) arg);
    return 1;
}