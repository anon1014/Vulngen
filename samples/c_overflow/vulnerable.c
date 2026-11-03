#include <stdio.h>
#include <string.h>

#define KEY_MAX 16
#define LINE_MAX_LEN 256

struct setting {
    char key[KEY_MAX];
    const char *value;
};

static const char *skip_spaces(const char *s) {
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    return s;
}

static int parse_line(const char *line, struct setting *out) {
    const char *eq = strchr(line, '=');
    if (eq == NULL) {
        return -1;
    }
    size_t len = (size_t)(eq - line);
    memcpy(out->key, line, len);
    out->key[len] = '\0';
    out->value = skip_spaces(eq + 1);
    return 0;
}

int main(void) {
    char buf[LINE_MAX_LEN];
    struct setting s;
    int count = 0;

    while (fgets(buf, sizeof buf, stdin) != NULL) {
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] == '#' || buf[0] == '\0') {
            continue;
        }
        if (parse_line(buf, &s) == 0) {
            printf("%-16s -> %s\n", s.key, s.value);
            count++;
        }
    }
    printf("%d settings loaded\n", count);
    return 0;
}
