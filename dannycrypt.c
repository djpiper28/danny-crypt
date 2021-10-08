#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 fistel cipher with five rounds
 */

struct text {
    char *buffer;
    size_t length;
};

void xorText(struct text a,
             struct text b) {
    size_t len = (a.length > b.length) * b.length
               + (a.length <= b.length) * a.length;
    for (size_t i = 0; i < len; i++) {
        a.buffer[i] ^= b.buffer[i];
    }
}

void hashText(struct text in,
              struct text key) {
    char vector = in.buffer[in.length - 1];
    for (size_t i = 0; i < in.length; i++) {
        in.buffer[i] ^= vector;
        in.buffer[i] ^= key.buffer[i % key.length];
        vector = in.buffer[i];
    }
}

void swapLandR(struct text *l,
               struct text *r) {
    char *bufferTmp = l->buffer;
    l->buffer = r->buffer;
    r->buffer = bufferTmp;
}

void applyRound(struct text *l,
                struct text *r,
                struct text key) {
    // Get f(r)
    struct text fOfR;
    fOfR.length = r->length;
    fOfR.buffer = (char *) malloc(sizeof(char) * fOfR.length);
    memcpy(fOfR.buffer, r->buffer, fOfR.length);
    hashText(fOfR, key);

    // Xor f(r) and l
    xorText(*l, fOfR);
    free(fOfR.buffer);

    // Swap l and r
    swapLandR(l, r);
}

#define ROUNDS 15
void applyRounds(struct text *l,
                 struct text *r,
                 struct text key) {
    for (size_t i = 0; i < ROUNDS; i++) {
        applyRound(l, r, key);
    }
    swapLandR(l, r);
}

#define BUFFER_LENGTH 4096

struct text getText() {
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_LENGTH);
    int c = getchar();
    size_t count = 0, len = BUFFER_LENGTH;
    while (c != -1) {
        if (count >= len) {
            void * ptr = realloc(buffer, len += BUFFER_LENGTH);

            if (ptr != buffer)
                buffer = ptr;
            if (buffer == NULL) {
                fprintf(stderr, "Error allocating more memory.");
                exit(13);
            }
        }

        buffer[count] = (char) c;
        count++;
        c = getchar();
    }

    struct text out = {buffer, count};
    return out;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("How to use: ./dannycrypt [KEY]\n");
        printf("Then type into stdin either the text to en/decrypt.\n");
        return 1;
    }

    struct text key = {argv[1], strlen(argv[1])};
    struct text text = getText();

    // Pad text (this will be in bounds as I
    // malloc an even amount of memory
    if (text.length % 2 == 1) {
        text.buffer[text.length] = 0;
        text.length++;
    }

    size_t len = text.length / 2;
    struct text l = {text.buffer, len};
    struct text r = {text.buffer + len, len};

    applyRounds(&l, &r, key);
    for (int j = 0; j < l.length; j++)
        printf("%c", l.buffer[j]);
    for (int j = 0; j < r.length; j++)
        printf("%c", r.buffer[j]);

    free(text.buffer);
    return 0;
}
