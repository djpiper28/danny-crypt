#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef TUX_PNG
#include <png.h>

struct PNG {
    png_structp	png_ptr;
    png_infop info_ptr;

    png_uint_32 width;
    png_uint_32 height;

    png_bytepp rows;

    int bit_depth;
    int color_type;
    int interlace_method;
    int compression_method;
    int filter_method;
    int bytes_pp;
};
#endif

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
              struct text key,
              char iv,
              int block) {
    char vector = iv;
    for (size_t i = 0; i < in.length; i++) {
        in.buffer[i] ^= vector;
        in.buffer[i] ^= key.buffer[(i + block) % key.length];
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
                struct text key,
                char iv,
                int block) {
    // Get f(r)
    struct text fOfR;
    fOfR.length = r->length;
    fOfR.buffer = (char *) malloc(sizeof(char) * fOfR.length);
    memcpy(fOfR.buffer, r->buffer, fOfR.length);
    hashText(fOfR, key, iv, block);

    // Xor f(r) and l
    xorText(*l, fOfR);
    free(fOfR.buffer);

    // Swap l and r
    swapLandR(l, r);
}

#define ROUNDS 21
void applyRounds(struct text *l,
                 struct text *r,
                 struct text key,
                 char iv,
                 int block) {
    for (size_t i = 0; i < ROUNDS; i++) {
        applyRound(l, r, key, iv, block);
    }

    // Swap l and r iff there is an even amount of rounds
    if (ROUNDS % 2 == 1)
        swapLandR(l, r);
}

#define BLOCK_SIZE 128
#define BUFFER_LENGTH BLOCK_SIZE * 20

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
    size_t len = 0;

#ifdef TUX_PNG
    // open the file
    FILE *inputFile = fopen("tux.png", "rb");

    // read the file as png
    struct PNG png;
    png.png_ptr = png_create_read_struct (PNG_LIBPNG_VER_STRING,
                                          NULL, NULL, NULL);

    if (png.png_ptr == NULL) {
        fprintf(stderr, "png_ptr is NULL\n");
        exit(13);
    }

    png.info_ptr = png_create_info_struct (png.png_ptr);

    if (png.info_ptr == NULL) {
        fprintf(stderr, "png_info_ptr is NULL\n");
        exit(14);
    }

    png_init_io (png.png_ptr, inputFile);
    png_read_png (png.png_ptr, png.info_ptr, 0, 0);
    png_get_IHDR (png.png_ptr, png.info_ptr, & png.width, & png.height, & png.bit_depth,
                  & png.color_type, & png.interlace_method, & png.compression_method,
                  & png.filter_method);

    png.rows = png_get_rows (png.png_ptr, png.info_ptr);
    png.bytes_pp = png_get_rowbytes (png.png_ptr, png.info_ptr) / png.width;

    // close the file
    fclose(inputFile);

    // load png to rows
    len = png.width * png.height * png.bytes_pp;
    size_t len_real = len;
    if (len_real % BLOCK_SIZE != 0) {
        len_real += BLOCK_SIZE - (len_real % BLOCK_SIZE);
    }

    char *rows = (char *) malloc(sizeof(char) * len_real);
    memset(rows, 0, len_real);

    int i = 0;
    for (int y = 0; y < png.height; y++) {
        for (int x = 0; x < png.width * png.bytes_pp; x++) {
            rows[i] = png.rows[y][x];
            i++;
        }
    }
    struct text text = {rows, len_real};
#else
    struct text text = getText();
#endif

    if (argc != 2) {
        printf("How to use: ./dannycrypt [KEY]\n");
        printf("Then type into stdin either the text to en/decrypt.\n");
        return 1;
    }

    struct text key = {argv[1], strlen(argv[1])};

    // Pad text (this will be in bounds as I
    // malloc in multiples of 128
    size_t modulo = text.length % BLOCK_SIZE;
    if (modulo > 0) {
        for (int i = 0; i < BLOCK_SIZE - modulo; i++) {
            text.buffer[text.length + i + 1] = 0;
        }
        text.length += BLOCK_SIZE - modulo;
    }

    // Calculate blocks
    size_t blocks = text.length / BLOCK_SIZE;
    char iv = key.buffer[key.length - 1];

    for (size_t block = 0; block < blocks; block++) {
        size_t offset = block * BLOCK_SIZE;
        len = BLOCK_SIZE / 2;

        struct text l = {text.buffer + offset, len};
        struct text r = {text.buffer + offset + len, len};

        applyRounds(&l, &r, key, iv, block);
    }

#ifdef TUX_PNG
    // Put rows back in png
    i = 0;
    for (int y = 0; y < png.height; y++) {
        for (int x = 0; x < png.width * png.bytes_pp; x++) {
            png.rows[y][x] = rows[i];
            i++;
        }
    }

    // Save png
    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;
    FILE *outputFile = fopen("tux2.png", "wb");

    png_ptr = png_create_write_struct (PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    info_ptr = png_create_info_struct (png_ptr);

    png_set_IHDR (png_ptr,
                  info_ptr,
                  png.width,
                  png.height,
                  png.bit_depth,
                  png.color_type,
                  png.interlace_method,
                  png.compression_method,
                  png.filter_method);

    png_init_io (png_ptr, outputFile);
    png_set_rows (png_ptr, info_ptr, png.rows);
    png_write_png (png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);
    png_destroy_write_struct (&png_ptr, &info_ptr);
    fclose(outputFile);

    // Free png rows
    for (unsigned int y = 0; y < png.height; y++) {
        png_free (png.png_ptr, png.rows[y]);
    }
    png_free (png.png_ptr, png.rows);
    free(rows);
#else
    for (size_t i = 0; i < text.length; i++) {
        putchar(text.buffer[i]);
    }
    free(text.buffer);
#endif

    return 0;
}
