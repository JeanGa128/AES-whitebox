#include<stdint.h>

void constructIdentity(const int size, uint8_t (*matrix)[size]);

void stripMatrix(const int lines, const int columns, const int from, const int to, uint8_t (* const matrix)[columns], uint8_t (* result)[from-to]);

void groupMatrix(const int lines, const int columns1, const int columns2, uint8_t (* const matrix1)[columns1], uint8_t (* const matrix2)[columns2], uint8_t (* result)[columns1+columns2]);

void multiplyMatrix(const int lines1, const int columns1, const int columns2, uint8_t (* const matrix1)[columns1], uint8_t (* const matrix2)[columns2], uint8_t (*result)[columns2]);

void generateInvertibleMatrix(uint8_t size, uint8_t (* matrix)[size], uint8_t (* invert)[size]);