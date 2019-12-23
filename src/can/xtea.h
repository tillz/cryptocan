#include <stdint.h>
//reference implementation, public domain
void encipher (unsigned int num_cycles, uint32_t v[2], uint32_t const k[4]);
void decipher (unsigned int num_cycles, uint32_t v[2], uint32_t const k[4]);
void btea(uint32_t *v, int n, uint32_t const key[4]);