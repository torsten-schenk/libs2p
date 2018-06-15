#pragma once

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

static void hexdump(
		const void *mem,
		size_t bytes)
{
	size_t cur;
	size_t i;
	size_t address = 0;
	const unsigned char *base = mem;
	FILE *out = stdout;
	while(bytes > 0) {
		cur = MIN(bytes, 16);
		fprintf(out, "%08x  ", (unsigned int)address);
		for(i = 0; i < cur; i++) {
			if(i == 8)
				fprintf(out, " ");
			fprintf(out, "%02x ", base[i]);
		}
		for(; i < 16; i++) {
			if(i == 8)
				fprintf(out, " ");
			fprintf(out, "   ");
		}
		fprintf(out, " |");
		for(i = 0; i < cur; i++)
			if(base[i] <= 0x20 || base[i] >= 0x7f)
				fprintf(out, ".");
			else
				fprintf(out, "%c", base[i]);
		fprintf(out, "|\n");
		bytes -= cur;
		address += cur;
		base += cur;
	}
}



