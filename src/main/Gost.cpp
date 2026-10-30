// СТ РК 4009-2025 (draft: https://ksm.kz/public-discussion/standards/discussion-of-draft-of-st-rk/112716/)
// Writes the Appendix A test vectors for resources/input.bin to resources/output.txt.
#include <cstdio>
#include "Qalqan.h"

int main()
{
	init(0);
	FILE* src = fopen("resources/input.bin", "rb");
	FILE* f = fopen("resources/output.txt", "w");
	if (!src || !f)
	{
		fprintf(stderr, "cannot open resources/input.bin or resources/output.txt\n");
		return 1;
	}
	ShortTestVectors(f, src);
	fclose(src);
	return fclose(f) == 0 ? 0 : 1;
}
