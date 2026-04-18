#include "process.h"
#include "tracer.h"
#include <capstone/capstone.h>
#include <cstdio>
#include <unistd.h>

int main(int argc, char *argv[])
{
    printf("Started!\n");
    char *input_path = nullptr;
    char *output_path = nullptr;

    int opt;

    while ((opt = getopt(argc, argv, "i:o:")) != -1) {
        switch (opt) {
        case 'i':
            input_path = optarg;
            break;

        case 'o':
            output_path = optarg;
            break;

        default:
            fprintf(stderr, "Usage: %s -i <input.exe> -o <output.json>\n",
                    argv[0]);
            return 1;
        }
    }

    if (!input_path || !output_path) {
        fprintf(stderr, "Missing required arguments\n");
        fprintf(stderr, "Usage: %s -i <input.exe> -o <output.json>\n", argv[0]);
        return 1;
    }

    Process proc(input_path);
    Tracer tracer(proc);

    auto code_sections = proc.get_code_sections();
    printf("code sections: %zu\n", code_sections.size());

    if (!tracer.static_analysis(code_sections)) {
        fprintf(stderr, "Static analysis failed\n");
        return 1;
    }

    printf("\n\n");

    if (!tracer.trace()) {
        fprintf(stderr, "Tracing failed\n");
        return 1;
    }

    if (!tracer.write_coverage(output_path)) {
        fprintf(stderr, "Failed to write coverage to %s\n", output_path);
        return 1;
    }

    return 0;
}
