#ifndef PROCESS_H
#define PROCESS_H

#include <cstdint>
#include <processthreadsapi.h>
#include <vector>

struct CodeSection {
    uint64_t va;
    uint32_t size;
    char name[9];
};

class Process {
  public:
    Process(const char *path);
    ~Process();

    PROCESS_INFORMATION *get_process_info() { return &m_pi; }
    uint64_t get_base_addr() const { return m_base_addr; }

    std::vector<CodeSection> get_code_sections(uint64_t *oep = nullptr);

  private:
    uint64_t m_base_addr;
    PROCESS_INFORMATION m_pi{};
};

#endif // PROCESS_H