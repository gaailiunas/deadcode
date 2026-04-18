#ifndef TRACER_H
#define TRACER_H

#include "process.h"
#include <capstone/capstone.h>
#include <list>
#include <unordered_map>

#define INT3 0xcc
#define TRAP_FLAG 0x100
#define WINDOW_SIZE 10

struct InsnInfo {
    uint64_t addr;
    char mnemonic[16];
    char op_str[64];
};

struct Branch {
    InsnInfo info;
    uint64_t taken;     // imm target or resolved indirect
    uint64_t not_taken; // insn[j+1].address, 0 if unconditional
    int taken_count = 0;
    int not_taken_count = 0;
    int total_count = 0;
    std::unordered_map<uint64_t, int> targets;
    unsigned int insn_id;
    std::vector<InsnInfo> window;
};

struct Return {
    InsnInfo info;
    std::unordered_map<uint64_t, int>
        targets; // key = return target, value = how many times observed
    unsigned int insn_id;
    std::vector<InsnInfo> window;
    int total_count = 0;
};

struct Call {
    InsnInfo info;
    std::unordered_map<uint64_t, int>
        targets; // key = call target, value = how many times observed
    std::unordered_map<uint64_t, int>
        return_targets; // key = pushed return addr, value = how many times seen
    unsigned int insn_id;
    std::vector<InsnInfo> window;
    int total_count = 0;
};

enum class RangeType {
    CALL,
    RET,
    JMP,
};

struct ExecutedRange {
    uint64_t start;
    uint64_t end;
    uint64_t next_addr;
    RangeType type;
    bool fallthrough;
};

class Tracer {
  public:
    Tracer(Process &proc);

    bool static_analysis(const std::vector<CodeSection> &code_sections);
    bool trace();
    bool write_coverage(const char *path);

    std::vector<ExecutedRange> &get_executed_ranges()
    {
        return m_executed_ranges;
    }

  private:
    Process &m_process;
    std::unordered_map<uint64_t, uint8_t> m_patched;
    bool m_running = true;

    std::list<Branch> m_branches;
    std::list<Return> m_returns;
    std::list<Call> m_calls;

    std::unordered_map<uint64_t, Branch *> m_jmp_to_branch;
    std::unordered_map<uint64_t, Return *> m_ret_to_return;
    std::unordered_map<uint64_t, Call *> m_call_to_call;

    std::vector<ExecutedRange> m_executed_ranges;

    bool is_jump(cs_insn *i);
    bool is_ret(cs_insn *i);
    bool is_call(cs_insn *i);

    bool add_bp_patch(uint64_t addr);
    bool add_bp(uint64_t addr);
};

#endif // TRACER_H
