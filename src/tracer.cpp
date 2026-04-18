#include "tracer.h"
#include "process.h"
#include <errhandlingapi.h>
#include <memoryapi.h>
#include <vector>
#include <windows.h>
#include <winnt.h>

Tracer::Tracer(Process &proc) : m_process(proc) {}

bool Tracer::is_jump(cs_insn *i)
{
    switch (i->id) {
    case X86_INS_JMP:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
        return true;
    default:
        return false;
    }
}

bool Tracer::is_ret(cs_insn *i)
{
    switch (i->id) {
    case X86_INS_RET:
    case X86_INS_RETFQ:
    case X86_INS_RETF:
        return true;
    default:
        return false;
    }
}

bool Tracer::is_call(cs_insn *i) { return i->id == X86_INS_CALL; }

bool Tracer::add_bp_patch(uint64_t addr)
{
    size_t bytes_written;
    uint8_t patch = INT3;
    return WriteProcessMemory(m_process.get_process_info()->hProcess,
                              (LPVOID)addr, &patch, 1, &bytes_written) &&
           bytes_written == 1;
}

bool Tracer::add_bp(uint64_t addr)
{
    uint8_t orig;
    size_t bytes_read;
    if (!ReadProcessMemory(m_process.get_process_info()->hProcess,
                           (LPCVOID)addr, &orig, 1, &bytes_read) ||
        bytes_read != 1) {
        return false;
    }
    m_patched[addr] = orig;
    return add_bp_patch(addr);
}

bool Tracer::static_analysis(const std::vector<CodeSection> &code_sections)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t bytes_read;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (auto &cs : code_sections) {
        std::vector<uint8_t> buf(cs.size);
        if (!ReadProcessMemory(m_process.get_process_info()->hProcess,
                               (LPCVOID)cs.va, buf.data(), cs.size,
                               &bytes_read) ||
            bytes_read == 0) {
            fprintf(stderr, "ReadProcessMemory failed for section %s: %lu\n",
                    cs.name, GetLastError());
            continue;
        }

        count = cs_disasm(handle, buf.data(), bytes_read, cs.va, 0, &insn);
        if (count <= 0) {
            fprintf(stderr, "failed to disassemble given code\n");
            continue;
        }

        for (size_t j = 0; j < count; j++) {
            if (is_jump(&insn[j])) {
                cs_x86_op *op = &insn[j].detail->x86.operands[0];

                Branch b{};
                b.info.addr = insn[j].address;
                b.not_taken = (insn[j].id != X86_INS_JMP && j + 1 < count)
                                  ? insn[j + 1].address
                                  : 0;

                if (op->type == X86_OP_IMM) {
                    b.taken = op->imm;
                }
                else {
                    b.taken = 0;
                }

                m_branches.push_back(b);
                Branch *bptr = &m_branches.back();
                m_jmp_to_branch[insn[j].address] = bptr;

                bptr->insn_id = insn[j].id;
                strncpy(bptr->info.mnemonic, insn[j].mnemonic,
                        sizeof(bptr->info.mnemonic));
                strncpy(bptr->info.op_str, insn[j].op_str,
                        sizeof(bptr->info.op_str));

                size_t start = (j >= WINDOW_SIZE) ? j - WINDOW_SIZE : 0;
                size_t end =
                    (j + WINDOW_SIZE < count) ? j + WINDOW_SIZE : count - 1;
                for (size_t k = start; k <= end; k++) {
                    InsnInfo info{};
                    info.addr = insn[k].address;
                    strncpy(info.mnemonic, insn[k].mnemonic,
                            sizeof(info.mnemonic));
                    strncpy(info.op_str, insn[k].op_str, sizeof(info.op_str));
                    bptr->window.push_back(info);
                }
            }
            else if (is_ret(&insn[j])) {
                Return r{};
                r.info.addr = insn[j].address;

                m_returns.push_back(r);
                Return *rptr = &m_returns.back();
                m_ret_to_return[insn[j].address] = rptr;

                rptr->insn_id = insn[j].id;
                strncpy(rptr->info.mnemonic, insn[j].mnemonic,
                        sizeof(rptr->info.mnemonic));
                strncpy(rptr->info.op_str, insn[j].op_str,
                        sizeof(rptr->info.op_str));

                size_t start = (j >= WINDOW_SIZE) ? j - WINDOW_SIZE : 0;
                size_t end =
                    (j + WINDOW_SIZE < count) ? j + WINDOW_SIZE : count - 1;
                for (size_t k = start; k <= end; k++) {
                    InsnInfo info{};
                    info.addr = insn[k].address;
                    strncpy(info.mnemonic, insn[k].mnemonic,
                            sizeof(info.mnemonic));
                    strncpy(info.op_str, insn[k].op_str, sizeof(info.op_str));
                    rptr->window.push_back(info);
                }
            }
            else if (is_call(&insn[j])) {
                Call c{};
                c.info.addr = insn[j].address;

                m_calls.push_back(c);
                Call *cptr = &m_calls.back();
                m_call_to_call[insn[j].address] = cptr;

                cptr->insn_id = insn[j].id;
                strncpy(cptr->info.mnemonic, insn[j].mnemonic,
                        sizeof(cptr->info.mnemonic));
                strncpy(cptr->info.op_str, insn[j].op_str,
                        sizeof(cptr->info.op_str));

                size_t start = (j >= WINDOW_SIZE) ? j - WINDOW_SIZE : 0;
                size_t end =
                    (j + WINDOW_SIZE < count) ? j + WINDOW_SIZE : count - 1;
                for (size_t k = start; k <= end; k++) {
                    InsnInfo info{};
                    info.addr = insn[k].address;
                    strncpy(info.mnemonic, insn[k].mnemonic,
                            sizeof(info.mnemonic));
                    strncpy(info.op_str, insn[k].op_str, sizeof(info.op_str));
                    cptr->window.push_back(info);
                }
            }
            else {
                continue;
            }

            if (!add_bp(insn[j].address)) {
                fprintf(stderr, "failed to add breakpoint at 0x%p\n",
                        (void *)insn[j].address);
            }
        }

        cs_free(insn, count);
    }

    cs_close(&handle);
    ResumeThread(m_process.get_process_info()->hThread);
    return true;
}

bool Tracer::trace()
{
    DEBUG_EVENT dbgev{};
    uint64_t pending_repatch = 0;
    size_t bytes_written;

    uint64_t last_rip = 0;

    while (m_running && WaitForDebugEvent(&dbgev, INFINITE)) {
        switch (dbgev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD *rec = &dbgev.u.Exception.ExceptionRecord;

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(m_process.get_process_info()->hThread, &ctx);

            if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) {
                void *hit_addr = rec->ExceptionAddress;

                auto it = m_patched.find((uint64_t)hit_addr);
                if (it == m_patched.end()) {
                    printf("hit unknown breakpoint at 0x%p\n", hit_addr);
                    ContinueDebugEvent(
                        m_process.get_process_info()->dwProcessId,
                        m_process.get_process_info()->dwThreadId,
                        DBG_EXCEPTION_NOT_HANDLED);
                    continue;
                }

                uint8_t orig = it->second;
                if (!WriteProcessMemory(m_process.get_process_info()->hProcess,
                                        hit_addr, &orig, 1, &bytes_written) ||
                    bytes_written != 1) {
                    fprintf(stderr,
                            "WriteProcessMemory failed for breakpoint at 0x%p, "
                            "error=%lu\n",
                            hit_addr, GetLastError());
                }

                ctx.Rip -= 1;
                ctx.EFlags |= TRAP_FLAG;

                SetThreadContext(m_process.get_process_info()->hThread, &ctx);
                pending_repatch = (uint64_t)hit_addr;
            }
            else if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP) {
                if (pending_repatch) {
                    bool fallthrough = false;

                    add_bp_patch(pending_repatch);

                    RangeType type{};

                    auto it = m_jmp_to_branch.find(pending_repatch);
                    if (it != m_jmp_to_branch.end()) {
                        type = RangeType::JMP;

                        Branch *b = it->second;
                        if (b->taken == 0) {
                            b->taken = ctx.Rip; // first time resolving indirect
                        }
                        b->targets[ctx.Rip]++;
                        b->total_count++;
                        if (ctx.Rip == b->taken) {
                            b->taken_count++;
                        }
                        else if (ctx.Rip == b->not_taken) {
                            b->not_taken_count++;
                            fallthrough = true;
                        }
                    }
                    else {
                        auto it2 = m_ret_to_return.find(pending_repatch);
                        if (it2 != m_ret_to_return.end()) {
                            type = RangeType::RET;
                            Return *r = it2->second;
                            r->targets[ctx.Rip]++;
                            r->total_count++;
                        }
                        else {
                            auto it3 = m_call_to_call.find(pending_repatch);
                            if (it3 != m_call_to_call.end()) {
                                type = RangeType::CALL;
                                Call *c = it3->second;
                                c->targets[ctx.Rip]++;
                                c->total_count++;

                                uint64_t pushed_ret_addr;
                                ReadProcessMemory(
                                    m_process.get_process_info()->hProcess,
                                    (LPCVOID)ctx.Rsp, &pushed_ret_addr,
                                    sizeof(pushed_ret_addr), &bytes_written);
                                c->return_targets[pushed_ret_addr]++;
                            }
                        }
                    }
                    if (last_rip != 0) {
                        ExecutedRange r{};
                        r.start = last_rip;
                        r.end = pending_repatch;
                        r.next_addr = ctx.Rip;
                        r.type = type;
                        r.fallthrough = fallthrough;
                        m_executed_ranges.push_back(r);
                    }

                    pending_repatch = 0;
                    last_rip = ctx.Rip;
                }
            }

            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            printf("exitting\n");
            m_running = false;
            break;
        }
        }

        ContinueDebugEvent(dbgev.dwProcessId, dbgev.dwThreadId, DBG_CONTINUE);
    }

    return true;
}

bool Tracer::write_coverage(const char *path) { return true; }
