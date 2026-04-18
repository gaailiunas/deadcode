#include "process.h"
#include <stdexcept>
#include <windows.h>
#include <winternl.h>

Process::Process(const char *path)
{
    STARTUPINFOA si = {};
    si.cb = sizeof(si);

    bool ok = CreateProcessA(path, nullptr, nullptr, nullptr, false,
                             CREATE_SUSPENDED | DEBUG_PROCESS, nullptr, nullptr,
                             &si, &m_pi);

    if (!ok) {
        throw std::runtime_error("failed to open process");
    }

    PROCESS_BASIC_INFORMATION pbi;
    size_t bytes_read;
    NtQueryInformationProcess(m_pi.hProcess, ProcessBasicInformation, &pbi,
                              sizeof(pbi), nullptr);

    if (!ReadProcessMemory(m_pi.hProcess, (uint8_t *)pbi.PebBaseAddress + 0x10,
                           &m_base_addr, sizeof(m_base_addr), &bytes_read) ||
        bytes_read != sizeof(m_base_addr)) {
        throw std::runtime_error("failed to read base address from PEB");
    }
}

Process::~Process()
{
    CloseHandle(m_pi.hProcess);
    CloseHandle(m_pi.hThread);
}

std::vector<CodeSection> Process::get_code_sections(uint64_t *oep)
{
    std::vector<CodeSection> result;

    IMAGE_DOS_HEADER dos{};
    SIZE_T n = 0;

    if (!ReadProcessMemory(m_pi.hProcess, (LPCVOID)m_base_addr, &dos,
                           sizeof(dos), &n) ||
        n != sizeof(dos)) {
        return result;
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return result;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(m_pi.hProcess, (LPCVOID)(m_base_addr + dos.e_lfanew),
                           &nt, sizeof(nt), &n) ||
        n != sizeof(nt)) {
        return result;
    }

    if (oep) {
        *oep = nt.OptionalHeader.AddressOfEntryPoint;
    }

    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        return result;
    }

    uint16_t num_sections = nt.FileHeader.NumberOfSections;
    uintptr_t sec_offset = m_base_addr + dos.e_lfanew +
                           offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                           nt.FileHeader.SizeOfOptionalHeader;

    for (uint16_t i = 0; i < num_sections; i++) {
        IMAGE_SECTION_HEADER sec{};
        if (!ReadProcessMemory(
                m_pi.hProcess,
                (LPCVOID)(sec_offset + i * sizeof(IMAGE_SECTION_HEADER)), &sec,
                sizeof(sec), &n) ||
            n != sizeof(sec)) {
            continue;
        }

        bool is_code = (sec.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
        if (!is_code) {
            continue;
        }

        CodeSection cs{};
        cs.va = m_base_addr + sec.VirtualAddress;
        cs.size =
            sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        memcpy(cs.name, sec.Name, 8);
        cs.name[8] = '\0';
        result.push_back(cs);
    }
    return result;
}