// Copyright (c) 2020 ElephantSe4l. All Rights Reserved.
// Released under MPL-2.0, see LICENCE for more information.

#include "syscall.hpp"
#include <stdexcept>
#include "native.hpp"
#include "utils.hpp"

#if defined(__GNUC__) && !defined(__clang__)
#define ALLOC_ON_CODE \
__attribute__((section(".text")))
#else
#define ALLOC_ON_CODE \
_Pragma("section(\".text\")") \
__declspec(allocate(".text"))
#endif

#define HASH(API)		(utils::_HashStringRotr32A((PCHAR) API))
// Custom syscall stub. Receives the number of the service to call as the first argument (rcx).
// The remaining arguments act as the parameters of the service called. In order to pass them
// properly, the stub needs to move forward every parameter by one. (e.g. second -> first,
// third -> second... n -> n-1).

ALLOC_ON_CODE unsigned char manual_syscall_stub[] = {
    0x48, 0x89, 0xC8,                                    // mov rax, rcx
    0x48, 0x89, 0xD1,                                    // mov rcx, rdx
    0x4C, 0x89, 0xC2,                                    // mov rdx, r8
    0x4D, 0x89, 0xC8,                                    // mov r8, r9
    0x4C, 0x8B, 0x4C, 0x24, 0x28,                        // mov r9, [rsp+28h]
    0x49, 0x89, 0xCA,                                    // mov r10, rcx
    0x48, 0x83, 0xC4, 0x08,                              // add rsp, 8
    0x0F, 0x05,                                          // syscall
    0x48, 0x83, 0xEC, 0x08,                              // sub rsp, 8
    0xC3                                                 // ret
};


// Custom syscall stub similar to `manual_syscall_stub` but this time it will act as a trampoline
// to another syscall instruction. Receives the number of the service to call as the first argument
// (rcx) but also requires the address of the syscall instruction as the second argument (rdx). As
// with `manual_syscall_stub` the stub needs to forward every argument but this time by two.

ALLOC_ON_CODE unsigned char masked_syscall_stub[] = {
    0x41, 0x55,                                          // push r13
    0x41, 0x56,                                          // push r14
    0x49, 0x89, 0xD6,                                    // mov r14, rdx
    0x49, 0x89, 0xCD,                                    // mov r13, rcx
    0x4C, 0x89, 0xC1,                                    // mov rcx, r8
    0x4C, 0x89, 0xCA,                                    // mov rdx, r9
    0x4C, 0x8B, 0x44, 0x24, 0x38,                        // mov r8, [rsp+38h]
    0x4C, 0x8B, 0x4C, 0x24, 0x40,                        // mov r9, [rsp+40h]
    0x48, 0x83, 0xC4, 0x28,                              // add rsp, 28h
    0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,            // lea r11, [rip+0x0C] ----
    0x41, 0xFF, 0xD3,                                    // call r11               |
    0x48, 0x83, 0xEC, 0x28,                              // sub rsp, 28h           |
    0x41, 0x5E,                                          // pop r14                |
    0x41, 0x5D,                                          // pop r13                |
    0xC3,                                                // ret                    |
    //                                                                             |
    0x4C, 0x89, 0xE8,                                    // mov rax, r13      <----
    0x49, 0x89, 0xCA,                                    // mov r10, rcx
    0x41, 0xFF, 0xE6                                     // jmp r14
};


void calls::Syscall::ExtractStubs() noexcept {
  const auto peb = reinterpret_cast<native::PEB *>(__readgsqword(0x60));

  // The first loaded module is the process' image, the second is ntdll
  const auto ntdll_ldr_entry = reinterpret_cast<native::LdrDataEntry *>(peb->Ldr->InLoadOrderModuleList.Flink->Flink);
  const auto ntdll_base = reinterpret_cast<uintptr_t>(ntdll_ldr_entry->DllBase);

  const auto dos_header = reinterpret_cast<native::DOSHeader *>(ntdll_base);
  const auto nt_headers = reinterpret_cast<native::NTHeaders64 *>(ntdll_base + dos_header->e_lfanew);

  const auto
      export_dir = reinterpret_cast<native::ExportDirectory *>(ntdll_base + nt_headers->OptionalHeader.DataDirectory[native::kExport].VirtualAddress);
  //runtime function table
  const auto
      runtimefunctable = reinterpret_cast<native::RuntimeFunctionTable*>(ntdll_base + nt_headers->OptionalHeader.DataDirectory[native::kException].VirtualAddress);
  const auto functions_table = reinterpret_cast<uint32_t *>(ntdll_base + export_dir->AddressOfFunctions);
  const auto names_table = reinterpret_cast<uint32_t *>(ntdll_base + export_dir->AddressOfNames);
  const auto names_ordinals_table = reinterpret_cast<uint16_t *>(ntdll_base + export_dir->AddressOfNameOrdinals);
  int ssn = 0;

  for (size_t i = 0; i < runtimefunctable[i].BeginAddress; i++)
  {
      for (size_t j = 0; j < export_dir->NumberOfFunctions; j++)
      {
          if (functions_table[names_ordinals_table[j]] == runtimefunctable[i].BeginAddress) {
              auto function_name = reinterpret_cast<PCHAR>(ntdll_base + names_table[j]);

              //insert to map
              syscall_map.insert({ HASH(function_name),ssn });

              // if this is a syscall, increase the ssn value.
              if (*(USHORT*)function_name == 'wZ') ssn++;
          }
      }
  }
}


//[[nodiscard]] uintptr_t freshycalls::Syscall::GetStubAddr(std::string_view stub_name) {
//  for (const auto &pair : stub_map) {
//    if (pair.second == stub_name) {
//      return pair.first;
//    }
//  }
//
//  throw std::runtime_error(utils::FormatString("[sisyphus::Syscall::GetStubAddr] Stub \"%s\" not found!", stub_name.data()));
//}
uintptr_t calls::Syscall::FindSyscallOffset() noexcept {

    INT64 offset = 0;
    BYTE syscall_signature[] = { (BYTE)0x0F, (BYTE)0x05, (BYTE)0xC3 };

    const auto peb = reinterpret_cast<native::PEB*>(__readgsqword(0x60));
    const auto ntdll_ldr_entry = reinterpret_cast<native::LdrDataEntry*>(peb->Ldr->InLoadOrderModuleList.Flink->Flink);
    const auto ntdll_base = reinterpret_cast<uintptr_t>(ntdll_ldr_entry->DllBase);
    const auto dos_header = reinterpret_cast<native::DOSHeader*>(ntdll_base);
    const auto nt_headers = reinterpret_cast<native::NTHeaders64*>(ntdll_base + dos_header->e_lfanew);
    const auto opt_headers = (nt_headers->OptionalHeader);
    INT64 dllSize = opt_headers.SizeOfImage;

    BYTE* currentbytes = (BYTE*)ntdll_base;

    while (TRUE)
    {

        if (*(reinterpret_cast<BYTE*>(currentbytes)) == syscall_signature[0] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 1)) == syscall_signature[1] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 2)) == syscall_signature[2])
        {
            return ntdll_base + offset;
        }

        offset++;

        if (offset + 3 > dllSize)
            return INFINITE;

        currentbytes = reinterpret_cast<BYTE*>(ntdll_base + offset);
    }


};

[[nodiscard]] uint32_t calls::Syscall::GetSyscallNumber(uint32_t function_name_hashed) {
  const auto syscall_entry = syscall_map.find(function_name_hashed);
  if (syscall_entry == syscall_map.end()) {
    throw std::runtime_error(utils::FormatString("[sisyphus::Syscall::GetSyscallNumber] Stub \"%s\" not found!", function_name_hashed));
  }

  return syscall_entry->second;
}
