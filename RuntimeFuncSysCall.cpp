#include <iostream>
#include "calls/syscall.hpp"
#include <ntstatus.h>

static auto& syscall = calls::Syscall::get_instance();

#define NtAllocateVirtualMemory_Hashed   0x67d7d4f
#define NtFreeVirtualMemory_Hashed  0xab020df0

int main() {

    void* allocation = nullptr;
    SIZE_T size = 0x1000;
    NTSTATUS status =  syscall.CallSyscall(NtAllocateVirtualMemory_Hashed,
        HANDLE(-1),
        &allocation,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (status != STATUS_SUCCESS) {
        printf("Memory allocation failed with status: 0x%X\n", status);
    }
    else {
        printf("Memory allocated at: %p\n", allocation);
    }

    NTSTATUS statusFree =  syscall.CallSyscall(NtFreeVirtualMemory_Hashed,
        HANDLE(-1),
        &allocation,
        &size,
        MEM_RELEASE);
    if (statusFree != STATUS_SUCCESS) {
        printf("NtFreeVirtualMemory failed with status: 0x%08X\n", statusFree);
    }
    else {
        printf("Memory at %p has been successfully freed.\n", allocation);
    }
    return 0;
}

