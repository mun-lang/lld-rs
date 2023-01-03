#include <lld/Common/CommonLinkerContext.h>
#include <lld/Common/Driver.h>

#include <cstdlib>
#include <iostream>
#include <mutex>

const char *mun_alloc_str(const std::string &str) {
    size_t size = str.length();
    if (size > 0) {
        char *strPtr = reinterpret_cast<char *>(malloc(size + 1));
        memcpy(strPtr, str.c_str(), size + 1);
        return strPtr;
    }
    return nullptr;
}

// LLD seems not to be thread safe. This is terrible. We basically only allow single threaded access
// to the driver using mutexes.
std::mutex concurrencyMutex;

extern "C" {

enum LldFlavor {
    Elf = 0,
    Wasm = 1,
    MachO = 2,
    Coff = 3,
};

struct LldInvokeResult {
    bool success;
    const char *messages;
};

void mun_link_free_result(LldInvokeResult *result) {
    if (result->messages) {
        free(reinterpret_cast<void *>(const_cast<char *>(result->messages)));
    }
}
}

auto getLinkerForFlavor(LldFlavor flavor) {
    switch (flavor) {
        case Wasm:
            return lld::wasm::link;
        case MachO:
            return lld::macho::link;
        case Coff:
            return lld::coff::link;
        case Elf:
        default:
            return lld::elf::link;
    }
}

extern "C" {

LldInvokeResult mun_lld_link(LldFlavor flavor, int argc, const char *const *argv) {
    LldInvokeResult result;

    // Determine which specific linker to use
    auto link = getLinkerForFlavor(flavor);

    // Construct stdout and stderr streams
    std::string outputString, errorString;
    llvm::raw_string_ostream outputStream(outputString);
    llvm::raw_string_ostream errorStream(errorString);

    // Copy arguments
    std::vector<const char *> args(argv, argv + argc);

    // The ELF, wasm, and COFF linkers expects the first argument to be the executable
    // name..
    if (flavor == Elf || flavor == Wasm) {
        args.insert(args.begin(), "lld");
    } else if (flavor == Coff) {
        args.insert(args.begin(), "lld.exe");
    }

    // LLD is not thread-safe at all, so we guard parallel invocation with a mutex
    std::unique_lock lock(concurrencyMutex);
    result.success = link(args, outputStream, errorStream, false, false);

    // Delete the global context and clear the global context pointer, so that it
    // cannot be accessed anymore.
    lld::CommonLinkerContext::destroy();

    std::string resultMessage = errorStream.str() + outputStream.str();
    result.messages = mun_alloc_str(resultMessage);
    return result;
}
}
