//
// Created by Ben on 2/13/2025.
//

#include "DumpHandler.h"

uintptr_t DumpHandler::findAddressInFile(uintptr_t addr) const
{
    return findAddress(addr)-reinterpret_cast<uintptr_t>(base);
}

uintptr_t DumpHandler::findAddress(uintptr_t addr) const
{
    auto tmp = tryFindAddress(addr);
    if (tmp.has_value()) return tmp.value();
    throw std::runtime_error("Failed to read memory at "+std::format("{:x}", addr));
}

std::optional<uintptr_t> DumpHandler::tryFindAddress(uintptr_t addr) const
{
    for (auto s : segments)
    {
        if (s.start <= addr && s.end >= addr)
        {
            auto off = addr - s.start;
            return reinterpret_cast<uintptr_t>(s.base) + off;
        }
    }
    return std::nullopt;
}
