//
// Created by Ben on 2/13/2025.
//

#include <codecvt>
#include <windows.h>
#include <dbghelp.h>
#include <filesystem>
#include <fstream>
#include <iostream>

#ifndef DUMPHANDLER_H
#define DUMPHANDLER_H

#define USE_IFSTREAM 0

inline bool dumpExists()
{
    return std::filesystem::exists("../game.dmp");
}

struct DumpSegment
{
    void* base;
    size_t size;
    uintptr_t start;
    uintptr_t end;
};

class DumpHandler {
public:
    HANDLE file;
    HANDLE map;
    std::vector<uint8_t> fileBuffer;
    void* base;
    MINIDUMP_HEADER* header;
    MINIDUMP_DIRECTORY* dir;
    std::vector<DumpSegment> segments;
    bool useIfstream;
    DumpHandler(const std::string& path, bool useIfstream = false)
    {
        this->useIfstream = useIfstream;
        if (!std::filesystem::exists(path))
        {
            throw std::runtime_error(std::format("File \"{:s}\" does not exist", path));
        }
        if (useIfstream)
        {
            std::cout << "Reading game.dmp..." << std::endl;
            auto ifile = new std::ifstream(path, std::ios::binary | std::ios::ate);
            auto size = ifile->tellg();
            ifile->seekg(0, std::ios::beg);
            fileBuffer.resize(size);
            if (!ifile->read(reinterpret_cast<char*>(fileBuffer.data()), size))
            {
                std::cerr << "Failed to read file" << std::endl;
                exit(1);
            }
            ifile->close();
            delete ifile;
            std::cout << "game.dmp read" << std::endl;
            base = fileBuffer.data();
        }
        else
        {
            file = CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            map = CreateFileMapping(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
        }
        header = static_cast<MINIDUMP_HEADER*>(base);
        dir = reinterpret_cast<MINIDUMP_DIRECTORY*>(reinterpret_cast<uintptr_t>(base) + header->StreamDirectoryRva);
        for (auto i = 0; i < header->NumberOfStreams; i++)
        {
            auto e = &dir[i];
            if (e->StreamType == Memory64ListStream)
            {
                auto s = reinterpret_cast<MINIDUMP_MEMORY64_LIST*>(reinterpret_cast<uint8_t*>(base) + e->Location.Rva);
                uintptr_t pos = reinterpret_cast<uintptr_t>(base)+s->BaseRva;
                for (auto j = 0; j < s->NumberOfMemoryRanges; j++)
                {
                    auto r = &s->MemoryRanges[j];
                    uintptr_t start = r->StartOfMemoryRange;
                    uintptr_t size = r->DataSize;
                    uintptr_t end = start + size;
                    DumpSegment segment {reinterpret_cast<void*>(pos), size, start, end };
                    segments.push_back(segment);
                    pos += size;
                }
            }
            if (e->StreamType == MemoryListStream)
            {
                auto s = reinterpret_cast<MINIDUMP_MEMORY_LIST*>(reinterpret_cast<uint8_t*>(base) + e->Location.Rva);
                for (auto j = 0; j < s->NumberOfMemoryRanges; j++)
                {
                    auto r = &s->MemoryRanges[j];
                    uintptr_t start = r->StartOfMemoryRange;
                    uintptr_t size = r->Memory.DataSize;
                    uintptr_t end = start + size;
                    uintptr_t pos = reinterpret_cast<uintptr_t>(base) + r->Memory.Rva;
                    DumpSegment segment {reinterpret_cast<void*>(pos), size, start, end };
                    segments.push_back(segment);
                }
            }
        }
    }
    ~DumpHandler()
    {
        UnmapViewOfFile(base);
        if (!useIfstream)
        {
            CloseHandle(map);
            CloseHandle(file);
        }
    }
    uintptr_t findAddressInFile(uintptr_t addr) const;

    uintptr_t findAddress(uintptr_t addr) const;

    template <typename T>
    T readMem(const uintptr_t addr)
    {
        return *reinterpret_cast<T*>(findAddress(addr));
    }
    template <typename T>
    std::unique_ptr<T> readBuf(uintptr_t addr)
    {
        return std::unique_ptr<T>(readMem<T>(addr));
    }
    std::string readString(const uintptr_t addr)
    {
        auto ptr = reinterpret_cast<char*>(findAddress(addr));
        return {ptr};
    }
    uintptr_t findModuleBase(const std::string& name) const
    {
        for (auto i = 0; i < header->NumberOfStreams; i++) {
            auto entry = &dir[i];
            if (entry->StreamType == ModuleListStream) {
                auto moduleList = reinterpret_cast<MINIDUMP_MODULE_LIST*>(static_cast<uint8_t*>(base) + entry->Location.Rva);

                for (auto j = 0; j < moduleList->NumberOfModules; j++) {
                    auto module = &moduleList->Modules[j];

                    // Get the module name from the minidump
                    auto moduleNameRva = module->ModuleNameRva;
                    auto moduleName = reinterpret_cast<MINIDUMP_STRING*>(static_cast<uint8_t*>(base) + moduleNameRva);
                    auto l = WideCharToMultiByte(CP_UTF8, 0, moduleName->Buffer, moduleName->Length, nullptr, 0, nullptr, nullptr);
                    std::vector<char> buffer(l+5);
                    WideCharToMultiByte(CP_UTF8, 0, moduleName->Buffer, moduleName->Length, buffer.data(), l+5, nullptr, nullptr);
                    std::string str(buffer.data());
                    if (str.ends_with(name)) {
                        return module->BaseOfImage;
                    }
                }
            }
        }

        // Return 0 if the module is not found
        return 0;
    }
};



#endif //DUMPHANDLER_H
