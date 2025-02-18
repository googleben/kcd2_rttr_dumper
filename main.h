//
// Created by Ben on 2/10/2025.
//
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <format>
#include <map>
#include <X86Disasm.hh>

#include "DumpHandler.h"
#include <ranges>

#ifndef MAIN_H
#define MAIN_H

static bool OUTPUT_DEBUG_INFO = false;
static bool COUT_DEBUG_ERRORS = true;
static bool COUT_DEBUG_PRINTS = false;

static HANDLE proc;
static uintptr_t mod;
static DumpHandler* dumpHandler = nullptr;

void log(const std::string& message);

inline DWORD findProcessID(const std::wstring& processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (!_wcsicmp(entry.szExeFile, processName.c_str()))
            {
                pid = entry.th32ProcessID;
                break;
            }
        }
        while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

inline uintptr_t findModuleBase(DWORD pid, const std::wstring& moduleName)
{
    uintptr_t baseAddr = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W me32{};
    me32.dwSize = sizeof(me32);

    if (Module32FirstW(snapshot, &me32))
    {
        do
        {
            if (!_wcsicmp(me32.szModule, moduleName.c_str()))
            {
                baseAddr = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                break;
            }
        }
        while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);
    return baseAddr;
}

template <typename T>
std::string hex(T t)
{
    return std::format("{:x}", t);
}

inline void checkErr(const std::string& info = "Unspecified error")
{
    DWORD err = GetLastError();
    if (err != ERROR_SUCCESS)
    {
        std::cout << info << ": " << err << std::endl;
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            nullptr, err, 0, (LPSTR)&messageBuffer, 0, nullptr);
        std::cout << messageBuffer << std::endl;
        LocalFree(messageBuffer);
        exit(1);
    }
}
template <typename T>
T readMem(uintptr_t addr)
{
    if (dumpHandler != nullptr)
        return dumpHandler->readMem<T>(addr);
    T buf;
    auto ok = ReadProcessMemory(proc, (LPCVOID)addr, &buf, sizeof(buf), nullptr);
    if (!ok) checkErr("ReadProcessMemory "+hex(addr));
    return buf;
}

uintptr_t readUintptr(uintptr_t addr);

template <typename T>
std::unique_ptr<T> readBuf(uintptr_t addr)
{
    if (dumpHandler != nullptr)
        return dumpHandler->readBuf<T>(addr);
    std::unique_ptr<T> buf = std::make_unique<T>();
    auto ok = ReadProcessMemory(proc, (LPCVOID)addr, buf, sizeof(T), nullptr);
    if (!ok) checkErr("ReadProcessMemory "+hex(addr));
    return buf;
}

inline std::string readStr(uintptr_t addr)
{
    if (dumpHandler != nullptr)
        return dumpHandler->readString(addr);
    std::string buf;
    for (int i = 0; i < 0x4000; i++)
    {
        char c = readMem<char>(addr++);
        if (c == 0) break;
        buf += c;
    }
    return buf;
}

inline std::string readStdString(uintptr_t addr)
{
    auto len = readMem<uintptr_t>(addr+0x10);
    if (len < 0x10)
    {
        return readStr(addr);
    }
    return readStr(readMem<uintptr_t>(addr));
}


template<typename T>
struct stdVec
{
    uintptr_t beginPtr;
    uintptr_t endPtr;
    uintptr_t capPtr;
    explicit stdVec(uintptr_t addr)
    {
        beginPtr = readMem<uintptr_t>(addr);
        endPtr = readMem<uintptr_t>(addr + 8);
        capPtr = readMem<uintptr_t>(addr + 16);
    }
    bool hasData() const
    {
        return beginPtr != 0 && beginPtr != endPtr;
    }
    uint32_t len() const
    {
        return (endPtr - beginPtr) / 8;
    }
    struct iterator
    {
        uintptr_t pos;
        iterator(uintptr_t pos) : pos(pos) {}
        iterator& operator++()
        {
            pos += 8;
            return *this;
        }
        T operator*()
        {
            return T(readMem<uintptr_t>(pos));
        }
        bool operator==(const iterator& other)
        {
            return pos == other.pos;
        }
        bool operator!=(const iterator& other)
        {
            return pos != other.pos;
        }
    };
    iterator begin()
    {
        return iterator(beginPtr);
    }
    iterator end()
    {
        return iterator(endPtr);
    }
    std::vector<T> toVec()
    {
        std::vector<T> vec;
        for (auto i = begin(); i != end(); ++i)
        {
            vec.push_back(*i);
        }
        return vec;
    }
};
struct type_data;
struct property;
struct ReadProperty;
struct method;

struct enumeration_wrapper
{
    uintptr_t addr;
    std::vector<std::string> getNames() const;
    uintptr_t getEndMetadata() const;
    type_data getInnerType() const;
    bool isConstexpr() const;
    size_t getConstexprSize() const;
    bool isEmpty() const;
    template <typename T>
    std::vector<T> getValues() const
    {
        auto endMetadata = addr+getEndMetadata();
            std::vector<T> vec;
        if (isConstexpr())
        {
            auto n = getConstexprSize();
            auto start = endMetadata + 0x10 * n;
            for (auto i = start; i < start + sizeof(T) * n; i += sizeof(T))
            {
                vec.emplace_back(readMem<T>(i));
            }
            return vec;
        }
        auto start = readMem<uintptr_t>(endMetadata+0x30);
        auto end = readMem<uintptr_t>(endMetadata+0x38);
        for (auto i = start; i < end; i+=sizeof(T))
        {
            vec.push_back(readMem<T>(i));
        }
        return vec;
    }
};
struct class_data
{
    uintptr_t addr;
    stdVec<type_data> getBaseTypes() const;
    stdVec<type_data> getDerivedTypes() const;
    stdVec<property> getProperties() const;
    stdVec<method> getMethods() const;
    std::vector<ReadProperty> readProperties() const;
};
struct type_data
{
    uintptr_t addr;
    uintptr_t getNamePtr() const;
    std::string getName() const;
    uintptr_t getClassDataPtr() const;
    class_data getClassData() const;
    std::vector<ReadProperty> readProperties() const;
    uintptr_t getEnumDataPtr() const;
    size_t getTypeSize() const;
    size_t getPointerDimension() const;
    enumeration_wrapper getEnumData() const;
};
struct property
{
    uintptr_t addr;
    uintptr_t getNameAddr() const;
    std::string getName() const;
    std::pair<bool, uintptr_t> getPropOffsetAddr() const;
    std::pair<bool, uintptr_t> getPropOffset() const;
    type_data getType() const;
    ReadProperty read() const;
};

enum VtableOffsetDisc
{
    Empty,
    Vtable,
    Other
};

struct VtableOffsetInfo
{
public:
    VtableOffsetDisc disc;
    std::optional<uintptr_t> off;
    VtableOffsetInfo(VtableOffsetDisc disc, std::optional<uintptr_t> off) : disc(disc), off(off) {}
};

struct method
{
    //0x0: vtable
    //0x8: string_view m_name
    //0x18: string_view m_signature_view
    //0x28: type m_declaring_type
    //0x30: std::string m_signature
    //0x50: metadata
    uintptr_t addr;
    std::string getName() const;
    std::string getSignature() const;
    uintptr_t findFunction() const;
    VtableOffsetInfo* findFunctionVtableOffset() const;
};

struct ReadProperty
{
    uintptr_t addrI;
    std::string addr;
    std::string name;
    std::string type;
    bool isOffset;
    property prop;
    constexpr bool operator<(const ReadProperty& rhs) const
    {
        return addrI < rhs.addrI;
    }
};
struct NamespaceSp
{
    std::vector<std::string> namespaceSp;
    std::vector<std::string> restStart;
    std::vector<std::string> restEnd;
    std::optional<std::string> templateParams;
};

struct WorkerResult
{
    std::string pseudo;
    std::string code;
    std::string name;
    NamespaceSp namespaceSp;
};

struct StringTee {
    std::string& s1;
    std::string& s2;

    StringTee(std::string& first, std::string& second)
        : s1(first), s2(second) {}

    StringTee& operator+=(const std::string& rhs) {
        s1 += rhs;
        s2 += rhs;
        return *this;
    }
};

struct NamespaceOut
{
private:
    std::FILE* file = nullptr;
    std::string ns;
public:
    std::string dirPath;
    std::string filePath;
    std::vector<std::string> namespacePath;
    std::map<std::string, std::shared_ptr<NamespaceOut>> children;

    NamespaceOut(std::string parentDirPath, std::vector<std::string> namespacePath)
    {
        this->namespacePath = namespacePath;
        if (namespacePath.empty())
        {
            dirPath = std::format("{:s}/out", parentDirPath);
        } else
        {
            dirPath = std::format("{:s}/{:s}", parentDirPath, namespacePath.back());
        }
        filePath = std::format("{:s}/out.hpp", dirPath);
    }

    std::shared_ptr<NamespaceOut> get(const std::string& ns)
    {
        if (children.contains(ns)) return children[ns];
        std::vector<std::string> v;
        for (auto& s : namespacePath)
        {
            v.push_back(s);
        }
        v.push_back(ns);
        const auto tmp = new NamespaceOut(dirPath, v);
        std::shared_ptr<NamespaceOut> ans {tmp};
        children[ns] = ans;
        return ans;
    }

    std::FILE* getFile();

    void close(std::FILE* header)
    {
        for (auto c : children | std::views::values)
        {
            c->close(header);
        }
        if (file == nullptr) return;
        std::string w;
        if (!namespacePath.empty())
        {
            w = "}\n";
            std::fwrite(w.c_str(), w.length(), 1, file);
        }
        w = "\n\n#endif\n";
        std::fwrite(w.c_str(), w.length(), 1, file);
        std::fclose(file);
        file = nullptr;
        w = "#include \"";
        for (auto& s : namespacePath)
        {
            w += s;
            w += "/";
        }
        w += "out.hpp\"\n";
        std::fwrite(w.c_str(), w.length(), 1, header);
    }
};


#endif //MAIN_H
