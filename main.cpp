#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <format>
#include <X86Disasm.hh>
#include "main.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <queue>
#include <ranges>
#include <shlobj_core.h>
#include <shlwapi.h>

#include "DumpHandler.h"
#include "CLI11.hpp"

struct CryGUID
{
    uint64_t hipart;
    uint64_t lopart;
};

static std::string funkJunk = ">(void) noexcept";

void stripFuncJunk(std::string& str)
{
    if (str.size() > funkJunk.size() && str.compare(str.size() - funkJunk.size(), funkJunk.size(), funkJunk) == 0)
    {
        str.erase(str.size() - funkJunk.size(), funkJunk.size());
    }
}

inline CS_INSN_HOLDER<CX86InsClass>* disasm(uintptr_t funcAddr, uint32_t bufLen = 4096)
{
    CX86Disasm64 dis;
    if (auto err = dis.GetError())
    {
        if (COUT_DEBUG_ERRORS) log(std::format("Disasm error: {:d}", static_cast<int32_t>(err)));
        return nullptr;
    }
    dis.SetDetail(cs_opt_value::CS_OPT_ON);
    dis.SetSyntax(cs_opt_value::CS_OPT_SYNTAX_INTEL);
    byte* buf = new byte[bufLen];
    for (auto i = 0; i < bufLen; i++)
        buf[i] = readMem<byte>(funcAddr + i);
    auto insnh = dis.Disasm(buf, bufLen, funcAddr);
    if (insnh == nullptr)
    {
        if (COUT_DEBUG_ERRORS) log("Disasm error");
        return nullptr;
    }
    //bad, but the destructor is crashing...
    return insnh.release();
}

/// finds the address of a static variable from an rttr getter
/// the structure of the provided function should be something like this:
/// ```
/// MyType* get(MyType** ptr) {
///     if (notInit) {
///         //initialize the static
///     }
///     *ptr = STATIC;
///     return ptr;
/// }
/// ```
/// And should have an instruction formatted like this:
/// ```
/// mov rax, qword ptr [STATIC]
/// ```
/// As the last `mov` before the `ret` to have operands of `rax` and a static memory location
uintptr_t findStaticFromFunction(uintptr_t getClassDataFuncAddr)
{
    static std::map<uintptr_t, uintptr_t> staticMap;
    if (staticMap.contains(getClassDataFuncAddr)) return staticMap[getClassDataFuncAddr];
    auto insnh = disasm(getClassDataFuncAddr);
    CX86InsClass* lastMov = nullptr;
    uintptr_t disp = 0;
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (insn->id == x86_insn::X86_INS_RET)
        {
            if (lastMov == nullptr)
            {
                if (COUT_DEBUG_PRINTS) log("Found ret but no mov");
                staticMap[getClassDataFuncAddr] = 0;
                return 0;
            }
            staticMap.insert(std::pair(getClassDataFuncAddr, disp));
            return disp;
        }
        else if (mn.starts_with("mov") || mn.starts_with("MOV"))
        {
            auto op1 = insn->detail->x86.operands[0];
            auto op2 = insn->detail->x86.operands[1];
            if (op1.type != x86_op_type::X86_OP_REG || op1.reg != x86_reg::X86_REG_RAX
                || op2.type != x86_op_type::X86_OP_MEM || op2.reg != x86_reg::X86_REG_INVALID)
            {
                continue;
            }
            if (COUT_DEBUG_PRINTS) log(std::format("Found mov: {:s}", insn->op_str));
            lastMov = &insn;
            disp = op2.mem.disp + insn->address + insn->size;
        }
    }
    if (COUT_DEBUG_PRINTS) log("Found no ret");
    return 0;
}

type_data findTypeDataFromVfunc(uintptr_t funcAddr)
{
    std::map<uintptr_t, type_data> cache;
    if (cache.contains(funcAddr)) return cache[funcAddr];
    // the function may directly return the static...
    uintptr_t maybeAns = findStaticFromFunction(funcAddr);
    if (maybeAns != 0)
    {
        auto ans = type_data {readMem<uintptr_t>(maybeAns)};
        cache[funcAddr] = ans;
        return ans;
    }
    // if not, it'll call a function that does
    auto insnh = disasm(funcAddr);
    uintptr_t call_loc = 0;
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (insn->id == x86_insn::X86_INS_CALL)
        {
            call_loc = insn->detail->x86.operands[0].imm;
            break;
        }
    }
    if (call_loc == 0)
    {
        if (COUT_DEBUG_ERRORS) log("No call");
        return type_data{};
    }
    if (COUT_DEBUG_PRINTS) log(std::format("Call loc: {:s}", hex(call_loc)));
    auto tPtr = findStaticFromFunction(call_loc);
    auto ans = type_data{readMem<uintptr_t>(tPtr)};
    cache[funcAddr] = ans;
    return ans;
}

static std::queue<std::string> logMessages;
static std::mutex logMutex;
void log(const std::string& message)
{
    logMutex.lock();
    logMessages.push(message);
    logMutex.unlock();
}

bool isAddressValid(uintptr_t addr)
{
    if (dumpHandler != nullptr)
        return dumpHandler->tryFindAddress(addr).has_value();
    MEMORY_BASIC_INFORMATION mbi;
    auto res = VirtualQueryEx(proc, std::bit_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
    SetLastError(0);
    if (res == 0 || mbi.State != MEM_COMMIT)
    {
        return false;
    }
    return true;
}

uintptr_t readUintptr(uintptr_t addr)
{
    return readMem<uintptr_t>(addr);
}

std::vector<std::string> enumeration_wrapper::getNames() const
{
    auto endMetadata = getEndMetadata();
    std::vector<std::string> ans;
    if (isConstexpr())
    {
        auto n = getConstexprSize();
        for (auto i = 0; i < n; i++)
        {
            ans.push_back(readStr(readMem<uintptr_t>(addr + endMetadata + i * 0x10)));
        }
        return ans;
    }
    auto start = readMem<uintptr_t>(addr+endMetadata);
    auto end = readMem<uintptr_t>(addr+endMetadata + 8);
    for (auto i = start; i < end; i+=0x20)
    {
        ans.push_back(readStdString(i));
    }
    return ans;
}

uintptr_t enumeration_wrapper::getEndMetadata() const
{
    auto vtable = readMem<uintptr_t>(addr);
    static std::map<uintptr_t, uintptr_t> enumMap;
    if (enumMap.contains(vtable)) return enumMap[vtable];
    auto name_to_value = readMem<uintptr_t>(vtable + (7 * 0x8));
    auto insnh = disasm(name_to_value);
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (mn.starts_with("mov") || mn.starts_with("MOV") || mn.starts_with("lea") || mn.starts_with("LEA"))
        {
            auto op2 = insn->detail->x86.operands[1];
            if (op2.type == x86_op_type::X86_OP_MEM)
            {
                enumMap[vtable] = op2.mem.disp;
                if (op2.mem.disp == 0)
                {
                    throw std::runtime_error("Metadata displacement 0");
                }
                return op2.mem.disp;
            }
        }
    }
    throw std::runtime_error("Couldn't find end of enum metadata");
}

type_data enumeration_wrapper::getInnerType() const
{
    auto vtable = readMem<uintptr_t>(addr);
    auto get_inner_type = readMem<uintptr_t>(vtable + (2 * 0x8));
    return findTypeDataFromVfunc(get_inner_type);
}

/// returns true if this enum has inline, constexpr-sized std::arrays instead of vectors
bool enumeration_wrapper::isConstexpr() const
{
    auto endMetadata = getEndMetadata();
    auto tmp = readMem<uintptr_t>(addr + endMetadata + 8);
    return tmp < 0x50000;
}

size_t enumeration_wrapper::getConstexprSize() const
{
    static std::map<uintptr_t, size_t> enumMap;
    auto vtable = readMem<uintptr_t>(addr);
    if (enumMap.contains(vtable)) return enumMap[vtable];
    auto getNames = readMem<uintptr_t>(vtable + (4 * 0x8));
    auto insnh = disasm(getNames);
    size_t lastR8 = 0;
    bool hasR8 = false;
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (mn.starts_with("mov"))
        {
            auto op1 = insn->detail->x86.operands[0];
            if (op1.type == x86_op_type::X86_OP_REG && op1.reg == x86_reg::X86_REG_R8 || op1.reg == x86_reg::X86_REG_R8D)
            {
                auto op2 = insn->detail->x86.operands[1];
                if (op2.type == x86_op_type::X86_OP_IMM)
                {
                    lastR8 = op2.imm;
                    hasR8 = true;
                }
            }
        }
        if (insn->id == x86_insn::X86_INS_CALL)
        {
            if (!hasR8)
            {
                throw std::runtime_error("No mov to r8 before call");
            }
            enumMap[vtable] = lastR8;
            return lastR8;
        }
    }
    throw std::runtime_error("No call instruction");
}

bool enumeration_wrapper::isEmpty() const
{
    auto endMetadata = getEndMetadata();
    auto tmp = readMem<uintptr_t>(addr + endMetadata);
    return tmp == 0;
}

stdVec<type_data> class_data::getBaseTypes() const
{
    return stdVec<type_data>(addr + 8);
}

stdVec<type_data> class_data::getDerivedTypes() const
{
    return stdVec<type_data>{addr + 0x20};
}

stdVec<property> class_data::getProperties() const
{
    return stdVec<property>{addr + 0x50};
}

stdVec<method> class_data::getMethods() const
{
    return stdVec<method>{addr + 0x68};
}

std::vector<ReadProperty> class_data::readProperties() const
{
    auto props = getProperties();
    std::vector<ReadProperty> ans;
    for (auto prop : props)
    {
        ans.emplace_back(prop.read());
    }
    //std::sort(ans.begin(), ans.end());
    return ans;
}

uintptr_t type_data::getNamePtr() const
{
    return readMem<uintptr_t>(addr + 0x38);
}

std::string type_data::getName() const
{
    auto ans = readStr(getNamePtr());
    stripFuncJunk(ans);
    return ans;
}

uintptr_t type_data::getClassDataPtr() const
{
    return readMem<uintptr_t>(findStaticFromFunction(readMem<uintptr_t>(addr + 0xb8)));
}

class_data type_data::getClassData() const
{
    return class_data{
        getClassDataPtr()
    };
}

std::vector<ReadProperty> type_data::readProperties() const
{
    return getClassData().readProperties();
}

uintptr_t type_data::getEnumDataPtr() const
{
    return readMem<uintptr_t>(addr + 0x68);
}

size_t type_data::getTypeSize() const
{
    return readMem<size_t>(addr+0x48);
}

size_t type_data::getPointerDimension() const
{
    return readMem<size_t>(addr+0x50);
}

enumeration_wrapper type_data::getEnumData() const
{
    return enumeration_wrapper{getEnumDataPtr()};
}

uintptr_t property::getNameAddr() const
{
    return readMem<uintptr_t>(addr + 0x8);
}

std::string property::getName() const
{
    auto ans = readStr(getNameAddr());
    stripFuncJunk(ans);
    return ans;
}

std::pair<bool, uintptr_t> property::getPropOffsetAddr() const
{
    static std::map<uintptr_t, std::pair<bool, uintptr_t>> propOffsetMap;
    //return addr + 0x20;
    auto vtable = readMem<uintptr_t>(addr);
    auto get_func = readMem<uintptr_t>(vtable + (9 * sizeof(uintptr_t)));
    if (propOffsetMap.contains(get_func)) return propOffsetMap[get_func];

    auto insnh = disasm(get_func);
    uintptr_t ans = 0;
    bool isVirt = false;
    std::map<x86_reg, uintptr_t> regOffs;
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (insn->id == x86_insn::X86_INS_MOVSXD && ans == 0)
        {
            ans = insn->detail->x86.operands[1].mem.disp;
        }
        if (mn.starts_with("mov") || mn.starts_with("MOV"))
        {
            auto op1 = insn->detail->x86.operands[0];
            auto op2 = insn->detail->x86.operands[1];
            if (op1.type == x86_op_type::X86_OP_REG && op2.type == x86_op_type::X86_OP_MEM)
            {
                regOffs[static_cast<x86_reg>(op1.reg)] = op2.mem.disp;
            }
        }
        if (insn->id == x86_insn::X86_INS_CALL && insn->detail->x86.operands[0].type == x86_op_type::X86_OP_REG)
        {
            // function call by register probably means a getter function
            isVirt = true;
            ans = regOffs[insn->detail->x86.operands[0].reg];
            break;
        }
        if (insn->id == x86_insn::X86_INS_CALL && insn->detail->x86.operands[0].type == x86_op_type::X86_OP_MEM)
        {
            isVirt = true;
            std::string opstr(insn->op_str);
            if (opstr.find('+') == std::string::npos)
            {
                throw std::invalid_argument("No '+' in op str");
            }
            ans = insn->detail->x86.operands[0].mem.disp;
            break;
        }
        if (insn->id == x86_insn::X86_INS_RET || insn->id == x86_insn::X86_INS_RETF || insn->id == x86_insn::X86_INS_RETFQ)
        {
            break;
        }
    }
    auto nans = std::make_pair(isVirt, ans);
    propOffsetMap[get_func] = nans;
    return nans;
}

std::pair<bool, uintptr_t> property::getPropOffset() const
{
    auto off = getPropOffsetAddr();
    if (off.second == 0) return std::make_pair(false, 0);
    if (off.first)
    {
        return std::make_pair(true, readMem<uintptr_t>(addr + off.second));
    }
    return std::make_pair(false, readMem<uint32_t>(addr + off.second));
}

type_data property::getType() const
{
    auto vtable = readMem<uintptr_t>(addr);
    auto get_type = readMem<uintptr_t>(vtable + (6 * 0x8));
    return findTypeDataFromVfunc(get_type);
}

ReadProperty property::read() const
{
    auto addrP = getPropOffset();
    bool isOffset = !addrP.first;
    auto addrI = addrP.second;
    if (!isOffset) addrI -= mod;
    std::string addr = std::format("0x{:x}", addrI);
    if (!isOffset) addr = "WHGame.dll+" + addr;
    auto name = this->getName();
    auto type = this->getType().getName();
    return ReadProperty{
        addrI, addr, name, type, isOffset, *this
    };
}

std::string method::getName() const
{
    auto namePtr = readMem<uintptr_t>(addr+0x8);
    return readStr(namePtr);
}

std::string method::getSignature() const
{
    auto sigPtr = readMem<uintptr_t>(addr+0x18);
    return readStr(sigPtr);
}

uintptr_t method::findFunction() const
{
    auto vtable = readMem<uintptr_t>(addr);
    auto invoke_variadic = readMem<uintptr_t>(vtable + (17 * 0x8));
    static std::map<uintptr_t, uintptr_t> funcMap;
    if (funcMap.contains(invoke_variadic)) return funcMap[invoke_variadic];
    auto insnh = disasm(invoke_variadic);
    for (auto i = 0; i < insnh->Count; i++)
    {
        auto insn = insnh->Instructions(i);
        auto mn = std::string(insn->mnemonic);
        if (insn->id == x86_insn::X86_INS_LEA && insn->detail->x86.operands[0].type == x86_op_type::X86_OP_REG
            //&& insn->detail->x86.operands[0].reg == x86_reg::X86_REG_RDX
            && insn->detail->x86.operands[1].type == x86_op_type::X86_OP_MEM)
        {
            auto op2 = insn->detail->x86.operands[1];
            auto off = op2.mem.disp;
            auto func = readMem<uintptr_t>(addr + off);
            if (!isAddressValid(func)) continue;
            funcMap[invoke_variadic] = func;
            return func;
        }
    }
    throw std::runtime_error("no lea in invoke variadic");
}

static VtableOffsetInfo VtableOffsetInfoEmpty = VtableOffsetInfo(Empty, {});

VtableOffsetInfo* method::findFunctionVtableOffset() const
{
    auto func = findFunction();
    static std::map<uintptr_t, VtableOffsetInfo*> funcMap;
    if (funcMap.contains(func)) return funcMap[func];
    //we should only need 9 bytes
    auto insnh = disasm(func, 0x20);
    if (insnh->Count == 0) throw std::runtime_error("no instructions found");
    auto i1 = insnh->Instructions(0);
    if (i1->id == x86_insn::X86_INS_RET || i1->id == x86_insn::X86_INS_RETF || i1->id == x86_insn::X86_INS_RETFQ)
    {
        return &VtableOffsetInfoEmpty;
    }
    if (insnh->Count < 2) throw std::runtime_error("not enough instructions");
    auto i2 = insnh->Instructions(1);
    std::string mn1(i1->mnemonic);
    std::string mn2(i2->mnemonic);
    auto op1 = &i1->detail->x86.operands[0];
    auto op2 = &i1->detail->x86.operands[1];
    auto op3 = &i2->detail->x86.operands[0];
    if (mn1.starts_with("mov") && mn2.starts_with("jmp")
        && op1->type == x86_op_type::X86_OP_REG && op2->type == x86_op_type::X86_OP_MEM
        && op3->type == x86_op_type::X86_OP_MEM
        && op1->reg == x86_reg::X86_REG_RAX && static_cast<x86_reg>(op3->mem.base) == x86_reg::X86_REG_RAX)
    {
        auto off = op3->mem.disp;
        auto ans = new VtableOffsetInfo(VtableOffsetDisc::Vtable, off);
        funcMap[func] = ans;
        return ans;
    }
    auto ans = new VtableOffsetInfo(VtableOffsetDisc::Other, func);
    funcMap[func] = ans;
    return ans;
}

std::FILE* NamespaceOut::getFile()
{
    if (file == nullptr)
    {
        char buff[400];
        auto qual = GetFullPathNameA(dirPath.c_str(), 400, buff, nullptr);
        if (!PathFileExistsA(buff))
            SHCreateDirectoryEx(nullptr, buff, nullptr);
        checkErr();
        fopen_s(&file, filePath.c_str(), "w");
        SetLastError(0);
        ns = "ns_";
        std::string w = "#ifndef ";
        for (auto& s : namespacePath)
        {
            ns += s;
            ns += "_";
        }
        w += ns;
        w += "\n";
        std::fwrite(w.c_str(), w.length(), 1, file);
        w = "#define ";
        w += ns;
        w += "\n";
        std::fwrite(w.c_str(), w.length(), 1, file);
        w = "#include \"all.hpp\"\n";
        std::fwrite(w.c_str(), w.length(), 1, file);
        if (namespacePath.empty()) return file;
        w = "namespace ";
        bool start = true;
        for (auto& s : namespacePath)
        {
            if (!start)
            {
                w += "::";
            }
            start = false;
            w += s;
        }
        w += " {\n";
        std::fwrite(w.c_str(), w.length(), 1, file);
    }
    return file;
}

std::string pad(const std::string& str, const uint32_t len)
{
    auto s = std::string(str);
    while (s.length() < len)
    {
        s.append(" ");
    }
    return s;
}

std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        std::string token = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
}

NamespaceSp splitNamespace(const std::string& name)
{
    auto tmp = split(name, " ");
    std::string actualName = name;
    if (tmp[0] == "class" || tmp[0] == "struct") actualName = tmp[1];
    for (auto& s : tmp)
    {
        if (s.find("::") != std::string::npos)
        {
            actualName = s;
            break;
        }
    }
    std::vector<std::string> restStart;
    std::vector<std::string> restEnd;
    bool end = false;
    for (auto s : tmp)
    {
        if (s != actualName)
        {
            if (end) restEnd.push_back(s);
            else restStart.push_back(s);
        } else
        {
            end = true;
        }
    }
    std::vector<std::string> namespaceSp;
    std::optional<std::string> templateParams;
    if (auto brack = actualName.find('<'); brack != std::string::npos)
    {
        auto first = actualName.substr(0, brack);
        templateParams = actualName.substr(brack);
        namespaceSp = split(first, "::");
    } else
    {
        namespaceSp = split(actualName, "::");
    }
    return {
        namespaceSp,
        restStart,
        restEnd,
        templateParams
    };
}

std::map<uint32_t, WorkerResult> results;
std::mutex resultsMutex;
std::atomic<int32_t> index{0};
std::atomic<int32_t> finished{0};
std::atomic<bool> done{false};

void worker(uintptr_t start, uintptr_t end, std::atomic<int32_t>* status, std::atomic<std::string*>* nameP)
{
    while (true)
    {
        auto i = index.fetch_add(1, std::memory_order_relaxed);
        auto c = start + i * 8;
        status->store(i, std::memory_order_relaxed);
        if (c >= end)
        {
            status->store(-1, std::memory_order_relaxed);
            return;
        }
        std::string pseudo;
        std::string code;
        StringTee both(pseudo, code);
        auto type_data_p = readMem<uintptr_t>(c);
        auto type = type_data{type_data_p};
        auto cl = type.getClassData();
        if (OUTPUT_DEBUG_INFO)
        {
            both += "//type_data pos: ";
            both += hex(type.addr);
            if (dumpHandler != nullptr)
            {
                both += " (";
                both += hex(dumpHandler->findAddressInFile(type.addr));
                both += ")";
            }
            both += "\n";
            both += "//class_data pos: ";
            both += hex(cl.addr);
            if (dumpHandler != nullptr)
            {
                both += " (";
                both += hex(dumpHandler->findAddressInFile(cl.addr));
                both += ")";
            }
            both += "\n";
            both += "//props pos: ";
            both += hex(cl.getProperties().beginPtr);
            if (dumpHandler != nullptr)
            {
                both += " (";
                both += hex(dumpHandler->findAddressInFile(cl.getProperties().beginPtr));
                both += ")";
            }
            both += "\n";
        }
        both += "//size in bytes: 0x";
        both += hex(type.getTypeSize());
        both += "\n";
        both += "//pointer dimension: ";
        both += std::to_string(type.getPointerDimension());
        both += "\n";
        auto name = type.getName();
        nameP->store(&name, std::memory_order::memory_order_relaxed);
        auto namespaceSp = splitNamespace(name);
        auto e = type.getEnumData();
        if (e.addr != 0)
        {
            auto innerType = e.getInnerType();
            auto innerTypeName = innerType.getName();
            if (OUTPUT_DEBUG_INFO)
            {
                both += "//enum_data pos: ";
                both += hex(e.addr);
                if (dumpHandler != nullptr)
                {
                    both += " (";
                    both += hex(dumpHandler->findAddressInFile(e.addr));
                    both += ")";
                }
                both += "\n";
            }
            both += "//enum vtable: ";
            both += hex(readMem<uintptr_t>(e.addr)-mod);
            both += "\n";

            pseudo += "enum ";
            pseudo += name;

            if (!name.starts_with("enum")) code += "enum ";
            code += namespaceSp.namespaceSp.back();

            both += " : ";
            both += innerTypeName;
            both += " {\n";
            if (!e.isEmpty())
            {
                auto names = e.getNames();
                std::vector<std::string> values;
                if (innerTypeName == "char")
                {
                    auto tmp = e.getValues<int8_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "unsigned char")
                {
                    auto tmp = e.getValues<uint8_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "short")
                {
                    auto tmp = e.getValues<int16_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "unsigned short")
                {
                    auto tmp = e.getValues<uint16_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "int")
                {
                    auto tmp = e.getValues<int32_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "unsigned int")
                {
                    auto tmp = e.getValues<uint32_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "long" || innerTypeName == "long long")
                {
                    auto tmp = e.getValues<int64_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                }
                else if (innerTypeName == "unsigned long" || innerTypeName == "unsigned long long")
                {
                    auto tmp = e.getValues<uint64_t>();
                    for (auto it : tmp) values.push_back(std::to_string(it));
                } else
                {
                    throw std::runtime_error("unknown enum inner type");
                }
                auto namesPad = 0;
                for (auto k = 0; k < values.size(); k++)
                {
                    const auto& n = names[k];
                    namesPad = max(namesPad, n.length());
                }
                for (auto k = 0; k < values.size(); k++)
                {
                    const auto& v = values[k];
                    auto n = names[k];
                    n = pad(n, namesPad);
                    both += "    ";
                    both += n;
                    both += " = ";
                    both += v;
                    both += ",\n";
                }
            }
        } else
        {
            pseudo += name;

            if (namespaceSp.templateParams.has_value())
            {
                auto tp = namespaceSp.templateParams.value();
                code += "template ";
                code += tp;
                code += "\n";
            }
            for (const auto& s : namespaceSp.restStart)
            {
                code += s;
                code += " ";
            }
            code += namespaceSp.namespaceSp.back();
            code += " ";
            for (const auto& s : namespaceSp.restEnd)
            {
                code += s;
                code += " ";
            }
            code += "{\n";

            auto supers = cl.getBaseTypes();
            if (supers.len() != 0)
            {
                pseudo += " : ";
            }
            bool comma = false;
            for (auto super : supers)
            {
                if (comma)
                {
                    pseudo += ", ";
                }
                comma = true;
                pseudo += super.getName();
            }

            pseudo += " {\n";

            uint32_t offLen = 0;
            uint32_t nameLen = 0;
            auto props = cl.readProperties();
            for (const auto& it : props)
            {
                if (it.isOffset) offLen = max(offLen, it.addr.length());
                nameLen = max(nameLen, it.name.length());
            }
            for (const auto& it : props)
            {
                if (!it.isOffset)
                {
                    both += "    //Getter: ";
                    both += it.addr;
                    both += "\n";
                }
                both += "    ";
                if (it.isOffset)
                {
                    pseudo += pad(it.addr, offLen);
                    code += "    //Offset: ";
                    code += it.addr;
                } else
                {
                    pseudo += pad("get", offLen);
                }

                pseudo += " : ";
                pseudo += pad(it.name, nameLen);
                pseudo += " : ";
                pseudo += it.type;
                pseudo += ";";

                code += "    ";
                code += it.type;
                code += " ";
                code += it.name;
                code += ";";

                if (OUTPUT_DEBUG_INFO)
                {
                    both += " //";
                    both += hex(it.prop.addr);
                    if (dumpHandler != nullptr)
                    {
                        both += " (";
                        both += hex(dumpHandler->findAddressInFile(it.prop.addr));
                        both += ")";
                    }
                    both += " ";
                    both += hex(readMem<uintptr_t>(it.prop.addr) - mod + 0x180000000);
                }
                both += "\n";
            }
        }
        auto methods = cl.getMethods();
        if (methods.hasData())
        {
            if (methods.len() != 0) both += "\n";
            for (const auto& it : methods)
            {
                auto vtable = readMem<uintptr_t>(it.addr);
                auto mname = it.getName();
                auto msig = it.getSignature();
                auto func = it.findFunction();

                if (func > 0x7fffffffffff)
                {
                    both += "    //edge case; couldn't find function\n";
                    both += "    //vtable: 0x";
                    both += hex(vtable-mod);
                    both += "\n";
                } else
                {
                    auto vto = it.findFunctionVtableOffset();
                    both += "    //";
                    if (vto->disc == VtableOffsetDisc::Empty)
                    {
                        both += "No-op method (instant return)";
                    }
                    else if (vto->disc == VtableOffsetDisc::Vtable)
                    {
                        both += "vtable offset: 0x";
                        both += hex(vto->off.value());
                    }
                    else if (vto->disc == VtableOffsetDisc::Other)
                    {
                        both += "non-vtable method: WHGame.dll+0x";
                        both += hex(vto->off.value()-mod);
                    }
                    else
                    {
                        throw std::runtime_error("Unknown VtableOffsetDisc");
                    }
                    both += "\n";
                    if (OUTPUT_DEBUG_INFO)
                    {
                        both += "    //method vtable: WHGame.dll+0x";
                        both += hex(vtable-mod);
                        both += "\n";
                        both += "    //method function: WHGame.dll+0x";
                        both += hex(func-mod);
                        both += "\n";
                        both += "    //method object: ";
                        both += hex(it.addr);
                        if (dumpHandler != nullptr)
                        {
                            both += " (";
                            both += hex(dumpHandler->findAddressInFile(it.addr));
                            both += ")";
                        }
                        both += "\n";
                    }
                }

                both += "    ";
                both += it.getSignature();
                both += ";\n";
            }
        }
        both += "};\n\n";
        WorkerResult res {pseudo, code, name, namespaceSp};
        resultsMutex.lock();
        results.insert(std::pair(i, res));
        resultsMutex.unlock();
        finished.fetch_add(1, std::memory_order_relaxed);
        nameP->store(nullptr, std::memory_order::memory_order_relaxed);
    }
}

void monitor(uint32_t numProps, const std::vector<std::atomic<int32_t>*>* statuses, const std::vector<std::atomic<std::string*>*>* names)
{
    using namespace std::chrono_literals;
    bool first = true;
    auto longest = 0;
    while (!done)
    {
        if (!first)
        {
            std::cout << "\033[21F";
        }
        first = false;
        logMutex.lock();
        while (!logMessages.empty())
        {
            auto s = logMessages.front();
            logMessages.pop();
            std::cout << s << std::endl;
        }
        logMutex.unlock();
        int best = 0;
        for (auto i = 0; i < statuses->size(); i++)
        {
            int status = (*statuses)[i]->load(std::memory_order_relaxed);
            if (status == -1)
            {
                std::cout << "Thread " << i << pad(": Done!", longest) << std::endl;
            } else
            {
                best = max(best, status);
                auto name = (*names)[i]->load(std::memory_order::memory_order_relaxed);
                std::cout << "Thread " << i << ": " << status;
                if (name != nullptr)
                {
                    std::string tmp;
                    if (name->length() > 50)
                    {
                        tmp = name->substr(0, 50);
                        name = &tmp;
                    }
                    longest = max(longest, name->length()+2);
                    std::cout << " " << pad(std::format("({:s})", *name), longest);
                }
                std::cout << std::endl;
            }
        }
        std::cout << std::format("{:.2f}%", static_cast<float>(finished.load(std::memory_order::memory_order_relaxed))/static_cast<float>(numProps) * 100.0) << std::endl;
        std::this_thread::sleep_for(50ms);
    }
}

int main(int argc, char** argv)
{
    CLI::App app{"KCD2 RTTR Dumper"};
    argv = app.ensure_utf8(argv);

    std::optional<std::string> dumpPath;
    app.add_option("-d,--dump", dumpPath,
        "The path to a full minidump of KCD2");

    std::string outPath = "out.cpp";
    app.add_option("-o,--out", outPath, "The output file path");

    uint32_t numThreads = 20;
    app.add_option("-t,--threads", numThreads, "The number of threads to use");

    app.add_flag("-p,--debug-prints", COUT_DEBUG_PRINTS,
        "Enables some debug logging");
    app.add_flag("-i,--debug-info", OUTPUT_DEBUG_INFO,
        "Outputs some extra information in out.cpp useful for debugging");
    bool include_std = false;
    app.add_flag("--include-std", include_std,
        "Include items from the std namespace");

    try
    {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e)
    {
        return app.exit(e);
    }

    if (dumpPath.has_value())
    {
        std::cout << "Using dump file" << std::endl;
        dumpHandler = new DumpHandler(dumpPath.value());
        mod = dumpHandler->findModuleBase("WHGame.dll");
    } else
    {
        auto procId = findProcessID(L"KingdomCome.exe");
        std::cout << "Process ID: " << procId << std::endl;
        proc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
        if (!proc) checkErr("OpenProcess");
        mod = findModuleBase(procId, L"WHGame.DLL");
        if (!mod) checkErr("FindModuleBase");
    }
    std::cout << "Module Base: " << hex(mod) << std::endl;
    //to find this offset:
    //find "struct wh::entitymodule::S_PlayerItemClass>(void) noexcept"
    //it should be referenced in a function that looks like a constructor, and also references
    //">(void) noexcept"
    //it should be called by exactly one function. go to that function.
    //the function should be a TLS getter+initializer. The function called after the one we just came from is
    //rttr::registration_manager::add_item. Enter it.
    //it should look something like this to start:
    //```
    //localVar = *param2;
    //localVar2 = someFunc();
    //localVar3 = someOtherFunc(localVar2, localVar);
    //localVar4 = *param2;
    //if (localVar3 == localVar4)
    //```
    //Enter someFunc. it's rttr::type_register_private::get_instance. It should also be a TLS getter+initializer.
    //At the end, it should have `return &DAT_18{some offset};`
    //Replace the hex offset off mod below with "some offset".
    auto type_register_private = mod + 0x53edeb0;
    if (COUT_DEBUG_PRINTS) std::cout << "type_register_private:" << hex(type_register_private) << std::endl;
    auto m_orig_name_to_id = type_register_private + 0x40;
    if (COUT_DEBUG_PRINTS) std::cout << "m_orig_name_to_id:" << hex(m_orig_name_to_id) << std::endl;
    auto types_start = readMem<uintptr_t>(m_orig_name_to_id + 0x18);
    if (COUT_DEBUG_PRINTS) std::cout << "Types start:" << hex(types_start) << std::endl;
    auto types_end = readMem<uintptr_t>(m_orig_name_to_id + 0x20);
    uint32_t types_len = (types_end - types_start) / 8;

    std::vector<std::atomic<int32_t>*> statuses;
    std::vector<std::atomic<std::string*>*> names;
    std::thread* monitorThread;
    if (numThreads <= 1)
    {
        auto* status = new std::atomic {0};
        statuses.push_back(status);
        auto name = new std::atomic<std::string*> {nullptr};
        names.push_back(name);
        monitorThread = new std::thread(monitor, types_len, &statuses, &names);
        worker(types_start, types_end, status, name);
        delete status;
    } else
    {
        std::vector<std::thread> threads;
        threads.reserve(numThreads);
        for (auto i = 0; i < numThreads; i++)
        {
            auto* status = new std::atomic<int32_t> {0};
            statuses.push_back(status);
            auto* name = new std::atomic<std::string*> {nullptr};
            names.push_back(name);
            threads.emplace_back(worker, types_start, types_end, status, name);
        }
        monitorThread = new std::thread(monitor, types_len, &statuses, &names);
        for (auto i = 0; i < numThreads; i++)
        {
            threads[i].join();
        }
    }
    done = true;
    monitorThread->join();
    delete monitorThread;

    std::cout << "Writing to file..." << std::endl;
    std::FILE* file;
    fopen_s(&file, outPath.c_str(), "w");
    SetLastError(0);
    if (file)
    {
        for (auto& val : results | std::views::values)
        {
            if (
                !include_std &&
                (val.name.starts_with("class std::") || val.name.starts_with("struct std::"))
                )
                continue;
            std::fwrite(val.pseudo.c_str(), val.pseudo.length(), 1, file);
        }
        std::fclose(file);
    }
    else
    {
        if (COUT_DEBUG_ERRORS) std::cout << "Could not open out.cpp!" << std::endl;
    }

    // std::vector<std::string> tmp;
    // auto baseP = new NamespaceOut("../", tmp);
    // std::shared_ptr<NamespaceOut> base {baseP};
    //
    // for (auto& val : results | std::views::values)
    // {
    //     auto out = base;
    //     for (auto i = 0; i < val.namespaceSp.namespaceSp.size()-1; i++)
    //     {
    //         out = out->get(val.namespaceSp.namespaceSp[i]);
    //     }
    //     auto f = out->getFile();
    //     std::fwrite(val.code.c_str(), val.code.length(), 1, f);
    // }
    // fopen_s(&file, "../out/all.hpp", "w");
    // SetLastError(0);
    // base->close(file);
    // std::fclose(file);

    std::cout << "Done!" << std::endl;
    return 0;
}
