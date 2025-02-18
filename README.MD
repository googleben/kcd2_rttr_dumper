# kcd2_rttr_dumper

This is a quick and dirty program to dump runtime type information for Kingdom Come: Deliverance 2, provided by 
[RTTR](https://github.com/rttrorg/rttr/) as embedded in the game.

# Why?

While KCD2's archives are relatively easy to modify, they only hold power over a limited scope of the game's data. For
more complex mods, it's necessary to modify the game's code, or the game's data at runtime. The output of this program
can be used to help write mods that do exactly that. Knowing the memory layout of types is often half the battle when
writing this kind of mod. For example, the information provided would make it easier to write a mod that prevents herbs
from taking quality damage, but still allows armor to take quality damage.

However, this program is not a magic bullet. It doesn't allow you to do the actual modification of the game; it simply
provides some information that would be useful while doing so. A method of code injection or static code patching would
still be required, like Cheat Engine or a DLL injector.

# Running the program

The program requires either KCD2 to be running, or a full minidump of KCD2. The minidump can be obtained by using
[procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) or a similar tool. The minidump should be
taken while the game is running, and should be full (including the full heap and code). By default, the program assumes
the game is running, and will attempt to attach to the game process. To use a minidump, use the `-d` argument.

The executable supports several arguments:
- `-d, --dump <path>`: Path to a full minidump of KCD2.
- `-o, --out <path>`: Output file path (default: out.cpp).
- `-t, --threads <number>`: Number of threads to use (default: 20).
- `-p, --debug-prints`: Enables debug logging.
- `-i, --debug-info`: Outputs extra information in out.cpp useful for debugging.

# Output

The output file, `out.cpp`, is not actually C++. Instead, types roughly follow this pattern:

```C++
((class|struct) TypeName : (type", "?)* {
    (PropOffset : PropName : PropType;)*
    (MethodName( ParamType* );)*
};
| enum TypeName : UnderlyingType {
    (MemberName = Value,)*
};)*
```

Enums should be C++-compatible, but structs and classes aren't. For example, this C++ type `Foo`:

```C++
class MyBase {};
class Foo {
    int bar;
    int* baz;
    virtual int getBar(int p);
};
```

Would look something like this:

```C++
class Foo : class MyBase {
    0x0 : bar : int;
    0x8 : baz : int*;
    
    //vtable offset: 0x8
    getBar( int );
}
```

However, in some cases a property requires a getter function. If it requires a getter, there'll be no offset shown, 
like this:

```C++
    //Getter: WHGame.dll+0x(addr)
    get : bar : int;
```

You may be able to determine the offset of the property by examining the getter function using a reverse engineering
tool like Ghidra.

Some information may be inaccurate or missing from the final output.

## Interpreting method information

The comments preceding a method declaration contain information about how to call the method. If it's a virtual method,
the comment will contain the vtable offset. If it's a non-virtual method, or the program is unable to determine the
offset in the vtable, the comment will contain the address of the method in memory. In the case the method consists of
a single `ret` instruction, the comment will read "No-op method (instant return)". Return type information is available
in memory, but is not currently outputted by the program; however, you may be able to recover it (as well as parameter
names) by using a reverse engineering tool like Ghidra along with the `-i` flag (note that some information outputted
due to `-i` includes heap-allocated addresses, and will thus change every time the game is started).

# Reasons for limitations

RTTR is largely a header-first, template-heavy library. This makes it difficult to represent types after the initial
compilation. Due to predictable vtable and type layouts, it's possible to recover some information by employing a
disassembler. However, the diversity of types and the complexity of the RTTR library make it difficult to recover all
information in a reliable manner. This program is a best-effort attempt to recover as much information as possible,
and will necessarily output incomplete or incorrect information.

In particular, RTTR makes heavy use of `constexpr std::array`s, which means that offsets of members of those types are
dynamic and may only be recovered by examining disassembly that accesses members placed after the `array`s, or the
`array`s themselves. An additional wrinkle is that the exact compiler Warhorse used is unknown to me, and the exact
version of RTTR is also unknown. This means that the exact layout of types can differ widely from what my tools tell
me to expect. The fact that they used RTTR allowed me to make relatively quick headway, but it's ultimately still a
source of many unknowns. For a more complete solution, a much larger reverse engineering effort would be required.

# Building

Make sure the submodule `cccapstone` is cloned. Build the CMake project in `./cccapstone/capstone` in the folder
`./cccapstone/capstone/cmake-build-release`, so that the file `./cccapstone/capstone/cmake-build-release/capstone.lib`
exists. Then build the main CMake project.

# Disclaimer

This project was written quick-and-dirty over a few days while I swapped between C++ STL, RTTR, Ghidra, and this 
codebase. This means the code is of generally relatively poor quality. It may output incorrect information, and it may 
not work at all. Use at your own risk, and take all information it outputs with a grain of salt.