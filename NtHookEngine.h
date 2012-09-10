
//This is a modified version of the open source x86/x64 
//NTCore Hooking Engine written by:
//Daniel Pistelli <ntcore@gmail.com>
//http://www.ntcore.com/files/nthookengine.htm
//
//It uses the x86/x64 GPL disassembler engine
//diStorm was written by Gil Dabah. 
//Copyright (C) 2003-2012 Gil Dabah. diStorm at gmail dot com.
//
//Mods by David Zimmer <dzzie@yahoo.com>

enum hookType{ ht_jmp = 0, ht_pushret=1, ht_jmp5safe=2, ht_jmpderef=3 };
enum hookErrors{ he_None=0, he_cantDisasm, he_cantHook, he_maxHooks, he_UnknownHookType  };
extern hookErrors lastErrorCode;

//extern void InitHookEngine(void); handled automatically now...

extern char* __cdecl GetHookError(void);
extern char* __cdecl GetDisasm(ULONG_PTR pAddress, int* retLen = NULL);
extern void __cdecl DisableHook(ULONG_PTR Function);
extern void __cdecl EnableHook(ULONG_PTR Function);
extern ULONG_PTR __cdecl GetOriginalFunction(ULONG_PTR Hook);
extern BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, char* name, enum hookType ht);

