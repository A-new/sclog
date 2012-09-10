
#include <windows.h>
#include <stdlib.h>
#include "./distorm3.3/distorm.h"
#include <stdio.h>
#include <intrin.h>

#pragma warning(disable:4996)

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


// 10000 hooks should be enough
#define MAX_HOOKS 10000
#define JUMP_WORST		0x10		// Worst case scenario + line all up on 0x10 boundary...

#ifndef __cplusplus
#define extern "C" stdc
#else
#define  stdc
#endif

enum hookType{ ht_jmp = 0, ht_pushret=1, ht_jmp5safe=2, ht_jmpderef=3 };
enum hookErrors{ he_None=0, he_cantDisasm, he_cantHook, he_maxHooks, he_UnknownHookType  };

bool initilized = false;
char lastError[500] = {0};
hookErrors lastErrorCode = he_None;

typedef struct _HOOK_INFO
{
	ULONG_PTR Function;	// Address of the original function
	ULONG_PTR Hook;		// Address of the function to call 
	ULONG_PTR Bridge;   // Address of the instruction bridge
	hookType hooktype;
	char* ApiName;
	bool Enabled;

} HOOK_INFO, *PHOOK_INFO;

HOOK_INFO HookInfo[MAX_HOOKS];
UINT NumberOfHooks = 0;
BYTE *pBridgeBuffer = NULL; // Here are going to be stored all the bridges
UINT CurrentBridgeBufferSize = 0; // This number is incremented as the bridge buffer is growing

stdc
char* __cdecl GetHookError(void){
	return (char*)lastError;
}

stdc
void __cdecl InitHookEngine(void){
	if(initilized) return;
	UINT sz = MAX_HOOKS * (JUMP_WORST * 3);
	pBridgeBuffer = (BYTE *) VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(pBridgeBuffer, 0 , sz);
	memset(&HookInfo[0], 0, sizeof(struct _HOOK_INFO) * MAX_HOOKS);
}

HOOK_INFO *GetHookInfoFromFunction(ULONG_PTR OriginalFunction)
{
	if (NumberOfHooks == 0)
		return NULL;

	for (UINT x = 0; x < NumberOfHooks; x++)
	{
		if (HookInfo[x].Function == OriginalFunction)
			return &HookInfo[x];
	}

	return NULL;
}

#ifdef _M_IX86
	//these two are only used for x86 ht_jmp5safe hooks..

	void __stdcall output(ULONG_PTR ra){
		HOOK_INFO *hi = GetHookInfoFromFunction(ra);
		if(hi){
			printf("jmp %s+5 api detected trying to recover...\n", hi->ApiName );
		}else{
			printf("jmp+5 api caught %x\n", ra );
		}
	}

	void __declspec(naked) UnwindProlog(void){
		_asm{
			mov eax, [ebp-4] //return address
			sub eax, 10      //function entry point
			push eax         //arg to output
			call output

			pop eax      //we got here through a call from our api hook stub so this is ret
			sub eax, 10  //back to api start address
			mov esp, ebp //now unwind the prolog the shellcode did on its own..
			pop ebp      //saved ebp 
			jmp eax      //and jmp back to the api public entry point to hit main hook jmp
		}
	}

#endif

// This function  retrieves the necessary size for the jump
// overwrite as little of the api function as possible per hook type...
UINT GetJumpSize(hookType ht)
{

	#ifdef _M_IX86

		switch(ht){
			case  ht_jmp: return 5;
			case  ht_pushret: return 6;
			default: return 10;
		}

	#else

			return 14;

	#endif

}

stdc
char* __cdecl GetDisasm(ULONG_PTR pAddress, int* retLen = NULL){ //just a helper doesnt set error code..

	#define MAX_INSTRUCTIONS 100

	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

	#ifdef _M_IX86
		_DecodeType dt = Decode32Bits;
	#else ifdef _M_AMD64
		_DecodeType dt = Decode64Bits;
	#endif

	_OffsetType offset = 0;

	res = distorm_decode(offset,	// offset for buffer
		(const BYTE *) pAddress,	// buffer to disassemble
		50,							// function size (code size to disasm) 
		dt,							// x86 or x64?
		decodedInstructions,		// decoded instr
		MAX_INSTRUCTIONS,			// array size
		&decodedInstructionsCount	// how many instr were disassembled?
		);

	if (res == DECRES_INPUTERR){
		//sprintf(lastError, "Could not disassemble address %x", (UINT)Function);
		//lastErrorCode = he_cantDisasm;
		return NULL;
	}

	int bufsz = 120;
	char* tmp = (char*)malloc(bufsz);
	memset(tmp, 0, bufsz);
	_snprintf(tmp, bufsz-1 , "%10x  %-10s %-6s %s\n", 
			 pAddress, 
		     decodedInstructions[0].instructionHex.p, 
			 decodedInstructions[0].mnemonic.p, 
			 decodedInstructions[0].operands.p
	);

	if(retLen !=NULL) *retLen = decodedInstructions[0].size;

	return tmp;
}
	



bool UnSupportedOpcode(BYTE *b){ //primary instruction opcodes are the same for x64 and x86 

	BYTE bb = *b;
	
	switch(bb){ 
		case 0x74:
		case 0x75: 
		case 0xEB:
		case 0xE8:
		case 0xE9:
		case 0x0F:
		case 0xFF:
		case 0xc3: 
		case 0xc4: 
			        goto failed;
	}

	return false;


failed:
		UINT offset = (UINT)b - HookInfo[NumberOfHooks].Function;
		char* d = GetDisasm((ULONG_PTR)b);

		if(d == NULL){
			sprintf(lastError,"Unsupported opcode at %s+%d: Opcode: %x", HookInfo[NumberOfHooks].ApiName, offset, *b);
			lastErrorCode = he_cantHook;
		}else{
			sprintf(lastError,"Unsupported opcode at %s+%d\n%s", HookInfo[NumberOfHooks].ApiName, offset, d);
			lastErrorCode = he_cantHook;
			free(d);
		}
		
		return true;

}


void WriteInt( BYTE *pAddress, UINT value){
	*(UINT*)pAddress = value;
}

//
// This function writes unconditional jumps
// both for x86 and x64
//
VOID WriteJump(VOID *pAddress, ULONG_PTR JumpTo, hookType ht)
{
	DWORD dwOldProtect = 0;
	VirtualProtect(pAddress, JUMP_WORST, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	BYTE *pCur = (BYTE *) pAddress;

#ifdef _M_IX86
        
	   if(ht == ht_pushret){
		   //68 DDCCBBAA      PUSH AABBCCDD (6 bytes)
		   //C3               RETN
		   *pCur = 0x68;
		   *((ULONG_PTR *)++pCur) = JumpTo;
		   pCur+=4;
		   *pCur = 0xc3;
	   }
	   else if(ht == ht_jmpderef){	  
			//eip>  FF25 AABBCCDD    JMP DWORD PTR DS:[eip+6] 10 bytes
			//eip+6 xxxxxxxx
			*pCur = 0xff;    
			*(pCur+1) = 0x25;
			WriteInt(pCur+2, (int)pCur + 6);
			WriteInt(pCur+6, JumpTo);
	   }
	   else if(ht== ht_jmp){
			//E9 jmp (DESTINATION_RVA - CURRENT_RVA - 5 [sizeof(E9 xx xx xx xx)]) (5 bytes)
		    UINT dst = JumpTo - (UINT)(pAddress) - 5;
			*pCur = 0xE9;
			WriteInt(pCur+1, dst);
	   }
	   else if(ht = ht_jmp5safe){ //this needs a second trampoline if api+5 jmp is hit, it needs to reverse the push ebp to send to hook..
			//E9 jmp normal prolog + eB call to UnwindProlog  (10 bytes)
		    *(pCur) = 0xE9;
			UINT dst = JumpTo - (UINT)(pCur) - 5; 
			WriteInt(pCur+1, dst);			
			*(pCur+5) = 0xE8;
			dst = (UINT)&UnwindProlog - (UINT)(pCur+5) - 5; //api+5 jmps are sent to our generic unwinder 
			WriteInt(pCur+6, dst);
	   }
	   else{
		   sprintf(lastError, "Unimplemented hook type asked for");
		   lastErrorCode = he_UnknownHookType;
		   ExitProcess(0);
	   }

#else ifdef _M_AMD64

		*pCur = 0xff;		// jmp [rip+addr]
		*(++pCur) = 0x25;
		*((DWORD *) ++pCur) = 0; // addr = 0
		pCur += sizeof (DWORD);
		*((ULONG_PTR *)pCur) = JumpTo;

#endif

	DWORD dwBuf = 0;	// nessary othewrise the function fails
	VirtualProtect(pAddress, JUMP_WORST, dwOldProtect, &dwBuf);
}


//
// This function creates a bridge of the original function
//

VOID *CreateBridge(ULONG_PTR Function, const UINT JumpSize)
{
	if (pBridgeBuffer == NULL) return NULL;

	#define MAX_INSTRUCTIONS 100

	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

	#ifdef _M_IX86
		_DecodeType dt = Decode32Bits;
	#else ifdef _M_AMD64
		_DecodeType dt = Decode64Bits;
	#endif

	_OffsetType offset = 0;

	res = distorm_decode(offset,	// offset for buffer
		(const BYTE *) Function,	// buffer to disassemble
		50,							// function size (code size to disasm) 
									// 50 instr should be _quite_ enough
		dt,							// x86 or x64?
		decodedInstructions,		// decoded instr
		MAX_INSTRUCTIONS,			// array size
		&decodedInstructionsCount	// how many instr were disassembled?
		);

	if (res == DECRES_INPUTERR){
		sprintf(lastError, "Could not disassemble address %x", (UINT)Function);
		lastErrorCode = he_cantDisasm;
		return NULL;
	}

	DWORD InstrSize = 0;
	VOID *pBridge = (VOID *) &pBridgeBuffer[CurrentBridgeBufferSize];

	for (UINT x = 0; x < decodedInstructionsCount; x++)
	{
		if (InstrSize >= JumpSize) break;

		BYTE *pCurInstr = (BYTE *) (InstrSize + (ULONG_PTR) Function);
		if(UnSupportedOpcode(pCurInstr)) return NULL;
		
		memcpy(&pBridgeBuffer[CurrentBridgeBufferSize], (VOID *) pCurInstr, decodedInstructions[x].size);

		CurrentBridgeBufferSize += decodedInstructions[x].size;
		InstrSize += decodedInstructions[x].size;
	}

	//to leave trampoline...
	WriteJump(&pBridgeBuffer[CurrentBridgeBufferSize], Function + InstrSize, ht_jmp);
	CurrentBridgeBufferSize += JumpSize;
	return pBridge;
}



stdc
BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, char *name, hookType ht)
{

	lastErrorCode = he_None;
	if(!initilized) InitHookEngine();

	HOOK_INFO *hinfo = GetHookInfoFromFunction(OriginalFunction);

	if (hinfo) return TRUE; //already hooked...

	if (NumberOfHooks == (MAX_HOOKS - 1)){
		lastErrorCode = he_maxHooks;
		strcpy(lastError,"Maximum number of hooks reached.");
		return FALSE;
	}

	HookInfo[NumberOfHooks].Function = OriginalFunction;
	HookInfo[NumberOfHooks].Hook = NewFunction;
    HookInfo[NumberOfHooks].hooktype = ht;
	HookInfo[NumberOfHooks].ApiName = strdup(name);

	VOID *pBridge = CreateBridge(OriginalFunction, GetJumpSize(ht) );

	if (pBridge == NULL){
		free(HookInfo[NumberOfHooks].ApiName);
		memset(&HookInfo[NumberOfHooks], 0, sizeof(struct _HOOK_INFO));
		return FALSE;
	}

	HookInfo[NumberOfHooks].Bridge = (ULONG_PTR) pBridge;
	HookInfo[NumberOfHooks].Enabled = true;
	NumberOfHooks++; //now we commit it as complete..

	WriteJump((VOID *) OriginalFunction, NewFunction, ht); //activates hook in api prolog..
	return TRUE;
}

stdc  
VOID __cdecl DisableHook(ULONG_PTR Function)
{
	HOOK_INFO *hinfo = GetHookInfoFromFunction(Function);
	if (hinfo)
	{
		if(hinfo->Enabled){
			hinfo->Enabled = false;
			WriteJump((VOID *)hinfo->Function, hinfo->Bridge, ht_jmp);
		}
	}

}

stdc 
VOID __cdecl EnableHook(ULONG_PTR Function)
{
	HOOK_INFO *hinfo = GetHookInfoFromFunction(Function);
	if (hinfo)
	{
		if(!hinfo->Enabled){
			hinfo->Enabled = true;
			WriteJump((VOID *)hinfo->Function, hinfo->Hook, hinfo->hooktype );
		}
	}
}

stdc
ULONG_PTR __cdecl GetOriginalFunction(ULONG_PTR Hook)
{
	if (NumberOfHooks == 0)
		return NULL;

	for (UINT x = 0; x < NumberOfHooks; x++)
	{
		if (HookInfo[x].Hook == Hook)
			return HookInfo[x].Bridge;
	}

	return NULL;
}
