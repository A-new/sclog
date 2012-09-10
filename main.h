/*
License: sclog.exe Copyright (C) 2005 David Zimmer <david@idefense.com, dzzie@yahoo.com>

         This program is free software; you can redistribute it and/or modify it
         under the terms of the GNU General Public License as published by the Free
         Software Foundation; either version 2 of the License, or (at your option)
         any later version.

         This program is distributed in the hope that it will be useful, but WITHOUT
         ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
         FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
         more details.

         You should have received a copy of the GNU General Public License along with
         this program; if not, write to the Free Software Foundation, Inc., 59 Temple
         Place, Suite 330, Boston, MA 02111-1307 USA

*/

struct mem{
	int offset;
	int size;
}; 

//should be pretty safe to assume shellcode only does one alloc..wrong...
struct mem GAlloc;
struct mem VAlloc;

HANDLE logFile = NULL;

#include <tlhelp32.h> 
#include <INTRIN.H>

HMODULE  (__stdcall *Real_LoadLibraryA)(LPCSTR a0);
BOOL     (__stdcall *Real_WriteFile)(HANDLE a0,LPCVOID a1,DWORD a2,LPDWORD a3,LPOVERLAPPED a4) = NULL;
HANDLE   (__stdcall *Real_CreateFileA)(LPCSTR a0,DWORD a1,DWORD a2,LPSECURITY_ATTRIBUTES a3,DWORD a4,DWORD a5,HANDLE a6);
HMODULE  (__stdcall *Real_LoadLibraryExA)(LPCSTR a0,HANDLE a1,DWORD a2);
HMODULE  (__stdcall *Real_LoadLibraryExW)(LPCWSTR a0,HANDLE a1,DWORD a2);
HMODULE  (__stdcall *Real_LoadLibraryW)(LPCWSTR a0);
BOOL	  (__stdcall *Real_WriteFileEx)(HANDLE a0,LPCVOID a1,DWORD a2,LPOVERLAPPED a3,LPOVERLAPPED_COMPLETION_ROUTINE a4) ;
HFILE    (__stdcall *Real__lclose)(HFILE a0);
HFILE	  (__stdcall *Real__lcreat)(LPCSTR a0,int a1);
HFILE	  (__stdcall *Real__lopen)(LPCSTR a0,int a1);
UINT	  (__stdcall *Real__lread)(HFILE a0,LPVOID a1,UINT a2);
UINT	  (__stdcall *Real__lwrite)(HFILE a0,LPCSTR a1,UINT a2);
BOOL	  (__stdcall *Real_CreateProcessA)(LPCSTR a0,LPSTR a1,LPSECURITY_ATTRIBUTES a2,LPSECURITY_ATTRIBUTES a3,BOOL a4,DWORD a5,LPVOID a6,LPCSTR a7,struct _STARTUPINFOA* a8,LPPROCESS_INFORMATION a9);
UINT	  (__stdcall *Real_WinExec)(LPCSTR a0,UINT a1);
BOOL	  (__stdcall *Real_DeleteFileA)(LPCSTR a0);
void	  (__stdcall *Real_ExitProcess)(UINT a0) = NULL;
void	  (__stdcall *Real_ExitThread)(DWORD a0);
FARPROC  (__stdcall *Real_GetProcAddress)(HMODULE a0,LPCSTR a1);
DWORD	  (__stdcall *Real_WaitForSingleObject)(HANDLE a0,DWORD a1);
HANDLE	  (__stdcall *Real_CreateRemoteThread)(HANDLE a0,LPSECURITY_ATTRIBUTES a1,DWORD a2,LPTHREAD_START_ROUTINE a3,LPVOID a4,DWORD a5,LPDWORD a6);
HANDLE	  (__stdcall *Real_OpenProcess)(DWORD a0,BOOL a1,DWORD a2);
BOOL	  (__stdcall *Real_WriteProcessMemory)(HANDLE a0,LPVOID a1,LPVOID a2,DWORD a3,LPDWORD a4);
HMODULE  (__stdcall *Real_GetModuleHandleA)(LPCSTR a0);
SOCKET	  (__stdcall *Real_accept)(SOCKET a0,sockaddr* a1,int* a2);
int	  (__stdcall *Real_bind)(SOCKET a0,SOCKADDR_IN* a1,int a2);
int	  (__stdcall *Real_closesocket)(SOCKET a0);
int	  (__stdcall *Real_connect)(SOCKET a0,SOCKADDR_IN* a1,int a2);
hostent* (__stdcall *Real_gethostbyaddr)(char* a0,int a1,int a2);
hostent* (__stdcall *Real_gethostbyname)(char* a0);
int	  (__stdcall *Real_gethostname)(char* a0,int a1);
int	  (__stdcall *Real_listen)(SOCKET a0,int a1);
int	  (__stdcall *Real_recv)(SOCKET a0,char* a1,int a2,int a3);
int	  (__stdcall *Real_send)(SOCKET a0,char* a1,int a2,int a3);
int	  (__stdcall *Real_shutdown)(SOCKET a0,int a1);
SOCKET   (__stdcall *Real_socket)(int a0,int a1,int a2);
SOCKET   (__stdcall *Real_WSASocketA)(int a0,int a1,int a2,struct _WSAPROTOCOL_INFOA* a3,GROUP a4,DWORD a5);
//int	  (Real_system)(const char* cmd);
//FILE*	  (Real_fopen)(const char* cmd, const char* mode);
//size_t  (Real_fwrite)(const void* a0, size_t a1, size_t a2, FILE* a3);
int	  (__stdcall *Real_URLDownloadToFileA)(int a0,char* a1, char* a2, DWORD a3, int a4);
int	  (__stdcall *Real_URLDownloadToCacheFile)(int a0,char* a1, char* a2, DWORD a3, DWORD a4, int a5);
DWORD    (__stdcall *Real_GetFileSize)( HANDLE a0, LPDWORD a1 );
HANDLE   (__stdcall *Real_FindFirstFileA)( LPCSTR a0, LPWIN32_FIND_DATAA a1 );
HGLOBAL  (__stdcall *Real_GlobalAlloc)( UINT a0, DWORD a1 );
HGLOBAL  (__stdcall *Real_GlobalFree)( HGLOBAL a0 );
LPVOID   (__stdcall *Real_VirtualAlloc)( LPVOID a0, DWORD a1, DWORD a2, DWORD a3 );
BOOL     (__stdcall *Real_VirtualFree)( LPVOID a0, DWORD a1, DWORD a2 );
DWORD    (__stdcall *Real_GetTempPathA)( DWORD a0, LPSTR a1 );
LPVOID (__stdcall *Real_VirtualAllocEx)( HANDLE a0, LPVOID a1, DWORD a2, DWORD a3, DWORD a4 );
DWORD (__stdcall *Real_SetFilePointer)( HANDLE a0, LONG a1, PLONG a2, DWORD a3 );

//my header and lib files are old! and i dont want to link to msvc90.dll with vs08..so fuck it
//ALLOC_THUNK( DWORD    __stdcall Real_GetFileSizeEx( HANDLE a0, PLARGE_INTEGER  a1 ) );
//ALLOC_THUNK( HANDLE   __stdcall Real_FindFirstFileExA( LPCSTR a0, FINDEX_INFO_LEVELS a1, LPVOID a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5 ) );
//ALLOC_THUNK( BOOL     __stdcall Real_IsDebuggerPresent( VOID ) );

enum AntiSpamFx{
	asAll		= 0,
	asWriteFile = 1,
};

bool AntiSpamSupress[50]; 

void SetSupress(AntiSpamFx api){
	AntiSpamSupress[api] = true;
}

void ReleaseSupress(AntiSpamFx api){
	AntiSpamSupress[api] = false;
}

void ReleaseSupressExcept(AntiSpamFx api){
	for(int i=0;i<50;i++){
		if(i!=api) AntiSpamSupress[i] = false;
	}
}


bool IsSupressed(AntiSpamFx api){
	return AntiSpamSupress[api];
}



char* ProcessFromPID(DWORD pid){ //must free() results

	PROCESSENTRY32 pe;
    HANDLE hSnap;
    char* buf = NULL;

    pe.dwSize = sizeof(pe);
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    Process32First( hSnap, &pe);
    if(pid == pe.th32ProcessID) goto found;

    while( Process32Next(hSnap, &pe) ){
		if(pid == pe.th32ProcessID) goto found;
	}

none:
	  buf = (char*)malloc(4);
	  strcpy(buf,"???");
	  return buf;

found:
	
	  try{
		if(pe.szExeFile){
			buf = (char*)malloc(strlen(pe.szExeFile));
			strcpy(buf,pe.szExeFile);
			return buf;
		}
	   }catch(...){}

		goto none;
	

}




//we cant just write to str because it may not be writable memory :-/
char* strlower(char *str){
	
	int max=1000;
	if(str == 0 ) return (char*)malloc(1);

	int l = strlen(str);
	if(l>max)  l = max;
	
	char* mstr = (char*)malloc(max+1);
	memset((void*)mstr,0,max+1);

	for(int i=0; i < l; i++){
		mstr[i] = tolower(str[i]);
	}

	return mstr;

}


char* ipfromlng(SOCKADDR_IN* sck){
	
	char *ip = (char*)malloc(16);
	unsigned char *x= (unsigned char*)(((int)sck)+4);
	sprintf(ip,"%d.%d.%d.%d\x00", x[0], x[1], x[2], x[3]);
	return ip;

}


void msg(char* msg, int color = -1, int logit=1){ //safe hook free console output
	
	DWORD cbWritten=0;
	
	if(msg==NULL) return;

	if(color) SetConsoleTextAttribute(STDOUT,  color);
	printf("%s",msg);
	if(color) SetConsoleTextAttribute(STDOUT,  0x7); //back to default gray

	if(logit==1 && logFile!=NULL){
		if(Real_WriteFile == NULL) WriteFile( logFile , msg , strlen(msg), &cbWritten, NULL);
		  else Real_WriteFile( logFile , msg , strlen(msg), &cbWritten, NULL);
		FlushFileBuffers(logFile);
	}

}

void hexdump(unsigned char* str, int len){
	
	char asc[19];
	int aspot=0;
    const int hexline_length = 3*16+4;
	
	char *nl="\r\n";
	char *tmp = (char*)malloc(50);
	
	if(showhex==0) return;

	msg(nl);

	for(int i=0;i< len;i++){

		sprintf(tmp, "%02x ", str[i]);
		msg(tmp);
		
		if( (int)str[i]>20 && (int)str[i] < 123 ) asc[aspot] = str[i];
		 else asc[aspot] = 0x2e;

		aspot++;
		if(aspot%16==0){
			asc[aspot]=0x00;
			sprintf(tmp,"    %s\r\n", asc);
			msg(tmp);
			aspot=0;
		}

	}

	if(aspot%16!=0){//print last ascii segment if not full line
		int spacer = hexline_length - (aspot*3);
		while(spacer--)	msg(" ");	
		asc[aspot]=0x00;
		sprintf(tmp, "%s\r\n",asc);
		msg(tmp);
	}
	
	msg(nl);
	free(tmp);


}

void infomsg(const char *format, ...)
{
	DWORD dwErr = GetLastError();

	if(format){
		char buf[1024];
		va_list args; 
		va_start(args,format); 
		try{
			_vsnprintf(buf,1024,format,args);
			msg(buf,infoMsgColor);
		}
		catch(...){}
	}

	SetLastError(dwErr);
}


//added 10.2.10
void DumpMemBuf(int offset, int size, char* ext){
	
		DWORD cbWritten;
		char pth[0x500]; //should be more than enough 
		
		if(size < 1 || offset < 1){
			infomsg("     DumpMemBuf invalid args %x %x\r\n\r\n", offset,size);
			return;
		}
		
		if( IsBadReadPtr((void*)offset,size) !=0 ){
			infomsg("     DumpMemBuf invalid args %x %x\r\n\r\n", offset,size);
			return;
		}

		if( strlen(sc_file) + strlen(ext) >= 0x500 ){ //just in case...
			infomsg("     DumpMemBuf path+ext > buffer skipping...\r\n\r\n");
			return;
		}

		void* memBuf;
		memBuf = malloc(size+1);
		memcpy(memBuf, (void*)offset, size);

		strcpy(pth,sc_file);
		sprintf(pth,"%s%s",pth,ext);
		
		HANDLE h = Real_CreateFileA( (const char*) &pth, GENERIC_WRITE, 0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL); 

		if (h  == INVALID_HANDLE_VALUE){
			infomsg("     Could not create dumpfile for DumpMemBuf %s\r\n\r\n", pth);
			return;
		}
	
		Real_WriteFile( h , memBuf , size, &cbWritten, NULL);
		CloseHandle(h);
		free(memBuf);

		SetConsoleTextAttribute(STDOUT,  0x0E); //yellow
		infomsg("     DumpMemBuf %x/%x bytes to %s\r\n", cbWritten, size, pth);
		SetConsoleTextAttribute(STDOUT,  0x07); //gray

} 

void DumpBuffer(){
	
		DWORD cbWritten;
		char pth[MAX_PATH]; //should be more than enough 
	
		if(autoDump==0) return;

		autoDump=0;
		strcpy(pth,sc_file);
		sprintf(pth,"%s.dmp",pth);
		
		HANDLE h = Real_CreateFileA( (const char*) &pth, GENERIC_WRITE, 0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL); 

		if (h  == INVALID_HANDLE_VALUE){
			infomsg("     Could not create dumpfile %s\r\n\r\n", pth);
			return;
		}
	
		Real_WriteFile( h , buf , bufsz, &cbWritten, NULL);
		CloseHandle(h);

		SetConsoleTextAttribute(STDOUT,  0x0E); //yellow
		infomsg("\r\n     /Dump Option - Dumping %x/%x bytes shellcode buf to %s\r\n", cbWritten,bufsz, pth);
		SetConsoleTextAttribute(STDOUT,  0x07); //gray

} 

void LogAPI(const char *format, ...)
{
	DWORD dwErr = GetLastError();

	if(HOOK_MSGS_OFF==1) return; //we init hooks earlier now so need this..

	if(format){
		char buf[1024]; 
		va_list args; 
		va_start(args,format); 
		try{

				if(stepMode) msg("Allow ? y/n ");

				_vsnprintf(buf,1024,format,args);
				msg(buf);
				
				if(autoDump) DumpBuffer();

				if(stepMode){
					 
					 char c;
					 DWORD dwBytesRead;
					
					 for(;;){
						ReadFile(STDIN,&c,1,&dwBytesRead,NULL); //make sure line input mode off!
						if(c=='y') break;
						if(c=='n') exit(0);
					 }

				}

		}
		catch(...){}
	}

	SetLastError(dwErr);
}


//used in WaitForSingleObject, LoadLibrary and GetProcAddress..does not account for new GAlloc or VAlloc bufs

/*__declspec(naked) int calledFromSC(){ //seems to work anyway :P
	
	_asm{
			 mov eax, nofilt  //no filter option display all hook output
			 cmp eax, 1       //if nofilt = 1
			 je  isOk
			 
			 pushad
			 mov eax, [ebp+4]  //return address of parent function (were nekkid)
			 mov ebx, buf      //start of shellcode
			 cmp eax, ebx
			 jl failed		   //call came from address lower than shellcode buffer	
			 
			 add ebx, bufsz    //add size of shellcode to buf base to get max offset
			 cmp eax, ebx
			 jg  failed        //call came from address higher than sc buffer

			 popad
	 isOk:	 mov eax, 1
			 ret

	 failed: popad
			 mov eax, 0
			 ret

	}
	
}*/



#if defined _M_X64 
	//ContextRecord.Eip = (ULONG)_ReturnAddress();
    //ContextRecord.Esp = (ULONG)_AddressOfReturnAddress();
    //ContextRecord.Ebp = *((ULONG *)_AddressOfReturnAddress()-1);

	//#define	SCOffset() (int)_AddressOfReturnAddress()
      #define	SCOffset() (int)_ReturnAddress()

	/*inline int SCOffset(){
		//dotn use RTLCaptureContext...
		//requires at least XP, make sure to turn optimizations off for release,still crashs on x64
		//http://www.bytetalk.net/2011/06/why-rtlcapturecontext-crashes-on.html
		//http://zachsaw.blogspot.com.au/2010/11/wow64-bug-getthreadcontext-may-return.html

		int rv = (int)_AddressOfReturnAddress();
		printf("ret=%x\n",rv);
		return rv;
	}*/
#else
	__declspec(naked) int SCOffset(){ //has to be called from parent hook function to mean anything...
		_asm{
				 mov eax, [ebp+4]  //return address of parent function (were nekkid)
				 ret
		}
	}
#endif

int calledFromSC(){

	if(nofilt==1) return 1;

	int x = SCOffset();
	if( x < (int)&buf) return 0;
	if( (x > (((int)&buf) + bufsz)) ) return 0;
	return 1;

}

//substantial change in behavior 10.2.10
void AddAddr(unsigned int retAdr){
	char tmp[35];
	
	int sc = retAdr - (int)buf; 
	int ga = -1;
	int va = -1;
	int color = 0xF; //white

	if(HOOK_MSGS_OFF==1) return;// color; 

	if(GAlloc.offset > 0) ga = retAdr - GAlloc.offset;
	if(VAlloc.offset > 0) va = retAdr - VAlloc.offset;

	if(sc <= bufsz){
		sprintf(tmp,"%4X ", sc);
	}else if(ga >=0 && ga <= GAlloc.size){
		sprintf(tmp,"GAlloc: %4X ", ga);
	}else if(va >= 0 && va <= VAlloc.size){
		sprintf(tmp,"VAlloc: %4X ", va);
	}else{
		if(showadr==1){
			sprintf(tmp," %8X ", retAdr);
		}else{
			color = 0x07; //default grey
			strcpy(tmp," --- "); //must be from other api we dont care (bad calc anyway)
		}
	}

	msg(tmp); //, color);
	//return color;
}

 

