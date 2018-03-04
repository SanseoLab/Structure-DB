// 32bit


typedef uint8_t BYTE;
typedef char TCHAR;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef long LONG;
typedef unsigned int ULONG;
typedef ULONG* SIZE_T;
typedef ULONG* ULONG_PTR;
typedef char* LPTSTR;
typedef LPTSTR LPCTSTR;
typedef char* LPBYTE;

typedef void* HANDLE;
typedef HANDLE PVOID;
typedef HANDLE LPVOID;
typedef HANDLE HKEY;
typedef HANDLE HINSTANCE;
typedef HANDLE HWND;








// No perfect

struct TEB {
	int32  seh;
	int  member0x04;
	int  member0x08;
	int  member0x0c;
	int  member0x10;
	int  member0x14;
	TEB*  TEB;
	int  member0x1c;
	DWORD  PID;
	DWORD  TID;
	int  member0x28;
	int  member0x2c;
	PEB*  PEB;
	DWORD  LastErrorValue;
};


struct PEB {
	int16  member0x00;
	BYTE  BeingDebugged;
	int8  member0x03;
	int32  member0x04;;
	void*  ImageBaseAddress;
	PEB_LDR_DATA*  Ldr;
	int  member0x10;
	int  member0x14;
	void*  ProcessHeap;
	int  member0x1c;
	int  member0x20;
	int  member0x24;
	int  member0x28;
	int  member0x2c;
	int  member0x30;
	int  member0x34;
	int  member0x38;
	int  member0x3c;
	int  member0x40;
	int  member0x44;
	int  member0x48;
	int  member0x4c;
	int  member0x50;
	int  member0x54;
	int  member0x58;
	int  member0x5c;
	int  member0x60;
	DWORD  NumberOfProcessors;
	DWORD  NtGlobalFlag;
};


struct PEB_LDR_DATA {
	int  member0x00;
	int  member0x04;
	int  member0x08;
	Load_Module*  InLoadOrderModuleList;
	int  member0x10;
	Memory_Module*  InMemoryOrderModuleList;
	int  member0x18;
	Init_Module*  InInitializationOrderModuleList;
};


struct Load_Module {
	Load_Module*  NextModule;
	Load_Module*  PreviousModule;
	int  member0x08;
	int  member0x0c;
	int  member0x10;
	int  member0x14;
	int32  ImgBase;
	int32  EntryPoint;
	int32  SizeOfImg;
	int  member0x24;
	int  member0x28;
	int  member0x2c;
	wchar_t*  name;
};


struct Memory_Module {
	Memory_Module*  NextModule;
	Memory_Module*  PreviousModule;
	int  member0x08;
	int  member0x0c;
	int32  ImgBase;
	int32  EntryPoint;
	int32  SizeOfImg;
	int  member0x1c;
	wchar_t*  Path;
};


struct Init_Module {
	Init_Module*  NextModule;
	Init_Module*  PreviousModule;
	int32  ImgBase;
	int32  EntryPoint;
	int32  SizeOfImg;
	int  member0x14;
	int  member0x18;
	int  member0x1c;
	wchar_t*  name;
};








// https://gist.github.com/mrexodia/e949ab26d5986a5fc1fa4944ac68147a#file-context32-h

struct FLOATING_SAVE_AREA
{
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[80]; //[SIZE_OF_80387_REGISTERS];
    DWORD   Spare0;
};

struct CONTEXT
{

    DWORD ContextFlags;

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    FLOATING_SAVE_AREA FloatSave;

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    BYTE    ExtendedRegisters[512]; //[MAXIMUM_SUPPORTED_EXTENSION];

};








// about PE

struct IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
};


struct IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
};


struct IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
};


struct IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};


struct IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
};








// etc

struct STARTUPINFO {
  DWORD  cb;
  LPTSTR lpReserved;
  LPTSTR lpDesktop;
  LPTSTR lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
};


struct PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD                          noSupport;
};


struct STARTUPINFOEX {
  STARTUPINFO                 StartupInfo;
  PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList;
};




struct PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
};


union DUMMYUNIONNAME {
    HANDLE hIcon;
    HANDLE hMonitor;
};


struct SHELLEXECUTEINFO {
  DWORD     cbSize;
  ULONG     fMask;
  HWND      hwnd;
  LPCTSTR   lpVerb;
  LPCTSTR   lpFile;
  LPCTSTR   lpParameters;
  LPCTSTR   lpDirectory;
  int       nShow;
  HINSTANCE hInstApp;
  LPVOID    lpIDList;
  LPCTSTR   lpClass;
  HKEY      hkeyClass;
  DWORD     dwHotKey;
  DUMMYUNIONNAME    dummyunion;
  HANDLE    hProcess;
};








struct MEMORY_BASIC_INFORMATION {
  PVOID  BaseAddress;
  PVOID  AllocationBase;
  DWORD  AllocationProtect;
  SIZE_T RegionSize;
  DWORD  State;
  DWORD  Protect;
  DWORD  Type;
};








struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  char*    szExeFile;
//  TCHAR     szExeFile[MAX_PATH]
};


struct filetime {
// It should be FILETIME but Error Occurs
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
};


struct WIN32_FIND_DATA {
  DWORD    dwFileAttributes;
// It should be FILETIME but Error Occurs
  filetime ftCreationTime;
  filetime ftLastAccessTime;
  filetime ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  TCHAR    cFileName[256];
  TCHAR    cAlternateFileName[14];
};








// network

struct WSAData {
  WORD           wVersion;
  WORD           wHighVersion;
  char           szDescription[257];
  char           szSystemStatus[257];
  unsigned short iMaxSockets;
  unsigned short iMaxUdpDg;
  char*          lpVendorInfo;
};


struct sockaddr {
        unsigned short  sa_family;
        char    sa_data[14];
};


struct sockaddr_in {
        short   sin_family;
        unsigned short sin_port;
        in_addr  sin_addr;
        char    sin_zero[8];
};


struct S_un_b {
  unsigned char s_b1;
  unsigned char s_b2;
  unsigned char s_b3;
  unsigned char s_b4;
};


struct S_un_w {
  unsigned short s_w1;
  unsigned short s_w2;
};


union S_un {
  S_un_b S_un_b;
  S_un_w S_un_w;
};


struct in_addr {
  S_un S_un;
};


struct addrinfo {
  int             ai_flags;
  int             ai_family;
  int             ai_socktype;
  int             ai_protocol;
  size_t          ai_addrlen;
  char*           ai_canonname;
  sockaddr*       ai_addr;
  addrinfo*       ai_next;
};


struct hostent {
  char*    h_name;
  char**    h_aliases;
  short         h_addrtype;
  short         h_length;
  char**    h_addr_list;
};


