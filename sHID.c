#include <windows.h>
#include <defs.h>


//-------------------------------------------------------------------------
// Data declarations

extern _UNKNOWN _ImageBase; // weak
extern _UNKNOWN unk_10000002; // weak
extern char Name[4]; // idb
extern void **off_10017420; // weak
extern int (*off_10017440)(); // weak
extern char *off_10017524; // weak
extern void *off_10017548; // weak
extern char *off_10017864; // weak
extern _UNKNOWN unk_10017958; // weak
extern _UNKNOWN unk_10017980; // weak
extern _UNKNOWN unk_100179B8; // weak
extern _UNKNOWN unk_100179D4; // weak
extern _UNKNOWN unk_100179E4; // weak
extern _UNKNOWN unk_100179F8; // weak
extern char *off_10017A14; // weak
extern int (*off_10017A44)(); // weak
extern char *off_10017A60; // weak
extern char *off_10017A94; // weak
extern char *off_10017AC8; // weak
extern int (*off_10017B24)(); // weak
extern int (*off_10017B3C)(); // weak
extern int (*off_10017B54)(); // weak
extern int (__thiscall *off_10017B6C)(void *, char); // weak
extern char aNotifywinevent[]; // idb
extern char LibFileName[]; // idb
extern char *off_10017BDC; // weak
extern void *off_10017C04; // weak
extern char *off_10017C24; // weak
extern char *off_10017C50; // weak
extern int (*off_10017C84)(); // weak
extern int (*off_10017C9C)(); // weak
extern int (*off_10017CB4)(); // weak
extern char *off_10017DDC; // weak
extern void *off_10017E00; // weak
extern void *off_10017E10; // weak
extern char aAfxwnd70s[10]; // weak
extern int (__thiscall *off_10018580)(void *, char); // weak
extern char aHtmlhelpa[]; // idb
extern char aHhctrl_ocx[]; // idb
extern char aCommctrl_dragl[]; // idb
extern char *off_10018724; // weak
extern int (*off_10018754)(); // weak
extern char *off_10018760; // weak
extern int (*off_10018788)(); // weak
extern char *off_1001879C; // weak
extern int (*off_100187D0)(); // weak
extern int (*off_100187F4)(); // weak
extern _UNKNOWN unk_10019A60; // weak
extern _UNKNOWN unk_1001A510; // weak
extern _UNKNOWN unk_1001A518; // weak
extern _UNKNOWN unk_1001AD94; // weak
extern char *off_1001D838; // weak
extern int dword_1001D870; // weak
extern int (*off_1001DC60)(void); // weak
extern void *off_1001DE24; // weak
extern _UNKNOWN unk_1001E420; // weak
extern _UNKNOWN unk_1001E438; // weak
extern _UNKNOWN unk_1001E720; // weak
extern char byte_1001E7C0; // weak
extern char byte_1001E7CC; // weak
extern _UNKNOWN unk_1001E7D8; // weak
extern _UNKNOWN unk_1001E870; // weak
extern _UNKNOWN unk_1001E908; // weak
extern int dword_1001E9A0; // weak
extern _UNKNOWN unk_1001E9A8; // weak
extern _UNKNOWN unk_1001EBDC; // weak
extern _UNKNOWN unk_1001EBE0; // weak
extern _UNKNOWN unk_1001EBE8; // weak
extern _UNKNOWN unk_1001EC80; // weak
extern _UNKNOWN unk_1001ED18; // weak
extern int dword_1001ED30; // weak
extern int dword_100205B4; // weak
extern int dword_100205B8; // weak
extern _UNKNOWN unk_100205C0; // weak
extern _UNKNOWN unk_10020610; // weak
extern _UNKNOWN unk_10020660; // weak
extern _UNKNOWN unk_100206B0; // weak
extern _UNKNOWN unk_10020704; // weak
extern int dword_1002070C; // weak
extern LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter; // idb
extern _UNKNOWN unk_10020C18; // weak
extern int dword_10020C58; // weak
extern int (__stdcall *dword_10020C5C)(_DWORD, _DWORD); // weak
extern int (__stdcall *dword_10020C60)(_DWORD, _DWORD); // weak

//-------------------------------------------------------------------------
// Function declarations

#define __thiscall __cdecl // Test compile in C mode

void ***__cdecl sub_10001000();
void *__thiscall sub_10001010(void *this);
int __thiscall sub_10001040(void *this);
int __thiscall sub_10001060(int this);
BOOL __thiscall sub_100010A0(BOOL this);
BOOL __thiscall sub_100010C0(BOOL this);
char __thiscall sub_10001130(BOOL this, int a2, int a3, int a4);
char __thiscall sub_10001450(int this);
char __thiscall sub_100014C0(int this);
char __thiscall sub_10001530(int this, int a2, unsigned int a3);
char __thiscall sub_10001600(int this, int a2, int a3);
char __thiscall sub_100016F0(int this, char a2, int a3);
char __thiscall sub_100017F0(int this, char a2, char a3);
char __thiscall sub_10001850(int this, char a2, int a3);
char __thiscall sub_10001890(int this, char a2, int a3);
char __thiscall sub_10001920(int this, char a2);
char __thiscall sub_10001990(int this, char a2);
char __thiscall sub_10001A00(int this, char a2);
char __thiscall sub_10001A70(int this);
char __thiscall sub_10001AC0(void *this, __int16 a2, unsigned __int16 a3, int a4);
char __thiscall sub_10001C00(void *this, __int16 a2, unsigned __int16 a3, int a4);
char __thiscall sub_10001D50(int this);
char __thiscall sub_10001DA0(void *this, __int16 a2, unsigned __int16 a3, int a4);
char __thiscall sub_10001EF0(void *this, __int16 a2, unsigned __int16 a3, int a4);
char __thiscall sub_10002040(int this, int a2);
char __thiscall sub_100020B0(int this, int a2);
int __cdecl sHID_create();
void *__stdcall sHID_destroy(BOOL a1);
char __stdcall sHID_Find(BOOL a1, int a2, int a3, int a4);
char __stdcall sHID_SetTX(int a1);
char __stdcall sHID_SetRX(int a1);
char __stdcall sHID_SetState(int a1, char a2);
char __stdcall sHID_SetFrame(int a1, int a2, unsigned int a3);
char __stdcall sHID_GetFrame(int a1, int a2, int a3);
char __stdcall sHID_WriteReg(int a1, char a2, char a3);
char __stdcall sHID_ReadReg(int a1, char a2, int a3);
char __stdcall sHID_ReadReg16(int a1, char a2, int a3);
char __stdcall sHID_GetReport(int a1, char a2, int a3);
char __stdcall sHID_SetPreamblePattern(int a1, char a2);
char __stdcall sHID_Execute(int a1, char a2);
char __stdcall sHID_EraseConfigFlash(int a1);
char __stdcall sHID_WriteConfigFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4);
char __stdcall sHID_ReadConfigFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4);
char __stdcall sHID_EraseDataFlash(int a1);
char __stdcall sHID_WriteDataFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4);
char __stdcall sHID_ReadDataFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4);
char __stdcall sHID_GetState(int a1, int a2);
char __stdcall sHID_GetRevInfo(int a1, int a2);
void *__thiscall sub_10002490(void *this, char a2);
int __cdecl sub_100024C0();
void *__thiscall sub_100024E0(BOOL this, char a2);
void __stdcall sub_10002520(void *a1);
void __stdcall sub_10002680(__int32 a1);
// int __stdcall HidD_GetHidGuid(_DWORD); weak
// int __stdcall HidD_FreePreparsedData(_DWORD); weak
// int __stdcall HidP_GetCaps(_DWORD, _DWORD); weak
// int __stdcall HidD_GetPreparsedData(_DWORD, _DWORD); weak
// int __stdcall HidD_GetAttributes(_DWORD, _DWORD); weak
// int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD); weak
// int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD); weak
void __cdecl sub_100026CE(); // idb
// int __thiscall ATL::CStringData::Release(_DWORD); weak
// int AfxGetMainWnd(void); weak
int __thiscall sub_100027D7(void *this, int a2);
void __cdecl sub_100027FD();
int __thiscall sub_10002830(void *this);
// _DWORD __stdcall unknown_libname_12(_DWORD); weak
void *__thiscall sub_10002938(void *this);
int loc_1000294C(); // weak
// int __stdcall ATL::CSimpleStringT<char_0>::SetString(char *); idb
// int __stdcall unknown_libname_13(HMODULE hModule, int); idb
HMODULE __stdcall sub_10002B30(unsigned int a1);
// _DWORD __stdcall ATL::CSimpleStringT<char_0>::CSimpleStringT<char_0>(_DWORD); weak
char __stdcall sub_10002C39(int a1);
void *__thiscall sub_10002C59(void *this, char *a2);
BOOL __thiscall sub_10002CD7(int this, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem);
void *__thiscall sub_10002D09(void *this, char a2);
void __thiscall sub_10002D25(void *this);
void __thiscall sub_10002D2C(void *this);
void __thiscall sub_10002D33(void *this);
void __thiscall sub_10002D3A(void *this);
// _DWORD __stdcall CSimpleException::CSimpleException(_DWORD); weak
void *__thiscall sub_10002D59(void *this, char a2);
void *__thiscall sub_10002D75(void *this, int a2, int a3);
void *__thiscall sub_10002D97(void *this, char a2);
void *__thiscall sub_10002DB3(void *this, int a2, int a3);
void *__thiscall sub_10002DD5(void *this, char a2);
void *__thiscall sub_10002DF1(void *this, int a2, int a3);
// int __stdcall CObject::operator delete(void *, int); idb
void *__thiscall sub_10002E90(void *this, int a2, int a3);
void __thiscall sub_10002EB2(void *this);
void *__thiscall sub_10002EB9(void *this, int a2, int a3);
void __thiscall sub_10002EDB(void *this);
BOOL __thiscall sub_10002EE2(int this, int x, int y);
BOOL __thiscall sub_10002EF6(int this, const RECT *lprect);
BOOL __thiscall sub_10002F06(int this, int x, int y, LPCSTR lpString, int c);
int __thiscall sub_10002F7F(int this, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format);
int __thiscall sub_10002FEA(int this, int iEscape, int cjIn, LPCSTR pvIn, LPVOID pvOut);
void *__thiscall sub_10003006(void *this, char a2);
void *__thiscall sub_10003022(void *this, char a2);
BOOL __thiscall sub_1000303E(int this);
void *__thiscall sub_10003049(void *this, char a2);
// int __fastcall ATL::CComCriticalSection::CComCriticalSection(void *); idb
// int __thiscall ATL::CComCriticalSection::Init(_DWORD); weak
BOOL __thiscall sub_100039BC(int this);
int __stdcall sub_100039E1(int a1, int a2);
signed int __stdcall sub_100039E6(int a1, int a2);
int __thiscall CFixedAllocNoSync::FreeAll(_DWORD); // weak
BOOL __thiscall sub_10003B6D(int this);
void *__thiscall sub_10003B78(void *this, char a2);
void *__thiscall sub_10003C90(void *this, int a2, char *a3);
void *__thiscall sub_10003CDD(void *this, char a2);
// int CArchiveException::_CArchiveException(void); weak
// void __cdecl free(void *);
// void *__cdecl malloc(size_t);
// int report_failure(void); weak
void __thiscall sub_10003E65(void *this);
// int __cdecl atexit(void (__cdecl *)());
// int __cdecl __CxxFrameHandler(struct EHExceptionRecord *, struct EHRegistrationNode *, struct _CONTEXT *, void *); idb
// size_t __cdecl strlen(const char *);
// void *__cdecl memset(void *, int, size_t);
// _DWORD __stdcall _CxxThrowException(_DWORD, _DWORD); weak
int __cdecl nullsub_2(_DWORD, _DWORD); // weak
// _DWORD __cdecl _unlock(_DWORD); weak
// _DWORD __cdecl _lock(_DWORD); weak
// int _getptd(void); weak
// void __cdecl terminate(); idb
void __cdecl sub_10007BD2();
int unk_10007BED(); // weak
void __cdecl sub_10008571();
void __cdecl sub_100085B5(); // idb
// LONG __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *); idb
int __cdecl sub_1000A236();
LPTOP_LEVEL_EXCEPTION_FILTER __cdecl sub_1000A249();
// int __updatetlocinfo(void); weak
void __cdecl sub_1000B8FE(signed int a1, int a2);
void __cdecl sub_1000B950(signed int a1, int a2);
// int __cdecl __tolower_mt(const CHAR MultiByteStr, WORD CharType); idb
int __cdecl sub_1000C3A8(WORD CharType); // idb
// _DWORD __cdecl _ld12cvt(_DWORD, _DWORD, _DWORD); weak
int __cdecl sub_1000C6C2(int a1, int a2);
int __cdecl sub_1000C6D8(int a1, int a2);
int __cdecl sub_1000C6EE(int a1, int a2);
int __cdecl sub_1000C72B(int a1, int a2);
// _DWORD __cdecl flsall(_DWORD); weak
int __cdecl sub_1000D01D();
// _DWORD __cdecl __strgtold12(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD); weak
int __thiscall sub_1000E171(int this);
int __thiscall sub_1000E1A1(int this);
int __stdcall sub_1000E284(int a1, int *Arguments);
// int unknown_libname_20(void); weak
// _DWORD __stdcall unknown_libname_22(_DWORD); weak
int __thiscall sub_1000E5B6(int this);
// int Concurrency::details::_Concurrent_queue_base_v4::__Concurrent_queue_base_v4(void); weak
void *__thiscall sub_1000E7CA(void *this, char a2);
// _DWORD __stdcall unknown_libname_24(_DWORD, _DWORD); weak
// int sub_1000E832(void); weak
int __thiscall sub_1000E85D(int this, int a2);
// _DWORD __stdcall unknown_libname_25(_DWORD, _DWORD, _DWORD); weak
int __thiscall sub_1000E8E5(int this, unsigned int a2);
void *__thiscall sub_1000E9A2(void *this, signed int a2);
int __thiscall sub_1000E9D0(void *this);
// int __thiscall CMapPtrToPtr::NewAssoc(_DWORD); weak
int __thiscall sub_1000EA26(void *this, int a2);
void *__thiscall sub_1000EA7B(void *this, char a2);
void **__cdecl sub_1000EA97();
// int __stdcall CWinApp::DevModeChange(LPCSTR pPrinterName); idb
int __thiscall sub_1000EC37(void *this, int a2, int a3);
int __thiscall sub_1000EC6B(void *this, int a2, int a3);
// _DWORD __stdcall AfxProcessWndProcException(_DWORD, _DWORD); weak
// void __stdcall loc_1000ED42(struct HINSTANCE__ *); weak
// void __stdcall loc_1000ED78(struct HINSTANCE__ *); weak
// void __stdcall loc_1000ED93(struct HINSTANCE__ *); weak
// void (__stdcall *__usercall sub_1000EDA4<eax>(int a1<ebp>))(struct HINSTANCE__ *);
// void (__stdcall *__usercall sub_1000EDB2<eax>(int a1<ebp>))(struct HINSTANCE__ *);
// void (__stdcall *__usercall sub_1000EDC0<eax>(int a1<ebp>))(struct HINSTANCE__ *);
int __cdecl sub_1000EE69();
// void __stdcall AfxInitThread(); idb
// int __thiscall CCmdTarget::_CCmdTarget(_DWORD); weak
signed int __stdcall sub_1000F571(int a1);
_UNKNOWN *__cdecl sub_1000F57F();
_UNKNOWN *__cdecl sub_1000F585();
_UNKNOWN *__cdecl sub_1000F58B();
_UNKNOWN *__cdecl sub_1000F591();
signed int __cdecl sub_1000F5C5();
_UNKNOWN *__cdecl sub_1000F5C9();
int __stdcall sub_1000F5CF(int a1);
_UNKNOWN *__cdecl sub_1000F5D4();
// int __thiscall CCmdTarget::BeginWaitCursor(_DWORD); weak
// int __thiscall CCmdTarget::EndWaitCursor(_DWORD); weak
BOOL __thiscall sub_1000F764(int this, LPCSTR lpString);
// int (__cdecl *__stdcall AfxSetNewHandler(int (__cdecl *)(unsigned int)))(unsigned int); idb
// int __cdecl operator new(size_t); idb
void __cdecl j__free(void *);
// int __thiscall CException::Delete(_DWORD); weak
// int CException::CException(void); weak
// void __usercall sub_1000F9CE(int a1<ebp>);
// void __stdcall AfxClassInit(struct CRuntimeClass *); idb
_UNKNOWN *__cdecl sub_1000FB8F();
void *__thiscall sub_1000FC0C(void *this);
// int __thiscall CAfxStringMgr::CAfxStringMgr(_DWORD); weak
int __cdecl sub_1000FC43();
// int __thiscall CWnd::GetStyle(_DWORD); weak
int __thiscall CProcessLocalObject::_CProcessLocalObject(_DWORD); // weak
int __thiscall sub_1000FEA5(void *this);
void __cdecl sub_1001002A();
BOOL __thiscall sub_1001003B(int this);
void *__thiscall sub_10010050(void *this, char a2);
void **__cdecl sub_1001006B();
void **__cdecl sub_1001014C();
signed int __stdcall sub_100101C5(int a1, int a2, int a3, int a4);
int __stdcall sub_100104D0(int a1);
int __cdecl sub_10010843();
// int __stdcall AfxEndDeferRegisterClass(__int32); idb
// int CWnd::GetCurrentMessage(void); weak
signed int __stdcall sub_10011151(int a1);
// int __thiscall CWnd::_CWnd(_DWORD); weak
// int __stdcall CWnd::SendMessageToDescendants(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, int, int); idb
void *__thiscall sub_10011A5F(void *this, char a2);
int __stdcall sub_10011B02(int a1, int a2, int a3, int a4);
// int __thiscall CWnd::GetTopLevelParent(_DWORD); weak
int __thiscall sub_10011D2E(void *this, LPCSTR pPrinterName);
// int __stdcall loc_10011F2A(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam); weak
// int (__stdcall *__usercall sub_10011FBC<eax>(int a1<ebp>))(HWND, UINT, WPARAM, LPARAM);
// int __thiscall CWnd::PrepareForHelp(_DWORD); weak
int __thiscall sub_10012B7C(void *this, ULONG_PTR dwData, UINT uCommand);
int __thiscall sub_10012BF6(void *this, int a2, int a3);
int __cdecl sub_10012CC0();
UINT __cdecl sub_10012CCC();
int __cdecl sub_10012D3D();
int __cdecl sub_10012D47();
int __cdecl sub_10012D51();
int __cdecl sub_10012D5B();
int __cdecl sub_10012D65();
// struct HINSTANCE__ *__stdcall AfxFindStringResourceHandle(unsigned int); idb
// _DWORD __stdcall afxMapHMENU(_DWORD); weak
int __thiscall sub_10012E6C(int this);
// int __stdcall AfxSetWindowText(HWND hWnd, LPCSTR lpString); idb
COLORREF __thiscall sub_100130BC(int this, COLORREF color);
COLORREF __thiscall sub_100130EB(int this, COLORREF color);
int __thiscall sub_1001311A(int this, int iMode);
int __thiscall sub_10013148(int this, LPRECT lprect);
// int __thiscall CDC::_CDC(_DWORD); weak
// _DWORD __stdcall afxMapHGDIOBJ(_DWORD); weak
int __thiscall sub_100134C4(int this);
void *__thiscall sub_10013504(void *this, char a2);
signed int __thiscall sub_1001393A(int this, LPSTR lpString1, int iMaxLength, int a4);
void __thiscall sub_10013A01(void *this, int a2, char *a3);
int __thiscall sub_10013AC0(int this);
// int __stdcall AfxMessageBox(unsigned int, unsigned int, unsigned int); idb
// int __cdecl ATL::CSimpleStringT<char_0>::Concatenate(int, void *, size_t, void *, size_t); idb
// int __usercall sub_10013E14<eax>(int a1<esi>, int a2, int a3, const char *a4);
// _DWORD __stdcall AfxFormatStrings(_DWORD, _DWORD, _DWORD, _DWORD); weak
// int __userpurge sub_10014038<eax>(int a1<ecx>, int a2<esi>, int a3, unsigned int a4, int a5, int a6);
// int __userpurge sub_1001409F<eax>(int a1<ecx>, int a2<esi>, int a3, unsigned int a4, char a5);
// int __cdecl CWinApp::_CWinApp();
char **__cdecl sub_10014703();
void *__thiscall sub_1001473D(void *this, char a2);
// int __cdecl CWinApp::InitInstance(_DWORD); weak
// int __stdcall CWinApp::CWinApp(char *); idb
signed int __cdecl sub_10014869();
char **__cdecl sub_10014B2B();
void *__thiscall sub_10014B65(void *this, char a2);
char **__cdecl sub_10014CA6();
char **__cdecl sub_10014CAC();
char **__cdecl sub_10014CB2();
char **__cdecl sub_10014CB8();
void __cdecl sub_10014D15(); // idb
void __cdecl sub_10014D1F(); // idb
void __cdecl sub_10014D29(); // idb
// int __stdcall unknown_libname_44(SIZE_T uBytes); idb
// void __cdecl CNoTrackObject::operator delete(void *); idb
// _DWORD __stdcall CProcessLocalObject::GetData(_DWORD); weak
void __cdecl sub_10014F52();
void __cdecl sub_10014F9A();
void *__thiscall sub_10014FF2(void *this);
void *__thiscall sub_100151A7(void *this, char a2);
int nullsub_1(void); // weak
// void __stdcall AfxTermLocalData(struct HINSTANCE__ *, int); idb
// void __stdcall AfxTlsRelease(); idb
// void __stdcall AfxCriticalTerm(); idb
// void __stdcall AfxLockGlobals(int); idb
// void __stdcall AfxUnlockGlobals(int); idb
int __thiscall CThreadLocalObject::_CThreadLocalObject(_DWORD); // weak
int __thiscall CProcessLocalObject::_CProcessLocalObject(_DWORD); // weak
// int AfxGetThreadState(void); weak
// int __thiscall AfxGetModuleState(_DWORD); weak
int __cdecl sub_100157CD();
int __cdecl sub_100157D9();
int __cdecl sub_100157E5();
int __cdecl sub_100157EF();
// int __thiscall CWinApp::SetCurrentHandles(_DWORD); weak
signed int __stdcall sub_10015976(int a1, int a2, int a3, int a4);
char **__cdecl sub_10015ACA();
char **__cdecl sub_10015AD0();
void **__cdecl sub_10015AD6();
char **__cdecl sub_10015ADC();
int __cdecl sub_10015B03();
int __stdcall sub_10015B39(int a1);
void __cdecl sub_10015B88(); // idb
void __cdecl sub_10015B92(); // idb
// int __thiscall AUX_DATA::AUX_DATA(_DWORD); weak
int __cdecl sub_10015BF1();
void __cdecl loc_10015C07(); // idb
char **__cdecl sub_10015C12();
int __cdecl sub_100161E2();
void *__thiscall sub_10016224(void *this, char a2);
// int CMFCComObject<ATL::CAccessibleProxy>::_CMFCComObject<ATL::CAccessibleProxy>(void); weak
// _DWORD __stdcall CMFCComObject<ATL::CAccessibleProxy>::AddRef(_DWORD); weak
// _DWORD __stdcall CMFCComObject<ATL::CAccessibleProxy>::Release(_DWORD); weak
int __stdcall sub_100162B3(int a1);
int __stdcall sub_100162BD(int a1);
int __stdcall sub_100162D1(int a1);
int __stdcall sub_100162DB(int a1);
char **__cdecl sub_1001636B();
char **__cdecl sub_10016371();
int __cdecl sub_10016377();
int __stdcall sub_10016391(int a1);
char **__cdecl sub_100163A6();
// int __stdcall _AfxInitDBCS(); idb
int __cdecl sub_100163DF();
char **__cdecl sub_100163EA();
int __cdecl sub_100163F0();
void __cdecl sub_10016406();
// void __stdcall AfxThrowOleException(__int32); idb
// int __thiscall CCmdTarget::ExternalRelease(_DWORD); weak
// int __thiscall CWinThread::_CWinThread(_DWORD); weak
// void __usercall sub_10016790(int a1<ebp>);
int __cdecl sub_10016799(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_100167A3<eax>(int a1<ebp>);
int __cdecl sub_100167AB(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_100167B5<eax>(int a1<ebp>);
int __cdecl sub_100167BD(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_100167C7();
int __cdecl sub_100167CF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_100167D9();
int __cdecl sub_100167E1(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_100167EB();
int __cdecl sub_100167F6(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_10016800();
void __cdecl sub_1001680B();
void __cdecl sub_10016816();
// int __usercall sub_10016835<eax>(int a1<ebp>);
int __cdecl sub_1001683D(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// void __usercall sub_10016847(int a1<ebp>);
int __cdecl sub_10016850(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// void __usercall sub_1001685A(int a1<ebp>);
int __cdecl sub_10016863(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_10016877<eax>(int a1<ebp>);
// int __usercall sub_10016891<eax>(int a1<ebp>);
// int __usercall sub_100168B3<eax>(int a1<ebp>);
// int __usercall sub_100168BE<eax>(int a1<ebp>);
// int __usercall sub_100168C9<eax>(int a1<ebp>);
// void __usercall sub_100168FC(int a1<ebp>);
int __cdecl sub_10016905(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_1001690F<eax>(int a1<ebp>);
// void __usercall sub_10016925(int a1<ebp>);
int __cdecl sub_10016939(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_10016943<eax>(int a1<ebp>);
int __cdecl sub_1001694B(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_10016955<eax>(int a1<ebp>);
int __cdecl sub_1001695D(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// void __usercall sub_10016967(int a1<ebp>);
// int __usercall sub_10016985<eax>(int a1<ebp>);
// int __usercall sub_1001698D<eax>(int a1<ebp>);
// int __usercall sub_10016995<eax>(int a1<ebp>);
// int __usercall sub_100169A7<eax>(int a1<ebp>);
int __cdecl sub_100169AF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// int __usercall sub_100169B9<eax>(int a1<ebp>);
int __cdecl sub_100169C1(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// void __usercall sub_100169CB(int a1<ebp>);
void __cdecl sub_100169DF();
void __cdecl sub_100169E7();
int __cdecl sub_100169EF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_100169F9();
int __cdecl sub_10016A04(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
// void __usercall sub_10016A0E(int a1<ebp>);
int __cdecl sub_10016A17(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
void __cdecl sub_10016A21();
int __cdecl sub_10016A29(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4);
int __cdecl sub_10016A40();
int __cdecl sub_10016A5C();
int __cdecl sub_10016A72();
int __cdecl sub_10016A90();
void __cdecl sub_10016A9F(); // idb
// COLORREF __stdcall SetBkColor(HDC hdc, COLORREF color);
// BOOL __stdcall DeleteObject(HGDIOBJ ho);
// int __stdcall Escape(HDC hdc, int iEscape, int cjIn, LPCSTR pvIn, LPVOID pvOut);
// BOOL __stdcall TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c);
// BOOL __stdcall RectVisible(HDC hdc, const RECT *lprect);
// BOOL __stdcall PtVisible(HDC hdc, int x, int y);
// int __stdcall GetClipBox(HDC hdc, LPRECT lprect);
// int __stdcall SetMapMode(HDC hdc, int iMode);
// COLORREF __stdcall SetTextColor(HDC hdc, COLORREF color);
// LPTOP_LEVEL_EXCEPTION_FILTER __stdcall SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
// void __stdcall RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments);
// UINT __stdcall SetErrorMode(UINT uMode);
// void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
// void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
// void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
// HLOCAL __stdcall LocalAlloc(UINT uFlags, SIZE_T uBytes);
// LPSTR __stdcall lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength);
// BOOL __stdcall FreeLibrary(HMODULE hLibModule);
// HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName);
// FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
// HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName);
// BOOL __stdcall CloseHandle(HANDLE hObject);
// HANDLE __stdcall CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
// HANDLE __stdcall CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
// DWORD __stdcall GetLastError();
// BOOL __stdcall CancelIo(HANDLE hFile);
// DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
// BOOL __stdcall ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
// BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
// LONG __stdcall InterlockedExchange(volatile LONG *Target, LONG Value);
// BOOL __stdcall SetupDiGetDeviceInterfaceDetailA(HDEVINFO DeviceInfoSet, PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData, PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData, DWORD DeviceInterfaceDetailDataSize, PDWORD RequiredSize, PSP_DEVINFO_DATA DeviceInfoData);
// HDEVINFO __stdcall SetupDiGetClassDevsA(const GUID *ClassGuid, PCSTR Enumerator, HWND hwndParent, DWORD Flags);
// BOOL __stdcall SetupDiEnumDeviceInterfaces(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, const GUID *InterfaceClassGuid, DWORD MemberIndex, PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
// BOOL __stdcall SetupDiDestroyDeviceInfoList(HDEVINFO DeviceInfoSet);
// BOOL __stdcall PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
// BOOL __stdcall EnableWindow(HWND hWnd, BOOL bEnable);
// UINT __stdcall GetMenuState(HMENU hMenu, UINT uId, UINT uFlags);
// BOOL __stdcall ModifyMenuA(HMENU hMnu, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem);
// int __stdcall DrawTextA(HDC hdc, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format);
// BOOL __stdcall DestroyMenu(HMENU hMenu);
// UINT __stdcall RegisterWindowMessageA(LPCSTR lpString);
// BOOL __stdcall WinHelpA(HWND hWndMain, LPCSTR lpszHelp, UINT uCommand, ULONG_PTR dwData);


//----- (10001000) --------------------------------------------------------
void ***__cdecl sub_10001000()
{
  return &off_10017420;
}
// 10017420: using guessed type void **off_10017420;

//----- (10001010) --------------------------------------------------------
void *__thiscall sub_10001010(void *this)
{
  void *v1; // ST04_4@1

  v1 = this;
  CWinApp::CWinApp(0);
  *(_DWORD *)v1 = &off_10017440;
  return v1;
}
// 10017440: using guessed type int (*off_10017440)();

//----- (10001040) --------------------------------------------------------
int __thiscall sub_10001040(void *this)
{
  return CWinApp::InitInstance(this);
}
// 10014759: using guessed type int __cdecl CWinApp__InitInstance(_DWORD);

//----- (10001060) --------------------------------------------------------
int __thiscall sub_10001060(int this)
{
  int v1; // ST04_4@1

  v1 = this;
  *(_DWORD *)(this + 80) = -1;
  *(_DWORD *)(this + 84) = -1;
  *(_DWORD *)(this + 88) = 0;
  HidD_GetHidGuid(this);
  return v1;
}
// 1000269E: using guessed type int __stdcall HidD_GetHidGuid(_DWORD);

//----- (100010A0) --------------------------------------------------------
BOOL __thiscall sub_100010A0(BOOL this)
{
  return sub_100010C0(this);
}

//----- (100010C0) --------------------------------------------------------
BOOL __thiscall sub_100010C0(BOOL this)
{
  BOOL result; // eax@3
  BOOL v2; // [sp+0h] [bp-4h]@1

  v2 = this;
  if ( *(_DWORD *)(this + 80) != -1 )
    CloseHandle(*(HANDLE *)(this + 80));
  result = v2;
  *(_DWORD *)(v2 + 80) = -1;
  if ( *(_DWORD *)(v2 + 84) != -1 )
    result = CloseHandle(*(HANDLE *)(v2 + 84));
  *(_DWORD *)(v2 + 84) = -1;
  if ( *(_DWORD *)(v2 + 88) )
    result = CloseHandle(*(HANDLE *)(v2 + 88));
  *(_DWORD *)(v2 + 88) = 0;
  return result;
}

//----- (10001130) --------------------------------------------------------
char __thiscall sub_10001130(BOOL this, int a2, int a3, int a4)
{
  BOOL InterfaceClassGuid; // [sp+0h] [bp-4Ch]@1
  int v6; // [sp+4h] [bp-48h]@15
  bool v7; // [sp+Bh] [bp-41h]@15
  struct _SP_DEVICE_INTERFACE_DATA DeviceInterfaceData; // [sp+Ch] [bp-40h]@3
  int v9; // [sp+28h] [bp-24h]@1
  int v10; // [sp+2Ch] [bp-20h]@10
  __int16 v11; // [sp+30h] [bp-1Ch]@10
  __int16 v12; // [sp+32h] [bp-1Ah]@10
  DWORD RequiredSize; // [sp+38h] [bp-14h]@6
  DWORD DeviceInterfaceDetailDataSize; // [sp+3Ch] [bp-10h]@6
  DWORD MemberIndex; // [sp+40h] [bp-Ch]@1
  PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData; // [sp+44h] [bp-8h]@6
  HDEVINFO DeviceInfoSet; // [sp+48h] [bp-4h]@1

  v9 = dword_1001D870;
  InterfaceClassGuid = this;
  sub_100010C0(this);
  DeviceInfoSet = SetupDiGetClassDevsA((const GUID *)InterfaceClassGuid, 0, 0, 0x12u);
  for ( MemberIndex = 0; ; ++MemberIndex )
  {
    DeviceInterfaceData.cbSize = 28;
    if ( !SetupDiEnumDeviceInterfaces(
            DeviceInfoSet,
            0,
            (const GUID *)InterfaceClassGuid,
            MemberIndex,
            &DeviceInterfaceData) )
      break;
    DeviceInterfaceDetailDataSize = 0;
    SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet, &DeviceInterfaceData, 0, 0, &DeviceInterfaceDetailDataSize, 0);
    DeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_A)malloc(DeviceInterfaceDetailDataSize);
    DeviceInterfaceDetailData->cbSize = 5;
    RequiredSize = 0;
    if ( SetupDiGetDeviceInterfaceDetailA(
           DeviceInfoSet,
           &DeviceInterfaceData,
           DeviceInterfaceDetailData,
           DeviceInterfaceDetailDataSize,
           &RequiredSize,
           0) )
    {
      *(_DWORD *)(InterfaceClassGuid + 80) = CreateFileA(
                                               DeviceInterfaceDetailData->DevicePath,
                                               0xC0000000u,
                                               3u,
                                               0,
                                               3u,
                                               0,
                                               0);
      if ( *(_DWORD *)(InterfaceClassGuid + 80) == -1 )
      {
        free(DeviceInterfaceDetailData);
      }
      else
      {
        v11 = 0;
        v12 = 0;
        v10 = 12;
        if ( (unsigned __int8)HidD_GetAttributes(*(_DWORD *)(InterfaceClassGuid + 80), &v10) )
        {
          if ( v11 == a2 && v12 == a3 )
          {
            v7 = HidD_GetPreparsedData(*(_DWORD *)(InterfaceClassGuid + 80), &v6);
            if ( v7 )
              v7 = HidP_GetCaps(v6, InterfaceClassGuid + 16) == 1114112;
            HidD_FreePreparsedData(v6);
            if ( v7 )
            {
              *(_DWORD *)(InterfaceClassGuid + 84) = CreateFileA(
                                                       DeviceInterfaceDetailData->DevicePath,
                                                       0xC0000000u,
                                                       3u,
                                                       0,
                                                       3u,
                                                       0x40000000u,
                                                       0);
              if ( *(_DWORD *)(InterfaceClassGuid + 84) == -1 )
              {
                free(DeviceInterfaceDetailData);
                CloseHandle(*(HANDLE *)(InterfaceClassGuid + 80));
                *(_DWORD *)(InterfaceClassGuid + 80) = -1;
              }
              else
              {
                free(DeviceInterfaceDetailData);
                *(_DWORD *)(InterfaceClassGuid + 88) = CreateEventA(0, 0, 1, Name);
                *(_DWORD *)(InterfaceClassGuid + 108) = *(_DWORD *)(InterfaceClassGuid + 88);
                *(_DWORD *)(InterfaceClassGuid + 100) = 0;
                *(_DWORD *)(InterfaceClassGuid + 104) = 0;
                if ( *(_DWORD *)(InterfaceClassGuid + 88) )
                {
                  SetupDiDestroyDeviceInfoList(DeviceInfoSet);
                  return 1;
                }
                CloseHandle(*(HANDLE *)(InterfaceClassGuid + 80));
                *(_DWORD *)(InterfaceClassGuid + 80) = -1;
                CloseHandle(*(HANDLE *)(InterfaceClassGuid + 84));
                *(_DWORD *)(InterfaceClassGuid + 84) = -1;
              }
            }
            else
            {
              free(DeviceInterfaceDetailData);
              CloseHandle(*(HANDLE *)(InterfaceClassGuid + 80));
              *(_DWORD *)(InterfaceClassGuid + 80) = -1;
            }
          }
          else
          {
            free(DeviceInterfaceDetailData);
            CloseHandle(*(HANDLE *)(InterfaceClassGuid + 80));
            *(_DWORD *)(InterfaceClassGuid + 80) = -1;
          }
        }
        else
        {
          free(DeviceInterfaceDetailData);
          CloseHandle(*(HANDLE *)(InterfaceClassGuid + 80));
          *(_DWORD *)(InterfaceClassGuid + 80) = -1;
        }
      }
    }
    else
    {
      free(DeviceInterfaceDetailData);
    }
LABEL_2:
    ;
  }
  if ( GetLastError() != 259 )
    goto LABEL_2;
  SetupDiDestroyDeviceInfoList(DeviceInfoSet);
  return 0;
}
// 100026A4: using guessed type int __stdcall HidD_FreePreparsedData(_DWORD);
// 100026AA: using guessed type int __stdcall HidP_GetCaps(_DWORD, _DWORD);
// 100026B0: using guessed type int __stdcall HidD_GetPreparsedData(_DWORD, _DWORD);
// 100026B6: using guessed type int __stdcall HidD_GetAttributes(_DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001450) --------------------------------------------------------
char __thiscall sub_10001450(int this)
{
  char result; // al@5
  char v2[24]; // [sp+4h] [bp-20h]@1
  int v3; // [sp+1Ch] [bp-8h]@1
  unsigned int i; // [sp+20h] [bp-4h]@1

  v3 = dword_1001D870;
  v2[0] = -47;
  for ( i = 1; i < 0x15; ++i )
    v2[i] = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), v2, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001450: using guessed type char var_20[24];

//----- (100014C0) --------------------------------------------------------
char __thiscall sub_100014C0(int this)
{
  char result; // al@5
  char v2[24]; // [sp+4h] [bp-20h]@1
  int v3; // [sp+1Ch] [bp-8h]@1
  unsigned int i; // [sp+20h] [bp-4h]@1

  v3 = dword_1001D870;
  v2[0] = -48;
  for ( i = 1; i < 0x15; ++i )
    v2[i] = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), v2, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 100014C0: using guessed type char var_20[24];

//----- (10001530) --------------------------------------------------------
char __thiscall sub_10001530(int this, int a2, unsigned int a3)
{
  char result; // al@8
  char v4; // [sp+4h] [bp-140h]@1
  char v5; // [sp+5h] [bp-13Fh]@1
  char v6; // [sp+6h] [bp-13Eh]@1
  char v7[309]; // [sp+7h] [bp-13Dh]@3
  int v8; // [sp+13Ch] [bp-8h]@1
  unsigned int i; // [sp+140h] [bp-4h]@1

  v8 = dword_1001D870;
  v4 = -43;
  v5 = (unsigned __int8)a3 >> 8;
  v6 = a3;
  for ( i = 0; i < a3; ++i )
    v7[i] = *(_BYTE *)a2++;
  for ( i = a3 + 3; i < 0x131; ++i )
    *(&v4 + i) = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v4, 273) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001530: using guessed type char var_13D[309];

//----- (10001600) --------------------------------------------------------
char __thiscall sub_10001600(int this, int a2, int a3)
{
  char result; // al@5
  char v4; // [sp+8h] [bp-148h]@3
  unsigned __int8 v5; // [sp+9h] [bp-147h]@6
  unsigned __int8 v6; // [sp+Ah] [bp-146h]@6
  char v7[313]; // [sp+Bh] [bp-145h]@8
  int v8; // [sp+144h] [bp-Ch]@1
  unsigned __int8 v9; // [sp+14Bh] [bp-5h]@6
  unsigned int i; // [sp+14Ch] [bp-4h]@1

  v8 = dword_1001D870;
  for ( i = 0; i < 0x131; ++i )
    *(&v4 + i) = 0;
  v4 = -42;
  if ( (unsigned __int8)HidD_GetFeature(*(_DWORD *)(this + 80), &v4, 273) )
  {
    v9 = v5;
    *(_DWORD *)a3 = (v6 | (unsigned __int16)(v5 << 8)) & 0x1FF;
    for ( i = 0; i < *(_DWORD *)a3; ++i )
      *(_BYTE *)a2++ = v7[i];
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001600: using guessed type char var_145[313];

//----- (100016F0) --------------------------------------------------------
char __thiscall sub_100016F0(int this, char a2, int a3)
{
  char result; // al@2
  int v4; // [sp+4h] [bp-144h]@1
  char Buffer; // [sp+8h] [bp-140h]@1
  char v6[303]; // [sp+9h] [bp-13Fh]@5
  int v7; // [sp+138h] [bp-10h]@1
  DWORD NumberOfBytesRead; // [sp+13Ch] [bp-Ch]@1
  DWORD v9; // [sp+140h] [bp-8h]@1
  unsigned int i; // [sp+144h] [bp-4h]@3

  v7 = dword_1001D870;
  v4 = this;
  Buffer = a2;
  ReadFile(*(HANDLE *)(this + 84), &Buffer, *(_WORD *)(this + 20), &NumberOfBytesRead, (LPOVERLAPPED)(this + 92));
  v9 = WaitForSingleObject(*(HANDLE *)(v4 + 88), 0x1F4u);
  if ( v9 )
  {
    CancelIo(*(HANDLE *)(v4 + 84));
    result = 0;
  }
  else
  {
    for ( i = 0; i < *(_WORD *)(v4 + 20); ++i )
      *(_BYTE *)a3++ = v6[i];
    result = 1;
  }
  return result;
}
// 1001D870: using guessed type int dword_1001D870;
// 100016F0: using guessed type char var_13F[303];

//----- (100017F0) --------------------------------------------------------
char __thiscall sub_100017F0(int this, char a2, char a3)
{
  char result; // al@2
  char v4; // [sp+4h] [bp-Ch]@1
  char v5; // [sp+5h] [bp-Bh]@1
  char v6; // [sp+6h] [bp-Ah]@1
  char v7; // [sp+7h] [bp-9h]@1
  char v8; // [sp+8h] [bp-8h]@1
  int v9; // [sp+Ch] [bp-4h]@1

  v9 = dword_1001D870;
  v4 = -16;
  v5 = a2 & 0x7F;
  v6 = 1;
  v7 = a3;
  v8 = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v4, 5) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001850) --------------------------------------------------------
char __thiscall sub_10001850(int this, char a2, int a3)
{
  char result; // al@2

  if ( sub_10001890(this, a2, a3) )
  {
    *(_WORD *)a3 &= 0xFFu;
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}

//----- (10001890) --------------------------------------------------------
char __thiscall sub_10001890(int this, char a2, int a3)
{
  char result; // al@2
  int v4; // [sp+0h] [bp-14h]@1
  char v5; // [sp+8h] [bp-Ch]@1
  __int16 v6; // [sp+9h] [bp-Bh]@1
  unsigned __int8 v7; // [sp+Bh] [bp-9h]@1
  unsigned __int8 v8; // [sp+Ch] [bp-8h]@1
  int v9; // [sp+10h] [bp-4h]@1

  v9 = dword_1001D870;
  v4 = this;
  v5 = -16;
  v6 = a2 & 0x7F;
  v7 = 0;
  v8 = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v5, 5) )
  {
    if ( (unsigned __int8)HidD_GetFeature(*(_DWORD *)(v4 + 80), &v5, 5) )
    {
      *(_WORD *)a3 = v7 | (unsigned __int16)(v8 << 8);
      result = 1;
    }
    else
    {
      result = 0;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001920) --------------------------------------------------------
char __thiscall sub_10001920(int this, char a2)
{
  char result; // al@5
  char v3; // [sp+4h] [bp-20h]@1
  char v4; // [sp+5h] [bp-1Fh]@1
  int v5; // [sp+1Ch] [bp-8h]@1
  unsigned int i; // [sp+20h] [bp-4h]@1

  v5 = dword_1001D870;
  v3 = -41;
  v4 = a2;
  for ( i = 2; i < 0x15; ++i )
    *(&v3 + i) = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v3, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001990) --------------------------------------------------------
char __thiscall sub_10001990(int this, char a2)
{
  char result; // al@5
  char v3; // [sp+4h] [bp-20h]@1
  char v4; // [sp+5h] [bp-1Fh]@1
  int v5; // [sp+1Ch] [bp-8h]@1
  unsigned int i; // [sp+20h] [bp-4h]@1

  v5 = dword_1001D870;
  v3 = -40;
  v4 = a2;
  for ( i = 2; i < 0x15; ++i )
    *(&v3 + i) = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v3, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001A00) --------------------------------------------------------
char __thiscall sub_10001A00(int this, char a2)
{
  char result; // al@5
  char v3; // [sp+4h] [bp-20h]@1
  char v4; // [sp+5h] [bp-1Fh]@1
  int v5; // [sp+1Ch] [bp-8h]@1
  unsigned int i; // [sp+20h] [bp-4h]@1

  v5 = dword_1001D870;
  v3 = -39;
  v4 = a2;
  for ( i = 2; i < 0x15; ++i )
    *(&v3 + i) = 0;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v3, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001A70) --------------------------------------------------------
char __thiscall sub_10001A70(int this)
{
  char result; // al@2
  char v2; // [sp+4h] [bp-1Ch]@1
  char v3; // [sp+5h] [bp-1Bh]@1
  int v4; // [sp+1Ch] [bp-4h]@1

  v4 = dword_1001D870;
  v2 = -38;
  v3 = 10;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v2, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001AC0) --------------------------------------------------------
char __thiscall sub_10001AC0(void *this, __int16 a2, unsigned __int16 a3, int a4)
{
  char result; // al@2
  void *v5; // [sp+0h] [bp-28h]@1
  char v6; // [sp+4h] [bp-24h]@6
  char v7; // [sp+5h] [bp-23h]@7
  char v8; // [sp+6h] [bp-22h]@7
  char v9; // [sp+7h] [bp-21h]@7
  char v10[24]; // [sp+8h] [bp-20h]@10
  int v11; // [sp+20h] [bp-8h]@1
  unsigned __int8 i; // [sp+27h] [bp-1h]@4

  v11 = dword_1001D870;
  v5 = this;
  if ( (signed int)a3 <= 512 )
  {
    while ( a3 )
    {
      for ( i = 0; i < 0x19u; ++i )
        *(&v6 + i) = -1;
      v6 = -37;
      v7 = 10;
      v8 = HIBYTE(a2);
      v9 = a2;
      if ( (signed int)a3 < 16 )
      {
        for ( i = 0; i < (signed int)a3; ++i )
          v10[i] = *(_BYTE *)a4++;
        a3 = 0;
      }
      else
      {
        for ( i = 0; (signed int)i < 16; ++i )
          v10[i] = *(_BYTE *)a4++;
        a3 -= 16;
      }
      if ( !(unsigned __int8)HidD_SetFeature(*((_DWORD *)v5 + 20), &v6, 25) )
        return 0;
      a2 += 16;
    }
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001AC0: using guessed type char var_20[24];

//----- (10001C00) --------------------------------------------------------
char __thiscall sub_10001C00(void *this, __int16 a2, unsigned __int16 a3, int a4)
{
  char result; // al@2
  void *v5; // [sp+0h] [bp-24h]@1
  char v6; // [sp+4h] [bp-20h]@4
  char v7; // [sp+5h] [bp-1Fh]@4
  char v8; // [sp+6h] [bp-1Eh]@4
  char v9; // [sp+7h] [bp-1Dh]@4
  char v10[20]; // [sp+8h] [bp-1Ch]@6
  int v11; // [sp+1Ch] [bp-8h]@1
  unsigned __int8 i; // [sp+23h] [bp-1h]@9

  v11 = dword_1001D870;
  v5 = this;
  if ( (signed int)a3 <= 512 )
  {
    while ( a3 )
    {
      v6 = -35;
      v7 = 10;
      v8 = HIBYTE(a2);
      v9 = a2;
      if ( !(unsigned __int8)HidD_SetFeature(*((_DWORD *)v5 + 20), &v6, 21) )
        return 0;
      v6 = -36;
      v7 = 0;
      v8 = 0;
      v9 = 0;
      v10[0] = 0;
      if ( !(unsigned __int8)HidD_GetFeature(*((_DWORD *)v5 + 20), &v6, 21) )
        return 0;
      if ( (signed int)a3 < 16 )
      {
        for ( i = 0; i < (signed int)a3; ++i )
          *(_BYTE *)a4++ = v10[i];
        a3 = 0;
      }
      else
      {
        for ( i = 0; (signed int)i < 16; ++i )
          *(_BYTE *)a4++ = v10[i];
        a3 -= 16;
        a2 += 16;
      }
    }
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001C00: using guessed type char var_1C[20];

//----- (10001D50) --------------------------------------------------------
char __thiscall sub_10001D50(int this)
{
  char result; // al@2
  char v2; // [sp+4h] [bp-1Ch]@1
  char v3; // [sp+5h] [bp-1Bh]@1
  int v4; // [sp+1Ch] [bp-4h]@1

  v4 = dword_1001D870;
  v2 = -38;
  v3 = 11;
  if ( (unsigned __int8)HidD_SetFeature(*(_DWORD *)(this + 80), &v2, 21) )
    result = 1;
  else
    result = 0;
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10001DA0) --------------------------------------------------------
char __thiscall sub_10001DA0(void *this, __int16 a2, unsigned __int16 a3, int a4)
{
  char result; // al@2
  void *v5; // [sp+0h] [bp-28h]@1
  char v6; // [sp+4h] [bp-24h]@6
  char v7; // [sp+5h] [bp-23h]@7
  char v8; // [sp+6h] [bp-22h]@7
  char v9; // [sp+7h] [bp-21h]@7
  char v10[24]; // [sp+8h] [bp-20h]@10
  int v11; // [sp+20h] [bp-8h]@1
  unsigned __int16 i; // [sp+24h] [bp-4h]@4

  v11 = dword_1001D870;
  v5 = this;
  if ( (signed int)a3 <= 512 )
  {
    while ( a3 )
    {
      for ( i = 0; i < 0x19u; ++i )
        *(&v6 + i) = -1;
      v6 = -37;
      v7 = 11;
      v8 = HIBYTE(a2);
      v9 = a2;
      if ( (signed int)a3 < 16 )
      {
        for ( i = 0; i < (signed int)a3; ++i )
          v10[i] = *(_BYTE *)a4++;
        a3 = 0;
      }
      else
      {
        for ( i = 0; (signed int)i < 16; ++i )
          v10[i] = *(_BYTE *)a4++;
        a3 -= 16;
      }
      if ( !(unsigned __int8)HidD_SetFeature(*((_DWORD *)v5 + 20), &v6, 25) )
        return 0;
      a2 += 16;
    }
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001DA0: using guessed type char var_20[24];

//----- (10001EF0) --------------------------------------------------------
char __thiscall sub_10001EF0(void *this, __int16 a2, unsigned __int16 a3, int a4)
{
  char result; // al@2
  void *v5; // [sp+0h] [bp-24h]@1
  char v6; // [sp+4h] [bp-20h]@4
  char v7; // [sp+5h] [bp-1Fh]@4
  char v8; // [sp+6h] [bp-1Eh]@4
  char v9; // [sp+7h] [bp-1Dh]@4
  char v10[20]; // [sp+8h] [bp-1Ch]@6
  int v11; // [sp+1Ch] [bp-8h]@1
  unsigned __int8 i; // [sp+23h] [bp-1h]@9

  v11 = dword_1001D870;
  v5 = this;
  if ( (signed int)a3 <= 512 )
  {
    while ( a3 )
    {
      v6 = -35;
      v7 = 11;
      v8 = HIBYTE(a2);
      v9 = a2;
      if ( !(unsigned __int8)HidD_SetFeature(*((_DWORD *)v5 + 20), &v6, 21) )
        return 0;
      v6 = -36;
      v7 = 0;
      v8 = 0;
      v9 = 0;
      v10[0] = 0;
      if ( !(unsigned __int8)HidD_GetFeature(*((_DWORD *)v5 + 20), &v6, 21) )
        return 0;
      if ( (signed int)a3 < 16 )
      {
        for ( i = 0; i < (signed int)a3; ++i )
          *(_BYTE *)a4++ = v10[i];
        a3 = 0;
      }
      else
      {
        for ( i = 0; (signed int)i < 16; ++i )
          *(_BYTE *)a4++ = v10[i];
        a3 -= 16;
        a2 += 16;
      }
    }
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026BC: using guessed type int __stdcall HidD_SetFeature(_DWORD, _DWORD, _DWORD);
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 10001EF0: using guessed type char var_1C[20];

//----- (10002040) --------------------------------------------------------
char __thiscall sub_10002040(int this, int a2)
{
  char result; // al@2
  char v3; // [sp+4h] [bp-10h]@1
  char v4; // [sp+5h] [bp-Fh]@1
  char v5; // [sp+6h] [bp-Eh]@1
  char v6; // [sp+7h] [bp-Dh]@1
  char v7; // [sp+8h] [bp-Ch]@1
  int v8; // [sp+10h] [bp-4h]@1

  v8 = dword_1001D870;
  v3 = -34;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  if ( (unsigned __int8)HidD_GetFeature(*(_DWORD *)(this + 80), &v3, 10) )
  {
    *(_BYTE *)a2 = v4;
    *(_BYTE *)(a2 + 1) = v5;
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (100020B0) --------------------------------------------------------
char __thiscall sub_100020B0(int this, int a2)
{
  char result; // al@2
  char v3; // [sp+4h] [bp-20h]@1
  char v4; // [sp+5h] [bp-1Fh]@1
  char v5; // [sp+6h] [bp-1Eh]@1
  char v6; // [sp+7h] [bp-1Dh]@1
  char v7; // [sp+8h] [bp-1Ch]@1
  int v8; // [sp+1Ch] [bp-8h]@1
  unsigned __int8 i; // [sp+23h] [bp-1h]@3

  v8 = dword_1001D870;
  v3 = -33;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  if ( (unsigned __int8)HidD_GetFeature(*(_DWORD *)(this + 80), &v3, 21) )
  {
    for ( i = 0; (signed int)i < 20; ++i )
      *(_BYTE *)a2++ = *(&v4 + i);
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100026C2: using guessed type int __stdcall HidD_GetFeature(_DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (10002140) --------------------------------------------------------
int __cdecl sHID_create()
{
  int v1; // [sp+0h] [bp-Ch]@2
  int v2; // [sp+4h] [bp-8h]@1

  v2 = operator new(0x70u);
  if ( v2 )
    v1 = sub_10001060(v2);
  else
    v1 = 0;
  return v1;
}

//----- (10002180) --------------------------------------------------------
void *__stdcall sHID_destroy(BOOL a1)
{
  void *result; // eax@1

  result = (void *)a1;
  if ( a1 )
    result = sub_100024E0(a1, 1);
  return result;
}

//----- (100021C0) --------------------------------------------------------
char __stdcall sHID_Find(BOOL a1, int a2, int a3, int a4)
{
  return sub_10001130(a1, a2, a3, a4);
}

//----- (100021F0) --------------------------------------------------------
char __stdcall sHID_SetTX(int a1)
{
  return sub_10001450(a1);
}

//----- (10002210) --------------------------------------------------------
char __stdcall sHID_SetRX(int a1)
{
  return sub_100014C0(a1);
}

//----- (10002230) --------------------------------------------------------
char __stdcall sHID_SetState(int a1, char a2)
{
  return sub_10001920(a1, a2);
}

//----- (10002250) --------------------------------------------------------
char __stdcall sHID_SetFrame(int a1, int a2, unsigned int a3)
{
  return sub_10001530(a1, a2, a3);
}

//----- (10002270) --------------------------------------------------------
char __stdcall sHID_GetFrame(int a1, int a2, int a3)
{
  return sub_10001600(a1, a2, a3);
}

//----- (10002290) --------------------------------------------------------
char __stdcall sHID_WriteReg(int a1, char a2, char a3)
{
  return sub_100017F0(a1, a2, a3);
}

//----- (100022B0) --------------------------------------------------------
char __stdcall sHID_ReadReg(int a1, char a2, int a3)
{
  return sub_10001850(a1, a2, a3);
}

//----- (100022D0) --------------------------------------------------------
char __stdcall sHID_ReadReg16(int a1, char a2, int a3)
{
  return sub_10001890(a1, a2, a3);
}

//----- (100022F0) --------------------------------------------------------
char __stdcall sHID_GetReport(int a1, char a2, int a3)
{
  return sub_100016F0(a1, a2, a3);
}

//----- (10002310) --------------------------------------------------------
char __stdcall sHID_SetPreamblePattern(int a1, char a2)
{
  return sub_10001990(a1, a2);
}

//----- (10002330) --------------------------------------------------------
char __stdcall sHID_Execute(int a1, char a2)
{
  return sub_10001A00(a1, a2);
}

//----- (10002350) --------------------------------------------------------
char __stdcall sHID_EraseConfigFlash(int a1)
{
  return sub_10001A70(a1);
}

//----- (10002370) --------------------------------------------------------
char __stdcall sHID_WriteConfigFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4)
{
  return sub_10001AC0(a1, a2, a3, a4);
}

//----- (100023A0) --------------------------------------------------------
char __stdcall sHID_ReadConfigFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4)
{
  return sub_10001C00(a1, a2, a3, a4);
}

//----- (100023D0) --------------------------------------------------------
char __stdcall sHID_EraseDataFlash(int a1)
{
  return sub_10001D50(a1);
}

//----- (100023F0) --------------------------------------------------------
char __stdcall sHID_WriteDataFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4)
{
  return sub_10001DA0(a1, a2, a3, a4);
}

//----- (10002420) --------------------------------------------------------
char __stdcall sHID_ReadDataFlash(void *a1, __int16 a2, unsigned __int16 a3, int a4)
{
  return sub_10001EF0(a1, a2, a3, a4);
}

//----- (10002450) --------------------------------------------------------
char __stdcall sHID_GetState(int a1, int a2)
{
  return sub_10002040(a1, a2);
}

//----- (10002470) --------------------------------------------------------
char __stdcall sHID_GetRevInfo(int a1, int a2)
{
  return sub_100020B0(a1, a2);
}

//----- (10002490) --------------------------------------------------------
void *__thiscall sub_10002490(void *this, char a2)
{
  void *v3; // [sp+0h] [bp-4h]@1

  v3 = this;
  sub_100024C0();
  if ( a2 & 1 )
    sub_10002520(v3);
  return v3;
}

//----- (100024C0) --------------------------------------------------------
int __cdecl sub_100024C0()
{
  return CWinApp::_CWinApp();
}

//----- (100024E0) --------------------------------------------------------
void *__thiscall sub_100024E0(BOOL this, char a2)
{
  void *v3; // [sp+0h] [bp-4h]@1

  v3 = (void *)this;
  sub_100010A0(this);
  if ( a2 & 1 )
    j__free(v3);
  return v3;
}

//----- (10002520) --------------------------------------------------------
void __stdcall sub_10002520(void *a1)
{
  j__free(a1);
}

//----- (10002680) --------------------------------------------------------
void __stdcall sub_10002680(__int32 a1)
{
  if ( a1 == -2147024882 )
    unknown_libname_20();
  AfxThrowOleException(a1);
}
// 1000E540: using guessed type int unknown_libname_20(void);

//----- (100026CE) --------------------------------------------------------
void __cdecl sub_100026CE()
{
  AfxTermLocalData(0, 1);
  AfxCriticalTerm();
  AfxTlsRelease();
}

//----- (100027D7) --------------------------------------------------------
int __thiscall sub_100027D7(void *this, int a2)
{
  int result; // eax@1

  result = a2;
  if ( a2 < 0 || a2 > *(_DWORD *)(*(_DWORD *)this - 8) )
    sub_10002680(-2147024809);
  *(_DWORD *)(*(_DWORD *)this - 12) = a2;
  *(_BYTE *)(a2 + *(_DWORD *)this) = 0;
  return result;
}

//----- (100027FD) --------------------------------------------------------
void __cdecl sub_100027FD()
{
  sub_10002680(-2147024882);
}

//----- (10002830) --------------------------------------------------------
int __thiscall sub_10002830(void *this)
{
  void *v1; // esi@1
  int result; // eax@1
  int v3; // ecx@1
  int v4; // edi@1

  v1 = this;
  result = *(_DWORD *)this;
  v3 = *(_DWORD *)this - 16;
  v4 = *(_DWORD *)v3;
  if ( *(_DWORD *)(v3 + 4) )
  {
    if ( *(_DWORD *)(v3 + 12) >= 0 )
    {
      ATL::CStringData::Release(v3);
      result = (*(int (__thiscall **)(int))(*(_DWORD *)v4 + 12))(v4) + 16;
      *(_DWORD *)v1 = result;
    }
    else
    {
      if ( *(_DWORD *)(result - 8) < 0 )
        sub_10002680(-2147024809);
      *(_DWORD *)(result - 12) = 0;
      result = *(_DWORD *)v1;
      **(_BYTE **)v1 = 0;
    }
  }
  return result;
}
// 100027AA: using guessed type int __thiscall ATL__CStringData__Release(_DWORD);

//----- (10002938) --------------------------------------------------------
void *__thiscall sub_10002938(void *this)
{
  void *v1; // esi@1
  _UNKNOWN *v2; // eax@1

  v1 = this;
  v2 = sub_1000FB8F();
  unknown_libname_12(v2);
  return v1;
}
// 10002873: using guessed type _DWORD __stdcall unknown_libname_12(_DWORD);

//----- (10002B30) --------------------------------------------------------
HMODULE __stdcall sub_10002B30(unsigned int a1)
{
  HMODULE result; // eax@1

  result = AfxFindStringResourceHandle(a1);
  if ( result )
    result = (HMODULE)unknown_libname_13(result, a1);
  return result;
}

//----- (10002C39) --------------------------------------------------------
char __stdcall sub_10002C39(int a1)
{
  char result; // al@1

  result = 0;
  if ( a1 )
  {
    if ( !(a1 & 0xFFFF0000) )
    {
      sub_10002B30((unsigned __int16)a1);
      result = 1;
    }
  }
  return result;
}

//----- (10002C59) --------------------------------------------------------
void *__thiscall sub_10002C59(void *this, char *a2)
{
  void *v2; // esi@1
  _UNKNOWN *v3; // eax@1

  v2 = this;
  v3 = sub_1000FB8F();
  unknown_libname_12(v3);
  if ( !sub_10002C39((int)a2) )
    ATL::CSimpleStringT<char_0>::SetString(a2);
  return v2;
}
// 10002873: using guessed type _DWORD __stdcall unknown_libname_12(_DWORD);

//----- (10002CD7) --------------------------------------------------------
BOOL __thiscall sub_10002CD7(int this, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem)
{
  return ModifyMenuA(*(HMENU *)(this + 4), uPosition, uFlags, uIDNewItem, lpNewItem);
}

//----- (10002D09) --------------------------------------------------------
void *__thiscall sub_10002D09(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002D25(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10002D25) --------------------------------------------------------
void __thiscall sub_10002D25(void *this)
{
  *(_DWORD *)this = &off_10017A44;
}
// 10017A44: using guessed type int (*off_10017A44)();

//----- (10002D2C) --------------------------------------------------------
void __thiscall sub_10002D2C(void *this)
{
  *(_DWORD *)this = &off_10017B24;
}
// 10017B24: using guessed type int (*off_10017B24)();

//----- (10002D33) --------------------------------------------------------
void __thiscall sub_10002D33(void *this)
{
  *(_DWORD *)this = &off_10017B3C;
}
// 10017B3C: using guessed type int (*off_10017B3C)();

//----- (10002D3A) --------------------------------------------------------
void __thiscall sub_10002D3A(void *this)
{
  *(_DWORD *)this = &off_10017B54;
}
// 10017B54: using guessed type int (*off_10017B54)();

//----- (10002D59) --------------------------------------------------------
void *__thiscall sub_10002D59(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002D2C(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10002D75) --------------------------------------------------------
void *__thiscall sub_10002D75(void *this, int a2, int a3)
{
  void *v3; // esi@1

  v3 = this;
  CSimpleException::CSimpleException(a2);
  *((_DWORD *)v3 + 37) = a3;
  *(_DWORD *)v3 = &off_10017B24;
  return v3;
}
// 10002D41: using guessed type _DWORD __stdcall CSimpleException__CSimpleException(_DWORD);
// 10017B24: using guessed type int (*off_10017B24)();

//----- (10002D97) --------------------------------------------------------
void *__thiscall sub_10002D97(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002D33(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10002DB3) --------------------------------------------------------
void *__thiscall sub_10002DB3(void *this, int a2, int a3)
{
  void *v3; // esi@1

  v3 = this;
  CSimpleException::CSimpleException(a2);
  *((_DWORD *)v3 + 37) = a3;
  *(_DWORD *)v3 = &off_10017B3C;
  return v3;
}
// 10002D41: using guessed type _DWORD __stdcall CSimpleException__CSimpleException(_DWORD);
// 10017B3C: using guessed type int (*off_10017B3C)();

//----- (10002DD5) --------------------------------------------------------
void *__thiscall sub_10002DD5(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002D3A(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10002DF1) --------------------------------------------------------
void *__thiscall sub_10002DF1(void *this, int a2, int a3)
{
  void *v3; // esi@1

  v3 = this;
  CSimpleException::CSimpleException(a2);
  *((_DWORD *)v3 + 37) = a3;
  *(_DWORD *)v3 = &off_10017B54;
  return v3;
}
// 10002D41: using guessed type _DWORD __stdcall CSimpleException__CSimpleException(_DWORD);
// 10017B54: using guessed type int (*off_10017B54)();

//----- (10002E90) --------------------------------------------------------
void *__thiscall sub_10002E90(void *this, int a2, int a3)
{
  void *v3; // esi@1

  v3 = this;
  CSimpleException::CSimpleException(a2);
  *((_DWORD *)v3 + 37) = a3;
  *(_DWORD *)v3 = &off_10017C84;
  return v3;
}
// 10002D41: using guessed type _DWORD __stdcall CSimpleException__CSimpleException(_DWORD);
// 10017C84: using guessed type int (*off_10017C84)();

//----- (10002EB2) --------------------------------------------------------
void __thiscall sub_10002EB2(void *this)
{
  *(_DWORD *)this = &off_10017C84;
}
// 10017C84: using guessed type int (*off_10017C84)();

//----- (10002EB9) --------------------------------------------------------
void *__thiscall sub_10002EB9(void *this, int a2, int a3)
{
  void *v3; // esi@1

  v3 = this;
  CSimpleException::CSimpleException(a2);
  *((_DWORD *)v3 + 37) = a3;
  *(_DWORD *)v3 = &off_10017C9C;
  return v3;
}
// 10002D41: using guessed type _DWORD __stdcall CSimpleException__CSimpleException(_DWORD);
// 10017C9C: using guessed type int (*off_10017C9C)();

//----- (10002EDB) --------------------------------------------------------
void __thiscall sub_10002EDB(void *this)
{
  *(_DWORD *)this = &off_10017C9C;
}
// 10017C9C: using guessed type int (*off_10017C9C)();

//----- (10002EE2) --------------------------------------------------------
BOOL __thiscall sub_10002EE2(int this, int x, int y)
{
  return PtVisible(*(HDC *)(this + 4), x, y);
}

//----- (10002EF6) --------------------------------------------------------
BOOL __thiscall sub_10002EF6(int this, const RECT *lprect)
{
  return RectVisible(*(HDC *)(this + 4), lprect);
}

//----- (10002F06) --------------------------------------------------------
BOOL __thiscall sub_10002F06(int this, int x, int y, LPCSTR lpString, int c)
{
  return TextOutA(*(HDC *)(this + 4), x, y, lpString, c);
}

//----- (10002F7F) --------------------------------------------------------
int __thiscall sub_10002F7F(int this, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format)
{
  return DrawTextA(*(HDC *)(this + 4), lpchText, cchText, lprc, format);
}

//----- (10002FEA) --------------------------------------------------------
int __thiscall sub_10002FEA(int this, int iEscape, int cjIn, LPCSTR pvIn, LPVOID pvOut)
{
  return Escape(*(HDC *)(this + 4), iEscape, cjIn, pvIn, pvOut);
}

//----- (10003006) --------------------------------------------------------
void *__thiscall sub_10003006(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002EB2(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10003022) --------------------------------------------------------
void *__thiscall sub_10003022(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10002EDB(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (1000303E) --------------------------------------------------------
BOOL __thiscall sub_1000303E(int this)
{
  BOOL result; // eax@2
  int v2; // eax@3

  *(_DWORD *)this = &off_10017CB4;
  if ( *(_DWORD *)(this + 4) )
  {
    v2 = sub_100134C4(this);
    result = DeleteObject((HGDIOBJ)v2);
  }
  else
  {
    result = 0;
  }
  return result;
}
// 10017CB4: using guessed type int (*off_10017CB4)();

//----- (10003049) --------------------------------------------------------
void *__thiscall sub_10003049(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_1000303E((int)this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (100039BC) --------------------------------------------------------
BOOL __thiscall sub_100039BC(int this)
{
  return EnableWindow(*(HWND *)(this + 28), 0);
}

//----- (100039E1) --------------------------------------------------------
int __stdcall sub_100039E1(int a1, int a2)
{
  return 0;
}

//----- (100039E6) --------------------------------------------------------
signed int __stdcall sub_100039E6(int a1, int a2)
{
  return -2147467263;
}

//----- (10003B6D) --------------------------------------------------------
BOOL __thiscall sub_10003B6D(int this)
{
  BOOL result; // eax@2
  int v2; // eax@3

  *(_DWORD *)this = &off_10018788;
  if ( *(_DWORD *)(this + 4) )
  {
    v2 = sub_10012E6C(this);
    result = DestroyMenu((HMENU)v2);
  }
  else
  {
    result = 0;
  }
  return result;
}
// 10018788: using guessed type int (*off_10018788)();

//----- (10003B78) --------------------------------------------------------
void *__thiscall sub_10003B78(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_10003B6D((int)this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10003C90) --------------------------------------------------------
void *__thiscall sub_10003C90(void *this, int a2, char *a3)
{
  void *v3; // esi@1

  v3 = this;
  CException::CException();
  *(_DWORD *)v3 = &off_100187D0;
  sub_10002938((char *)v3 + 12);
  *((_DWORD *)v3 + 2) = a2;
  ATL::CSimpleStringT<char_0>::SetString(a3);
  return v3;
}
// 1000F87B: using guessed type int CException__CException(void);
// 100187D0: using guessed type int (*off_100187D0)();

//----- (10003CDD) --------------------------------------------------------
void *__thiscall sub_10003CDD(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CArchiveException::_CArchiveException();
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 10003CF9: using guessed type int CArchiveException___CArchiveException(void);

//----- (10003E65) --------------------------------------------------------
void __thiscall sub_10003E65(void *this)
{
  if ( this != (void *)dword_1001D870 )
    report_failure();
}
// 10003E34: using guessed type int report_failure(void);
// 1001D870: using guessed type int dword_1001D870;

//----- (10007BD2) --------------------------------------------------------
void __cdecl sub_10007BD2()
{
  if ( off_1001DC60 )
  {
    off_1001DC60();
    JUMPOUT(*(int *)unk_10007BED);
  }
  terminate();
}
// 10007BED: using guessed type int();
// 1001DC60: using guessed type int (*off_1001DC60)(void);

//----- (10008571) --------------------------------------------------------
void __cdecl sub_10008571()
{
  unsigned int i; // [sp+Ch] [bp-1Ch]@1

  for ( i = (unsigned int)&unk_1001A510; i < (unsigned int)&unk_1001A510; i += 4 )
  {
    if ( *(_DWORD *)i )
      (*(void (**)(void))i)();
  }
}

//----- (100085B5) --------------------------------------------------------
void __cdecl sub_100085B5()
{
  unsigned int i; // [sp+Ch] [bp-1Ch]@1

  for ( i = (unsigned int)&unk_1001A518; i < (unsigned int)&unk_1001A518; i += 4 )
  {
    if ( *(_DWORD *)i )
      (*(void (**)(void))i)();
  }
}

//----- (1000A236) --------------------------------------------------------
int __cdecl sub_1000A236()
{
  lpTopLevelExceptionFilter = SetUnhandledExceptionFilter(__CxxUnhandledExceptionFilter);
  return 0;
}

//----- (1000A249) --------------------------------------------------------
LPTOP_LEVEL_EXCEPTION_FILTER __cdecl sub_1000A249()
{
  return SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
}

//----- (1000B8FE) --------------------------------------------------------
void __cdecl sub_1000B8FE(signed int a1, int a2)
{
  if ( a1 >= 20 )
    EnterCriticalSection((LPCRITICAL_SECTION)(a2 + 32));
  else
    _lock(a1 + 16);
}
// 100062C7: using guessed type _DWORD __cdecl _lock(_DWORD);

//----- (1000B950) --------------------------------------------------------
void __cdecl sub_1000B950(signed int a1, int a2)
{
  if ( a1 >= 20 )
    LeaveCriticalSection((LPCRITICAL_SECTION)(a2 + 32));
  else
    _unlock(a1 + 16);
}
// 10006212: using guessed type _DWORD __cdecl _unlock(_DWORD);

//----- (1000C3A8) --------------------------------------------------------
int __cdecl sub_1000C3A8(WORD CharType)
{
  void *v1; // eax@1

  v1 = *(void **)(_getptd() + 100);
  if ( v1 != off_1001DE24 )
    LOBYTE(v1) = __updatetlocinfo();
  return __tolower_mt((const CHAR)v1, CharType);
}
// 100078C7: using guessed type int _getptd(void);
// 1000AAAC: using guessed type int __updatetlocinfo(void);
// 1001DE24: using guessed type void *off_1001DE24;

//----- (1000C6C2) --------------------------------------------------------
int __cdecl sub_1000C6C2(int a1, int a2)
{
  return _ld12cvt(a1, a2, &unk_1001E420);
}
// 1000C56A: using guessed type _DWORD __cdecl _ld12cvt(_DWORD, _DWORD, _DWORD);

//----- (1000C6D8) --------------------------------------------------------
int __cdecl sub_1000C6D8(int a1, int a2)
{
  return _ld12cvt(a1, a2, &unk_1001E438);
}
// 1000C56A: using guessed type _DWORD __cdecl _ld12cvt(_DWORD, _DWORD, _DWORD);

//----- (1000C6EE) --------------------------------------------------------
int __cdecl sub_1000C6EE(int a1, int a2)
{
  char v3; // [sp+0h] [bp-14h]@1
  char v4; // [sp+4h] [bp-10h]@1
  int v5; // [sp+10h] [bp-4h]@1

  v5 = dword_1001D870;
  __strgtold12(&v4, &v3, a2, 0, 0, 0, 0);
  return sub_1000C6C2((int)&v4, a1);
}
// 1000D4B6: using guessed type _DWORD __cdecl __strgtold12(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (1000C72B) --------------------------------------------------------
int __cdecl sub_1000C72B(int a1, int a2)
{
  char v3; // [sp+0h] [bp-14h]@1
  char v4; // [sp+4h] [bp-10h]@1
  int v5; // [sp+10h] [bp-4h]@1

  v5 = dword_1001D870;
  __strgtold12(&v4, &v3, a2, 0, 0, 0, 0);
  return sub_1000C6D8((int)&v4, a1);
}
// 1000D4B6: using guessed type _DWORD __cdecl __strgtold12(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD);
// 1001D870: using guessed type int dword_1001D870;

//----- (1000D01D) --------------------------------------------------------
int __cdecl sub_1000D01D()
{
  return flsall(1);
}
// 1000CF48: using guessed type _DWORD __cdecl flsall(_DWORD);

//----- (1000E171) --------------------------------------------------------
int __thiscall sub_1000E171(int this)
{
  int v1; // esi@1

  v1 = this;
  ATL::CComCriticalSection::CComCriticalSection((void *)(this + 24));
  *(_DWORD *)(v1 + 48) = 0;
  *(_DWORD *)(v1 + 52) = 0;
  *(_DWORD *)(v1 + 56) = 0;
  return v1;
}

//----- (1000E1A1) --------------------------------------------------------
int __thiscall sub_1000E1A1(int this)
{
  int v1; // esi@1
  struct _OSVERSIONINFOA VersionInformation; // [sp+4h] [bp-20h]@1
  int v4; // [sp+98h] [bp+74h]@1

  v4 = dword_1001D870;
  v1 = this;
  sub_1000E171(this);
  *(_DWORD *)(v1 + 8) = &_ImageBase;
  *(_DWORD *)(v1 + 4) = &_ImageBase;
  *(_DWORD *)v1 = 60;
  *(_BYTE *)(v1 + 12) = 0;
  memset(&VersionInformation, 0, 0x94u);
  VersionInformation.dwOSVersionInfoSize = 148;
  GetVersionExA(&VersionInformation);
  if ( VersionInformation.dwPlatformId == 2 )
  {
    if ( VersionInformation.dwMajorVersion < 5 )
      goto LABEL_9;
    goto LABEL_8;
  }
  if ( VersionInformation.dwPlatformId == 1
    && (VersionInformation.dwMajorVersion > 4
     || VersionInformation.dwMajorVersion == 4 && VersionInformation.dwMinorVersion) )
LABEL_8:
    *(_BYTE *)(v1 + 12) = 1;
LABEL_9:
  *(_DWORD *)(v1 + 16) = 1808;
  *(_DWORD *)(v1 + 20) = &unk_10019A60;
  if ( ATL::CComCriticalSection::Init(v1 + 24) < 0 )
    byte_1001E7C0 = 1;
  return v1;
}
// 10003079: using guessed type int __thiscall ATL__CComCriticalSection__Init(_DWORD);
// 1001D870: using guessed type int dword_1001D870;
// 1001E7C0: using guessed type char byte_1001E7C0;

//----- (1000E284) --------------------------------------------------------
int __stdcall sub_1000E284(int a1, int *Arguments)
{
  int v2; // esi@1
  int v3; // ebx@1
  char *v4; // edi@1
  const CHAR *v5; // ecx@1
  char *v6; // ebx@1
  char *v7; // edx@1
  bool v8; // zf@1
  LONG v10; // edi@3
  unsigned int v11; // edx@3
  int v12; // ebx@6
  HLOCAL v13; // eax@17
  int v14; // eax@25
  int v15; // [sp+Ch] [bp-44h]@1
  int v16; // [sp+10h] [bp-40h]@1
  int *v17; // [sp+14h] [bp-3Ch]@1
  LPCSTR lpLibFileName; // [sp+18h] [bp-38h]@1
  unsigned int v19; // [sp+1Ch] [bp-34h]@1
  LPCSTR lpProcName; // [sp+20h] [bp-30h]@1
  LONG v21; // [sp+24h] [bp-2Ch]@1
  int v22; // [sp+28h] [bp-28h]@1
  DWORD v23; // [sp+2Ch] [bp-24h]@1
  volatile LONG *Target; // [sp+38h] [bp-18h]@1
  char *v25; // [sp+44h] [bp-Ch]@1
  int v26; // [sp+4Ch] [bp-4h]@1

  v2 = a1;
  v3 = *(_DWORD *)(a1 + 12);
  v4 = (char *)&_ImageBase + *(_DWORD *)(a1 + 20);
  v5 = (char *)&_ImageBase + *(_DWORD *)(a1 + 4);
  Target = (volatile LONG *)((char *)&_ImageBase + *(_DWORD *)(a1 + 8));
  v6 = (char *)&_ImageBase + v3;
  v7 = (char *)&_ImageBase + *(_DWORD *)(a1 + 16);
  v26 = *(_DWORD *)(a1 + 28);
  lpLibFileName = v5;
  v25 = v4;
  v17 = Arguments;
  v8 = (*(_DWORD *)a1 & 1) == 0;
  v15 = 36;
  v16 = a1;
  v19 = 0;
  lpProcName = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  if ( v8 )
  {
    Arguments = &v15;
    RaiseException(0xC06D0057u, 0, 1u, (const ULONG_PTR *)&Arguments);
    return 0;
  }
  v10 = *Target;
  v11 = *(_DWORD *)&v7[4 * ((signed int)((char *)Arguments - v6) >> 2)];
  a1 = 4 * ((signed int)((char *)Arguments - v6) >> 2);
  v19 = ~(v11 >> 31) & 1;
  if ( ~(v11 >> 31) & 1 )
    lpProcName = (char *)&unk_10000002 + v11;
  else
    lpProcName = (LPCSTR)(unsigned __int16)v11;
  v12 = 0;
  if ( !dword_10020C60 || (v12 = dword_10020C60(0, &v15)) == 0 )
  {
    if ( !v10 )
    {
      if ( !dword_10020C60 || (v10 = dword_10020C60(1, &v15)) == 0 )
      {
        v10 = (LONG)LoadLibraryA(lpLibFileName);
        if ( !v10 )
        {
          v23 = GetLastError();
          if ( !dword_10020C5C || (v10 = dword_10020C5C(3, &v15)) == 0 )
          {
            Arguments = &v15;
            RaiseException(0xC06D007Eu, 0, 1u, (const ULONG_PTR *)&Arguments);
            return v22;
          }
        }
      }
      if ( InterlockedExchange(Target, v10) == v10 )
      {
        FreeLibrary((HMODULE)v10);
      }
      else
      {
        if ( *(_DWORD *)(v2 + 24) )
        {
          v13 = LocalAlloc(0x40u, 8u);
          if ( v13 )
          {
            *((_DWORD *)v13 + 1) = v2;
            *(_DWORD *)v13 = dword_10020C58;
            dword_10020C58 = (int)v13;
          }
        }
      }
    }
    v21 = v10;
    if ( dword_10020C60 )
      v12 = dword_10020C60(2, &v15);
    if ( !v12 )
    {
      if ( !*(_DWORD *)(v2 + 20)
        || !*(_DWORD *)(v2 + 28)
        || (v14 = v10 + *(_DWORD *)(v10 + 60), *(_DWORD *)v14 != 17744)
        || *(_DWORD *)(v14 + 8) != v26
        || v10 != *(_DWORD *)(v14 + 52)
        || (v12 = *(_DWORD *)&v25[a1]) == 0 )
      {
        v12 = (int)GetProcAddress((HMODULE)v10, lpProcName);
        if ( !v12 )
        {
          v23 = GetLastError();
          if ( dword_10020C5C )
            v12 = dword_10020C5C(4, &v15);
          if ( !v12 )
          {
            a1 = (int)&v15;
            RaiseException(0xC06D007Fu, 0, 1u, (const ULONG_PTR *)&a1);
            v12 = v22;
          }
        }
      }
    }
    *Arguments = v12;
  }
  if ( dword_10020C60 )
  {
    v23 = 0;
    v21 = v10;
    v22 = v12;
    dword_10020C60(5, &v15);
  }
  return v12;
}
// 10020C58: using guessed type int dword_10020C58;
// 10020C5C: using guessed type int (__stdcall *dword_10020C5C)(_DWORD, _DWORD);
// 10020C60: using guessed type int (__stdcall *dword_10020C60)(_DWORD, _DWORD);

//----- (1000E5B6) --------------------------------------------------------
int __thiscall sub_1000E5B6(int this)
{
  int v1; // eax@1
  int v2; // edx@1
  bool v3; // zf@1
  int v4; // esi@1

  v1 = *(_DWORD *)(this + 4);
  v2 = *(_DWORD *)v1;
  v3 = *(_DWORD *)v1 == 0;
  v4 = *(_DWORD *)(v1 + 8);
  *(_DWORD *)(this + 4) = *(_DWORD *)v1;
  if ( v3 )
    *(_DWORD *)(this + 8) = 0;
  else
    *(_DWORD *)(v2 + 4) = 0;
  unknown_libname_22(v1);
  return v4;
}
// 1000E594: using guessed type _DWORD __stdcall unknown_libname_22(_DWORD);

//----- (1000E7CA) --------------------------------------------------------
void *__thiscall sub_1000E7CA(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  Concurrency::details::_Concurrent_queue_base_v4::__Concurrent_queue_base_v4();
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 1000E73D: using guessed type int Concurrency__details___Concurrent_queue_base_v4____Concurrent_queue_base_v4(void);

//----- (1000E85D) --------------------------------------------------------
int __thiscall sub_1000E85D(int this, int a2)
{
  int result; // eax@1
  bool v3; // zf@1

  result = a2;
  *(_DWORD *)a2 = *(_DWORD *)(this + 16);
  v3 = (*(_DWORD *)(this + 12))-- == 1;
  *(_DWORD *)(this + 16) = a2;
  if ( v3 )
    result = sub_1000E832();
  return result;
}
// 1000E832: using guessed type int sub_1000E832(void);

//----- (1000E8E5) --------------------------------------------------------
int __thiscall sub_1000E8E5(int this, unsigned int a2)
{
  int v2; // esi@1
  int result; // eax@2
  int v4; // edx@3

  v2 = *(_DWORD *)(this + 4);
  if ( v2 )
  {
    v4 = v2 + 4 * (a2 >> 4) % *(_DWORD *)(this + 8);
    for ( result = *(_DWORD *)v4; result; result = *(_DWORD *)result )
    {
      if ( *(_DWORD *)(result + 4) == a2 )
      {
        *(_DWORD *)v4 = *(_DWORD *)result;
        sub_1000E85D(this, result);
        return 1;
      }
      v4 = result;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}

//----- (1000E9A2) --------------------------------------------------------
void *__thiscall sub_1000E9A2(void *this, signed int a2)
{
  void *result; // eax@1
  signed int v3; // ecx@1

  result = this;
  v3 = a2;
  *(_DWORD *)result = &off_10018754;
  if ( a2 <= 0 )
    v3 = 10;
  *((_DWORD *)result + 1) = 0;
  *((_DWORD *)result + 2) = 17;
  *((_DWORD *)result + 3) = 0;
  *((_DWORD *)result + 4) = 0;
  *((_DWORD *)result + 5) = 0;
  *((_DWORD *)result + 6) = v3;
  return result;
}
// 10018754: using guessed type int (*off_10018754)();

//----- (1000E9D0) --------------------------------------------------------
int __thiscall sub_1000E9D0(void *this)
{
  *(_DWORD *)this = &off_10018754;
  return sub_1000E832();
}
// 1000E832: using guessed type int sub_1000E832(void);
// 10018754: using guessed type int (*off_10018754)();

//----- (1000EA26) --------------------------------------------------------
int __thiscall sub_1000EA26(void *this, int a2)
{
  int v2; // edi@1
  void *v3; // esi@1
  int v4; // eax@1
  int v5; // ecx@4
  char v7; // [sp+8h] [bp-4h]@1

  v2 = a2;
  v3 = this;
  v4 = unknown_libname_25(a2, &a2, &v7);
  if ( !v4 )
  {
    if ( !*((_DWORD *)v3 + 1) )
      unknown_libname_24(*((_DWORD *)v3 + 2), 1);
    v4 = CMapPtrToPtr::NewAssoc(v3);
    v5 = a2;
    *(_DWORD *)(v4 + 4) = v2;
    v5 *= 4;
    *(_DWORD *)v4 = *(_DWORD *)(v5 + *((_DWORD *)v3 + 1));
    *(_DWORD *)(v5 + *((_DWORD *)v3 + 1)) = v4;
  }
  return v4 + 8;
}
// 1000E7E6: using guessed type _DWORD __stdcall unknown_libname_24(_DWORD, _DWORD);
// 1000E876: using guessed type _DWORD __stdcall unknown_libname_25(_DWORD, _DWORD, _DWORD);
// 1000E9DB: using guessed type int __thiscall CMapPtrToPtr__NewAssoc(_DWORD);

//----- (1000EA7B) --------------------------------------------------------
void *__thiscall sub_1000EA7B(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_1000E9D0(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (1000EA97) --------------------------------------------------------
void **__cdecl sub_1000EA97()
{
  return &off_10017548;
}
// 10017548: using guessed type void *off_10017548;

//----- (1000EC37) --------------------------------------------------------
int __thiscall sub_1000EC37(void *this, int a2, int a3)
{
  void *v3; // edi@1
  int v4; // esi@1

  v3 = this;
  v4 = AfxGetMainWnd();
  *((_DWORD *)v3 + 22) = 0;
  PostMessageA(*(HWND *)(v4 + 28), 0x36Au, 0, 0);
  return (*(int (__thiscall **)(int, int, int))(*(_DWORD *)v4 + 116))(v4, a2, a3);
}
// 100027C4: using guessed type int AfxGetMainWnd(void);

//----- (1000EC6B) --------------------------------------------------------
int __thiscall sub_1000EC6B(void *this, int a2, int a3)
{
  void *v3; // edi@1
  int v4; // esi@1

  v3 = this;
  v4 = AfxGetMainWnd();
  *((_DWORD *)v3 + 22) = 0;
  PostMessageA(*(HWND *)(v4 + 28), 0x36Au, 0, 0);
  return (*(int (__thiscall **)(int, int, int))(*(_DWORD *)v4 + 120))(v4, a2, a3);
}
// 100027C4: using guessed type int AfxGetMainWnd(void);

//----- (1000EDA4) --------------------------------------------------------
void (__stdcall *__usercall sub_1000EDA4<eax>(int a1<ebp>))(struct HINSTANCE__ *)
{
  CException::Delete(*(_DWORD *)(a1 - 20));
  return loc_1000ED42;
}
// 1000ED42: using guessed type void __stdcall loc_1000ED42(struct HINSTANCE__ *);
// 1000F7FF: using guessed type int __thiscall CException__Delete(_DWORD);

//----- (1000EDB2) --------------------------------------------------------
void (__stdcall *__usercall sub_1000EDB2<eax>(int a1<ebp>))(struct HINSTANCE__ *)
{
  CException::Delete(*(_DWORD *)(a1 - 20));
  return loc_1000ED78;
}
// 1000ED78: using guessed type void __stdcall loc_1000ED78(struct HINSTANCE__ *);
// 1000F7FF: using guessed type int __thiscall CException__Delete(_DWORD);

//----- (1000EDC0) --------------------------------------------------------
void (__stdcall *__usercall sub_1000EDC0<eax>(int a1<ebp>))(struct HINSTANCE__ *)
{
  CException::Delete(*(_DWORD *)(a1 - 20));
  return loc_1000ED93;
}
// 1000ED93: using guessed type void __stdcall loc_1000ED93(struct HINSTANCE__ *);
// 1000F7FF: using guessed type int __thiscall CException__Delete(_DWORD);

//----- (1000EE69) --------------------------------------------------------
int __cdecl sub_1000EE69()
{
  return *(_DWORD *)(AfxGetThreadState() + 56);
}
// 10015780: using guessed type int AfxGetThreadState(void);

//----- (1000F571) --------------------------------------------------------
signed int __stdcall sub_1000F571(int a1)
{
  return 1;
}

//----- (1000F57F) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F57F()
{
  return &unk_10017958;
}

//----- (1000F585) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F585()
{
  return &unk_10017980;
}

//----- (1000F58B) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F58B()
{
  return &unk_100179B8;
}

//----- (1000F591) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F591()
{
  return &unk_100179D4;
}

//----- (1000F5C5) --------------------------------------------------------
signed int __cdecl sub_1000F5C5()
{
  return 1;
}

//----- (1000F5C9) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F5C9()
{
  return &unk_100179E4;
}

//----- (1000F5CF) --------------------------------------------------------
int __stdcall sub_1000F5CF(int a1)
{
  return 0;
}

//----- (1000F5D4) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000F5D4()
{
  return &unk_100179F8;
}

//----- (1000F764) --------------------------------------------------------
BOOL __thiscall sub_1000F764(int this, LPCSTR lpString)
{
  int v2; // esi@1
  BOOL result; // eax@1
  UINT v4; // eax@3

  v2 = this;
  result = *(_DWORD *)(this + 12);
  if ( result )
  {
    if ( !*(_DWORD *)(this + 16) )
    {
      v4 = GetMenuState(*(HMENU *)(result + 4), *(_DWORD *)(this + 8), 0x400u);
      result = sub_10002CD7(
                 *(_DWORD *)(v2 + 12),
                 *(_DWORD *)(v2 + 8),
                 v4 & 0xFFFFF6FB | 0x400,
                 *(_DWORD *)(v2 + 4),
                 lpString);
    }
  }
  else
  {
    result = AfxSetWindowText(*(HWND *)(*(_DWORD *)(this + 20) + 28), lpString);
  }
  return result;
}

//----- (1000F9CE) --------------------------------------------------------
void __usercall sub_1000F9CE(int a1<ebp>)
{
  AfxSetNewHandler(*(int (__cdecl **)(unsigned int))(a1 + 8));
  _CxxThrowException(0, 0);
}
// 10005408: using guessed type _DWORD __stdcall _CxxThrowException(_DWORD, _DWORD);

//----- (1000FB8F) --------------------------------------------------------
_UNKNOWN *__cdecl sub_1000FB8F()
{
  return &unk_1001ED18;
}

//----- (1000FC0C) --------------------------------------------------------
void *__thiscall sub_1000FC0C(void *this)
{
  return this;
}

//----- (1000FC43) --------------------------------------------------------
int __cdecl sub_1000FC43()
{
  return CAfxStringMgr::CAfxStringMgr(&unk_1001ED18);
}
// 1000FC0F: using guessed type int __thiscall CAfxStringMgr__CAfxStringMgr(_DWORD);

//----- (1000FEA5) --------------------------------------------------------
int __thiscall sub_1000FEA5(void *this)
{
  return (int)((char *)this + 60);
}

//----- (1001002A) --------------------------------------------------------
void __cdecl sub_1001002A()
{
  AfxUnlockGlobals(1);
  _CxxThrowException(0, 0);
}
// 10005408: using guessed type _DWORD __stdcall _CxxThrowException(_DWORD, _DWORD);

//----- (1001003B) --------------------------------------------------------
BOOL __thiscall sub_1001003B(int this)
{
  HMODULE v1; // ecx@1
  BOOL result; // eax@2

  *(_DWORD *)this = &off_10018580;
  v1 = *(HMODULE *)(this + 4);
  if ( v1 )
    result = FreeLibrary(v1);
  return result;
}
// 10018580: using guessed type int (__thiscall *off_10018580)(void *, char);

//----- (10010050) --------------------------------------------------------
void *__thiscall sub_10010050(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  sub_1001003B((int)this);
  if ( a2 & 1 )
    CNoTrackObject::operator delete(v2);
  return v2;
}

//----- (1001006B) --------------------------------------------------------
void **__cdecl sub_1001006B()
{
  return &off_10017E10;
}
// 10017E10: using guessed type void *off_10017E10;

//----- (1001014C) --------------------------------------------------------
void **__cdecl sub_1001014C()
{
  return &off_10017E00;
}
// 10017E00: using guessed type void *off_10017E00;

//----- (100101C5) --------------------------------------------------------
signed int __stdcall sub_100101C5(int a1, int a2, int a3, int a4)
{
  return -2147467263;
}

//----- (100104D0) --------------------------------------------------------
int __stdcall sub_100104D0(int a1)
{
  return CCmdTarget::ExternalRelease(a1 - 48);
}
// 100164D2: using guessed type int __thiscall CCmdTarget__ExternalRelease(_DWORD);

//----- (10010843) --------------------------------------------------------
int __cdecl sub_10010843()
{
  return 0;
}

//----- (10011151) --------------------------------------------------------
signed int __stdcall sub_10011151(int a1)
{
  if ( !*(_DWORD *)(a1 + 40) )
  {
    AfxEndDeferRegisterClass(1);
    *(_DWORD *)(a1 + 40) = "AfxWnd70s";
  }
  return 1;
}

//----- (10011A5F) --------------------------------------------------------
void *__thiscall sub_10011A5F(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CWnd::_CWnd(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10011B02) --------------------------------------------------------
int __stdcall sub_10011B02(int a1, int a2, int a3, int a4)
{
  int v4; // esi@1
  HMODULE v5; // eax@2
  FARPROC v6; // eax@3

  AfxLockGlobals(12);
  v4 = CProcessLocalObject::GetData(sub_100161E2);
  if ( !*(_DWORD *)(v4 + 8) )
  {
    v5 = LoadLibraryA("hhctrl.ocx");
    *(_DWORD *)(v4 + 4) = v5;
    if ( !v5 )
      return 0;
    v6 = GetProcAddress(v5, "HtmlHelpA");
    *(_DWORD *)(v4 + 8) = v6;
    if ( !v6 )
    {
      FreeLibrary(*(HMODULE *)(v4 + 4));
      *(_DWORD *)(v4 + 4) = 0;
      return 0;
    }
  }
  AfxUnlockGlobals(12);
  return (*(int (__stdcall **)(int, int, int, int))(v4 + 8))(a1, a2, a3, a4);
}
// 10014F07: using guessed type _DWORD __stdcall CProcessLocalObject__GetData(_DWORD);

//----- (10011D2E) --------------------------------------------------------
int __thiscall sub_10011D2E(void *this, LPCSTR pPrinterName)
{
  void *v2; // esi@1
  int v3; // eax@1
  int result; // eax@4
  int v5; // eax@5

  v2 = this;
  v3 = *(_DWORD *)(AfxGetModuleState(this) + 4);
  if ( v3 && *(void **)(v3 + 28) == v2 )
    CWinApp::DevModeChange(pPrinterName);
  result = CWnd::GetStyle(v2);
  if ( !(result & 0x40000000) )
  {
    v5 = CWnd::GetCurrentMessage();
    result = CWnd::SendMessageToDescendants(
               *((HWND *)v2 + 7),
               *(_DWORD *)(v5 + 4),
               *(_DWORD *)(v5 + 8),
               *(_DWORD *)(v5 + 12),
               1,
               1);
  }
  return result;
}
// 1000FCF3: using guessed type int __thiscall CWnd__GetStyle(_DWORD);
// 10010F8F: using guessed type int CWnd__GetCurrentMessage(void);
// 10015790: using guessed type int __thiscall AfxGetModuleState(_DWORD);

//----- (10011FBC) --------------------------------------------------------
int (__stdcall *__usercall sub_10011FBC<eax>(int a1<ebp>))(HWND, UINT, WPARAM, LPARAM)
{
  int v1; // eax@1
  int v2; // ecx@1

  *(_DWORD *)(a1 - 76) = *(_DWORD *)(a1 + 8);
  *(_DWORD *)(a1 - 72) = *(_DWORD *)(a1 + 12);
  *(_DWORD *)(a1 - 68) = *(_DWORD *)(a1 + 16);
  *(_DWORD *)(a1 - 64) = *(_DWORD *)(a1 + 20);
  v1 = AfxProcessWndProcException(*(_DWORD *)(a1 - 32), a1 - 76);
  v2 = *(_DWORD *)(a1 - 32);
  *(_DWORD *)(a1 - 20) = v1;
  CException::Delete(v2);
  return loc_10011F2A;
}
// 1000ED0A: using guessed type _DWORD __stdcall AfxProcessWndProcException(_DWORD, _DWORD);
// 1000F7FF: using guessed type int __thiscall CException__Delete(_DWORD);
// 10011F2A: using guessed type int __stdcall loc_10011F2A(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

//----- (10012B7C) --------------------------------------------------------
int __thiscall sub_10012B7C(void *this, ULONG_PTR dwData, UINT uCommand)
{
  void *v3; // edi@1
  int v4; // esi@1
  int v5; // eax@1
  int v6; // eax@1
  int v7; // ecx@1
  int v8; // eax@3

  v3 = this;
  v4 = *(_DWORD *)(AfxGetModuleState(this) + 4);
  v5 = AfxGetModuleState(v7);
  CCmdTarget::BeginWaitCursor(*(_DWORD *)(v5 + 4));
  CWnd::PrepareForHelp(v3);
  v6 = CWnd::GetTopLevelParent(v3);
  if ( !WinHelpA(*(HWND *)(v6 + 28), *(LPCSTR *)(v4 + 96), uCommand, dwData) )
    AfxMessageBox(0xF107u, 0, 0xFFFFFFFFu);
  v8 = AfxGetModuleState(v7);
  return CCmdTarget::EndWaitCursor(*(_DWORD *)(v8 + 4));
}
// 1000F600: using guessed type int __thiscall CCmdTarget__BeginWaitCursor(_DWORD);
// 1000F615: using guessed type int __thiscall CCmdTarget__EndWaitCursor(_DWORD);
// 10011CC0: using guessed type int __thiscall CWnd__GetTopLevelParent(_DWORD);
// 10012322: using guessed type int __thiscall CWnd__PrepareForHelp(_DWORD);
// 10015790: using guessed type int __thiscall AfxGetModuleState(_DWORD);

//----- (10012BF6) --------------------------------------------------------
int __thiscall sub_10012BF6(void *this, int a2, int a3)
{
  void *v3; // edi@1
  int v4; // esi@1
  int v5; // eax@1
  int v6; // eax@1
  int v7; // ecx@1
  int v8; // eax@3

  v3 = this;
  v4 = *(_DWORD *)(AfxGetModuleState(this) + 4);
  v5 = AfxGetModuleState(v7);
  CCmdTarget::BeginWaitCursor(*(_DWORD *)(v5 + 4));
  CWnd::PrepareForHelp(v3);
  v6 = CWnd::GetTopLevelParent(v3);
  if ( !sub_10011B02(*(_DWORD *)(v6 + 28), *(_DWORD *)(v4 + 96), a3, a2) )
    AfxMessageBox(0xF107u, 0, 0xFFFFFFFFu);
  v8 = AfxGetModuleState(v7);
  return CCmdTarget::EndWaitCursor(*(_DWORD *)(v8 + 4));
}
// 1000F600: using guessed type int __thiscall CCmdTarget__BeginWaitCursor(_DWORD);
// 1000F615: using guessed type int __thiscall CCmdTarget__EndWaitCursor(_DWORD);
// 10011CC0: using guessed type int __thiscall CWnd__GetTopLevelParent(_DWORD);
// 10012322: using guessed type int __thiscall CWnd__PrepareForHelp(_DWORD);
// 10015790: using guessed type int __thiscall AfxGetModuleState(_DWORD);

//----- (10012CC0) --------------------------------------------------------
int __cdecl sub_10012CC0()
{
  return atexit(sub_10012D3D);
}

//----- (10012CCC) --------------------------------------------------------
UINT __cdecl sub_10012CCC()
{
  UINT result; // eax@1

  result = RegisterWindowMessageA("commctrl_DragListMsg");
  dword_100205B8 = result;
  return result;
}
// 100205B8: using guessed type int dword_100205B8;

//----- (10012D3D) --------------------------------------------------------
int __cdecl sub_10012D3D()
{
  return CProcessLocalObject::_CProcessLocalObject(&unk_10020704);
}
// 1000FE01: using guessed type int __thiscall CProcessLocalObject___CProcessLocalObject(_DWORD);

//----- (10012D47) --------------------------------------------------------
int __cdecl sub_10012D47()
{
  return CWnd::_CWnd(&unk_100205C0);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10012D51) --------------------------------------------------------
int __cdecl sub_10012D51()
{
  return CWnd::_CWnd(&unk_10020610);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10012D5B) --------------------------------------------------------
int __cdecl sub_10012D5B()
{
  return CWnd::_CWnd(&unk_10020660);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10012D65) --------------------------------------------------------
int __cdecl sub_10012D65()
{
  return CWnd::_CWnd(&unk_100206B0);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10012E6C) --------------------------------------------------------
int __thiscall sub_10012E6C(int this)
{
  int v1; // esi@1
  int v2; // edi@1
  int v3; // eax@2

  v1 = this;
  v2 = *(_DWORD *)(this + 4);
  if ( v2 )
  {
    v3 = afxMapHMENU(0);
    if ( v3 )
      sub_1000E8E5(v3 + 28, *(_DWORD *)(v1 + 4));
  }
  *(_DWORD *)(v1 + 4) = 0;
  return v2;
}
// 10012DC8: using guessed type _DWORD __stdcall afxMapHMENU(_DWORD);

//----- (100130BC) --------------------------------------------------------
COLORREF __thiscall sub_100130BC(int this, COLORREF color)
{
  int v2; // esi@1
  HDC v3; // ecx@1
  COLORREF result; // eax@1
  HDC v5; // esi@3

  v2 = this;
  v3 = *(HDC *)(this + 4);
  result = -1;
  if ( v3 != *(HDC *)(v2 + 8) )
    result = SetBkColor(v3, color);
  v5 = *(HDC *)(v2 + 8);
  if ( v5 )
    result = SetBkColor(v5, color);
  return result;
}

//----- (100130EB) --------------------------------------------------------
COLORREF __thiscall sub_100130EB(int this, COLORREF color)
{
  int v2; // esi@1
  HDC v3; // ecx@1
  COLORREF result; // eax@1
  HDC v5; // esi@3

  v2 = this;
  v3 = *(HDC *)(this + 4);
  result = -1;
  if ( v3 != *(HDC *)(v2 + 8) )
    result = SetTextColor(v3, color);
  v5 = *(HDC *)(v2 + 8);
  if ( v5 )
    result = SetTextColor(v5, color);
  return result;
}

//----- (1001311A) --------------------------------------------------------
int __thiscall sub_1001311A(int this, int iMode)
{
  int v2; // esi@1
  HDC v3; // ecx@1
  int result; // eax@1
  HDC v5; // esi@3

  v2 = this;
  v3 = *(HDC *)(this + 4);
  result = 0;
  if ( v3 != *(HDC *)(v2 + 8) )
    result = SetMapMode(v3, iMode);
  v5 = *(HDC *)(v2 + 8);
  if ( v5 )
    result = SetMapMode(v5, iMode);
  return result;
}

//----- (10013148) --------------------------------------------------------
int __thiscall sub_10013148(int this, LPRECT lprect)
{
  return GetClipBox(*(HDC *)(this + 4), lprect);
}

//----- (100134C4) --------------------------------------------------------
int __thiscall sub_100134C4(int this)
{
  int v1; // esi@1
  int v2; // edi@1
  int v3; // eax@2

  v1 = this;
  v2 = *(_DWORD *)(this + 4);
  if ( v2 )
  {
    v3 = afxMapHGDIOBJ(0);
    if ( v3 )
      sub_1000E8E5(v3 + 28, *(_DWORD *)(v1 + 4));
  }
  *(_DWORD *)(v1 + 4) = 0;
  return v2;
}
// 1001343A: using guessed type _DWORD __stdcall afxMapHGDIOBJ(_DWORD);

//----- (10013504) --------------------------------------------------------
void *__thiscall sub_10013504(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CDC::_CDC(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 10013421: using guessed type int __thiscall CDC___CDC(_DWORD);

//----- (1001393A) --------------------------------------------------------
signed int __thiscall sub_1001393A(int this, LPSTR lpString1, int iMaxLength, int a4)
{
  int v4; // edi@1
  _UNKNOWN *v5; // eax@4
  int v6; // ecx@4
  int v7; // esi@4
  bool v8; // zf@4
  signed int result; // eax@6
  int v10; // [sp+0h] [bp-24h]@1
  LPCSTR lpString2; // [sp+10h] [bp-14h]@4
  int *v12; // [sp+14h] [bp-10h]@1
  int v13; // [sp+20h] [bp-4h]@4

  v12 = &v10;
  v4 = this;
  if ( lpString1 )
  {
    if ( a4 )
      *(_DWORD *)a4 = *(_DWORD *)(this + 8) + 61872;
    v13 = 0;
    v5 = sub_1000FB8F();
    lpString2 = (LPCSTR)((*(int (__thiscall **)(_UNKNOWN *))(*(_DWORD *)v5 + 12))(v5) + 16);
    LOBYTE(v13) = 1;
    ATL::CSimpleStringT<char_0>::CSimpleStringT<char_0>(v4 + 12);
    v7 = a4;
    v8 = *(_DWORD *)(a4 - 12) == 0;
    LOBYTE(v13) = 2;
    if ( v8 )
    {
      sub_10002B30(0xF006u);
      v7 = a4;
    }
    sub_1001409F(v6, v7, (int)&lpString2, *(_DWORD *)(v4 + 8) + 61872, v7);
    lstrcpynA(lpString1, lpString2, iMaxLength);
    ATL::CStringData::Release(v7 - 16);
    ATL::CStringData::Release(lpString2 - 16);
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100027AA: using guessed type int __thiscall ATL__CStringData__Release(_DWORD);
// 10002BCF: using guessed type _DWORD __stdcall ATL__CSimpleStringT_char_0___CSimpleStringT_char_0_(_DWORD);

//----- (10013A01) --------------------------------------------------------
void __thiscall sub_10013A01(void *this, int a2, char *a3)
{
  int v3; // eax@1
  void *v4; // ecx@1
  int v5; // ST08_4@1
  void *v6; // eax@1
  void *v7; // [sp+4h] [bp-10h]@1
  int v8; // [sp+10h] [bp-4h]@1

  v7 = this;
  v3 = operator new(0x10u);
  v4 = (void *)v3;
  v5 = v3;
  v6 = 0;
  v8 = 0;
  if ( v5 )
    v6 = sub_10003C90(v4, a2, a3);
  v8 = -1;
  v7 = v6;
  _CxxThrowException(&v7, &unk_1001AD94);
}
// 10005408: using guessed type _DWORD __stdcall _CxxThrowException(_DWORD, _DWORD);

//----- (10013AC0) --------------------------------------------------------
int __thiscall sub_10013AC0(int this)
{
  return (*(int (**)(void))(**(_DWORD **)(this + 84) + 28))();
}

//----- (10013E14) --------------------------------------------------------
int __usercall sub_10013E14<eax>(int a1<esi>, int a2, int a3, const char *a4)
{
  int v4; // ST0C_4@1
  void **v5; // esi@1
  int v6; // eax@1
  size_t v7; // eax@2

  v4 = a1;
  v5 = (void **)a3;
  v6 = (*(int (__stdcall **)(int, _DWORD))(**(_DWORD **)(*(_DWORD *)a3 - 16) + 16))(v4, 0);
  a3 = (*(int (__thiscall **)(int))(*(_DWORD *)v6 + 12))(v6) + 16;
  if ( a4 )
    v7 = strlen(a4);
  else
    v7 = 0;
  ATL::CSimpleStringT<char_0>::Concatenate((int)&a3, *v5, *((_DWORD *)*v5 - 3), (void *)a4, v7);
  ATL::CSimpleStringT<char_0>::CSimpleStringT<char_0>(&a3);
  ATL::CStringData::Release(a3 - 16);
  return a2;
}
// 10013E14: could not find valid save-restore pair for esi
// 100027AA: using guessed type int __thiscall ATL__CStringData__Release(_DWORD);
// 10002BCF: using guessed type _DWORD __stdcall ATL__CSimpleStringT_char_0___CSimpleStringT_char_0_(_DWORD);

//----- (10014038) --------------------------------------------------------
int __userpurge sub_10014038<eax>(int a1<ecx>, int a2<esi>, int a3, unsigned int a4, int a5, int a6)
{
  _UNKNOWN *v6; // eax@1
  int result; // eax@2
  int v8; // [sp+0h] [bp-10h]@1

  v8 = a1;
  v6 = sub_1000FB8F();
  (*(void (__thiscall **)(_UNKNOWN *, int))(*(_DWORD *)v6 + 12))(v6, v8);
  if ( sub_10002B30(a4) )
  {
    AfxFormatStrings(a3, a2, a5, a6);
    result = ATL::CStringData::Release(a2 - 16);
  }
  else
  {
    result = ATL::CStringData::Release(v8 - 16);
  }
  return result;
}
// 100027AA: using guessed type int __thiscall ATL__CStringData__Release(_DWORD);
// 10013F39: using guessed type _DWORD __stdcall AfxFormatStrings(_DWORD, _DWORD, _DWORD, _DWORD);

//----- (1001409F) --------------------------------------------------------
int __userpurge sub_1001409F<eax>(int a1<ecx>, int a2<esi>, int a3, unsigned int a4, char a5)
{
  return sub_10014038(a1, a2, a3, a4, (int)&a5, 1);
}

//----- (10014703) --------------------------------------------------------
char **__cdecl sub_10014703()
{
  return &off_10017524;
}
// 10017524: using guessed type char *off_10017524;

//----- (1001473D) --------------------------------------------------------
void *__thiscall sub_1001473D(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CWinApp::_CWinApp();
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}

//----- (10014869) --------------------------------------------------------
signed int __cdecl sub_10014869()
{
  return 1;
}

//----- (10014B2B) --------------------------------------------------------
char **__cdecl sub_10014B2B()
{
  return &off_10017864;
}
// 10017864: using guessed type char *off_10017864;

//----- (10014B65) --------------------------------------------------------
void *__thiscall sub_10014B65(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CWinThread::_CWinThread(this);
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 1001668A: using guessed type int __thiscall CWinThread___CWinThread(_DWORD);

//----- (10014CA6) --------------------------------------------------------
char **__cdecl sub_10014CA6()
{
  return &off_10017A14;
}
// 10017A14: using guessed type char *off_10017A14;

//----- (10014CAC) --------------------------------------------------------
char **__cdecl sub_10014CAC()
{
  return &off_10017AC8;
}
// 10017AC8: using guessed type char *off_10017AC8;

//----- (10014CB2) --------------------------------------------------------
char **__cdecl sub_10014CB2()
{
  return &off_10017A94;
}
// 10017A94: using guessed type char *off_10017A94;

//----- (10014CB8) --------------------------------------------------------
char **__cdecl sub_10014CB8()
{
  return &off_10017A60;
}
// 10017A60: using guessed type char *off_10017A60;

//----- (10014D15) --------------------------------------------------------
void __cdecl sub_10014D15()
{
  sub_10002D2C(&unk_1001E7D8);
}

//----- (10014D1F) --------------------------------------------------------
void __cdecl sub_10014D1F()
{
  sub_10002D33(&unk_1001E870);
}

//----- (10014D29) --------------------------------------------------------
void __cdecl sub_10014D29()
{
  sub_10002D3A(&unk_1001E908);
}

//----- (10014F52) --------------------------------------------------------
void __cdecl sub_10014F52()
{
  AfxUnlockGlobals(16);
  _CxxThrowException(0, 0);
}
// 10005408: using guessed type _DWORD __stdcall _CxxThrowException(_DWORD, _DWORD);

//----- (10014F9A) --------------------------------------------------------
void __cdecl sub_10014F9A()
{
  ++dword_1001E9A0;
}
// 1001E9A0: using guessed type int dword_1001E9A0;

//----- (10014FF2) --------------------------------------------------------
void *__thiscall sub_10014FF2(void *this)
{
  void *result; // eax@1

  result = this;
  *(_DWORD *)this = &off_10017B6C;
  return result;
}
// 10017B6C: using guessed type int (__thiscall *off_10017B6C)(void *, char);

//----- (100151A7) --------------------------------------------------------
void *__thiscall sub_100151A7(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  nullsub_1();
  if ( a2 & 1 )
    CNoTrackObject::operator delete(v2);
  return v2;
}
// 100151C2: using guessed type int nullsub_1(void);

//----- (100157CD) --------------------------------------------------------
int __cdecl sub_100157CD()
{
  return atexit(sub_100157E5);
}

//----- (100157D9) --------------------------------------------------------
int __cdecl sub_100157D9()
{
  return atexit(sub_100157EF);
}

//----- (100157E5) --------------------------------------------------------
int __cdecl sub_100157E5()
{
  return CThreadLocalObject::_CThreadLocalObject(&unk_1001EBDC);
}
// 100154BE: using guessed type int __thiscall CThreadLocalObject___CThreadLocalObject(_DWORD);

//----- (100157EF) --------------------------------------------------------
int __cdecl sub_100157EF()
{
  return CProcessLocalObject::_CProcessLocalObject(&unk_1001EBE0);
}
// 100154C3: using guessed type int __thiscall CProcessLocalObject___CProcessLocalObject(_DWORD);

//----- (10015976) --------------------------------------------------------
signed int __stdcall sub_10015976(int a1, int a2, int a3, int a4)
{
  UINT v4; // eax@1
  int v5; // eax@1
  int v6; // eax@1
  int v7; // ecx@1
  HMODULE v8; // eax@5

  v4 = SetErrorMode(0);
  SetErrorMode(v4 | 0x8001);
  v5 = AfxGetModuleState(v7);
  *(_DWORD *)(v5 + 8) = a1;
  *(_DWORD *)(v5 + 12) = a1;
  v6 = *(_DWORD *)(AfxGetModuleState(v7) + 4);
  if ( v6 )
  {
    *(_DWORD *)(v6 + 68) = a3;
    *(_DWORD *)(v6 + 72) = a4;
    *(_DWORD *)(v6 + 64) = a1;
    CWinApp::SetCurrentHandles(v6);
  }
  if ( !*(_BYTE *)(AfxGetModuleState(v7) + 20) )
    AfxInitThread();
  v8 = GetModuleHandleA("user32.dll");
  if ( v8 )
    dword_100205B4 = (int)GetProcAddress(v8, "NotifyWinEvent");
  return 1;
}
// 10015790: using guessed type int __thiscall AfxGetModuleState(_DWORD);
// 10015828: using guessed type int __thiscall CWinApp__SetCurrentHandles(_DWORD);
// 100205B4: using guessed type int dword_100205B4;

//----- (10015ACA) --------------------------------------------------------
char **__cdecl sub_10015ACA()
{
  return &off_10017C50;
}
// 10017C50: using guessed type char *off_10017C50;

//----- (10015AD0) --------------------------------------------------------
char **__cdecl sub_10015AD0()
{
  return &off_10017C24;
}
// 10017C24: using guessed type char *off_10017C24;

//----- (10015AD6) --------------------------------------------------------
void **__cdecl sub_10015AD6()
{
  return &off_10017C04;
}
// 10017C04: using guessed type void *off_10017C04;

//----- (10015ADC) --------------------------------------------------------
char **__cdecl sub_10015ADC()
{
  return &off_10017BDC;
}
// 10017BDC: using guessed type char *off_10017BDC;

//----- (10015B03) --------------------------------------------------------
int __cdecl sub_10015B03()
{
  int result; // eax@1

  result = operator new(8u);
  if ( result )
  {
    *(_DWORD *)result = &off_10017CB4;
    *(_DWORD *)(result + 4) = 0;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 10017CB4: using guessed type int (*off_10017CB4)();

//----- (10015B39) --------------------------------------------------------
int __stdcall sub_10015B39(int a1)
{
  int result; // eax@1

  result = a1;
  if ( a1 )
  {
    *(_DWORD *)(a1 + 4) = 0;
    *(_DWORD *)a1 = &off_10017CB4;
  }
  return result;
}
// 10017CB4: using guessed type int (*off_10017CB4)();

//----- (10015B88) --------------------------------------------------------
void __cdecl sub_10015B88()
{
  sub_10002EB2(&unk_1001EBE8);
}

//----- (10015B92) --------------------------------------------------------
void __cdecl sub_10015B92()
{
  sub_10002EDB(&unk_1001EC80);
}

//----- (10015BF1) --------------------------------------------------------
int __cdecl sub_10015BF1()
{
  AUX_DATA::AUX_DATA(&dword_1001ED30);
  return atexit(loc_10015C07);
}
// 10015B9C: using guessed type int __thiscall AUX_DATA__AUX_DATA(_DWORD);
// 1001ED30: using guessed type int dword_1001ED30;

//----- (10015C12) --------------------------------------------------------
char **__cdecl sub_10015C12()
{
  return &off_10017DDC;
}
// 10017DDC: using guessed type char *off_10017DDC;

//----- (100161E2) --------------------------------------------------------
int __cdecl sub_100161E2()
{
  int result; // eax@1

  result = unknown_libname_44(0xCu);
  if ( result )
    *(_DWORD *)result = &off_10018580;
  else
    result = 0;
  return result;
}
// 10018580: using guessed type int (__thiscall *off_10018580)(void *, char);

//----- (10016224) --------------------------------------------------------
void *__thiscall sub_10016224(void *this, char a2)
{
  void *v2; // esi@1

  v2 = this;
  CMFCComObject<ATL::CAccessibleProxy>::_CMFCComObject<ATL::CAccessibleProxy>();
  if ( a2 & 1 )
    j__free(v2);
  return v2;
}
// 10016240: using guessed type int CMFCComObject_ATL__CAccessibleProxy____CMFCComObject_ATL__CAccessibleProxy_(void);

//----- (100162B3) --------------------------------------------------------
int __stdcall sub_100162B3(int a1)
{
  return CMFCComObject<ATL::CAccessibleProxy>::AddRef(a1 - 4);
}
// 10016265: using guessed type _DWORD __stdcall CMFCComObject_ATL__CAccessibleProxy___AddRef(_DWORD);

//----- (100162BD) --------------------------------------------------------
int __stdcall sub_100162BD(int a1)
{
  return CMFCComObject<ATL::CAccessibleProxy>::Release(a1 - 4);
}
// 10016272: using guessed type _DWORD __stdcall CMFCComObject_ATL__CAccessibleProxy___Release(_DWORD);

//----- (100162D1) --------------------------------------------------------
int __stdcall sub_100162D1(int a1)
{
  return CMFCComObject<ATL::CAccessibleProxy>::AddRef(a1 - 16);
}
// 10016265: using guessed type _DWORD __stdcall CMFCComObject_ATL__CAccessibleProxy___AddRef(_DWORD);

//----- (100162DB) --------------------------------------------------------
int __stdcall sub_100162DB(int a1)
{
  return CMFCComObject<ATL::CAccessibleProxy>::Release(a1 - 16);
}
// 10016272: using guessed type _DWORD __stdcall CMFCComObject_ATL__CAccessibleProxy___Release(_DWORD);

//----- (1001636B) --------------------------------------------------------
char **__cdecl sub_1001636B()
{
  return &off_10018724;
}
// 10018724: using guessed type char *off_10018724;

//----- (10016371) --------------------------------------------------------
char **__cdecl sub_10016371()
{
  return &off_10018760;
}
// 10018760: using guessed type char *off_10018760;

//----- (10016377) --------------------------------------------------------
int __cdecl sub_10016377()
{
  int result; // eax@1

  result = operator new(8u);
  if ( result )
  {
    *(_DWORD *)result = &off_10018788;
    *(_DWORD *)(result + 4) = 0;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 10018788: using guessed type int (*off_10018788)();

//----- (10016391) --------------------------------------------------------
int __stdcall sub_10016391(int a1)
{
  int result; // eax@1

  result = a1;
  if ( a1 )
  {
    *(_DWORD *)(a1 + 4) = 0;
    *(_DWORD *)a1 = &off_10018788;
  }
  return result;
}
// 10018788: using guessed type int (*off_10018788)();

//----- (100163A6) --------------------------------------------------------
char **__cdecl sub_100163A6()
{
  return &off_1001879C;
}
// 1001879C: using guessed type char *off_1001879C;

//----- (100163DF) --------------------------------------------------------
int __cdecl sub_100163DF()
{
  int result; // eax@1

  result = _AfxInitDBCS();
  dword_1002070C = result;
  return result;
}
// 1002070C: using guessed type int dword_1002070C;

//----- (100163EA) --------------------------------------------------------
char **__cdecl sub_100163EA()
{
  return &off_1001D838;
}
// 1001D838: using guessed type char *off_1001D838;

//----- (100163F0) --------------------------------------------------------
int __cdecl sub_100163F0()
{
  int result; // eax@1

  result = operator new(0x14u);
  if ( result )
  {
    *(_DWORD *)result = &off_100187F4;
    *(_DWORD *)(result + 4) = 0;
    *(_DWORD *)(result + 16) = 0;
    *(_DWORD *)(result + 12) = 0;
    *(_DWORD *)(result + 8) = 0;
  }
  else
  {
    result = 0;
  }
  return result;
}
// 100187F4: using guessed type int (*off_100187F4)();

//----- (10016406) --------------------------------------------------------
void __cdecl sub_10016406()
{
  AfxClassInit((struct CRuntimeClass *)&off_1001D838);
}
// 1001D838: using guessed type char *off_1001D838;

//----- (10016790) --------------------------------------------------------
void __usercall sub_10016790(int a1<ebp>)
{
  CNoTrackObject::operator delete(*(void **)(a1 - 16));
}

//----- (10016799) --------------------------------------------------------
int __cdecl sub_10016799(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100167A3) --------------------------------------------------------
int __usercall sub_100167A3<eax>(int a1<ebp>)
{
  return CWinThread::_CWinThread(*(_DWORD *)(a1 - 16));
}
// 1001668A: using guessed type int __thiscall CWinThread___CWinThread(_DWORD);

//----- (100167AB) --------------------------------------------------------
int __cdecl sub_100167AB(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100167B5) --------------------------------------------------------
int __usercall sub_100167B5<eax>(int a1<ebp>)
{
  return ATL::CStringData::Release(*(_DWORD *)(a1 - 16) - 16);
}
// 100027AA: using guessed type int __thiscall ATL__CStringData__Release(_DWORD);

//----- (100167BD) --------------------------------------------------------
int __cdecl sub_100167BD(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100167C7) --------------------------------------------------------
void __cdecl sub_100167C7()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (100167CF) --------------------------------------------------------
int __cdecl sub_100167CF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100167D9) --------------------------------------------------------
void __cdecl sub_100167D9()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (100167E1) --------------------------------------------------------
int __cdecl sub_100167E1(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100167EB) --------------------------------------------------------
void __cdecl sub_100167EB()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (100167F6) --------------------------------------------------------
int __cdecl sub_100167F6(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016800) --------------------------------------------------------
void __cdecl sub_10016800()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (1001680B) --------------------------------------------------------
void __cdecl sub_1001680B()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (10016816) --------------------------------------------------------
void __cdecl sub_10016816()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (10016835) --------------------------------------------------------
int __usercall sub_10016835<eax>(int a1<ebp>)
{
  return CCmdTarget::_CCmdTarget(*(_DWORD *)(a1 - 16));
}
// 1000F342: using guessed type int __thiscall CCmdTarget___CCmdTarget(_DWORD);

//----- (1001683D) --------------------------------------------------------
int __cdecl sub_1001683D(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016847) --------------------------------------------------------
void __usercall sub_10016847(int a1<ebp>)
{
  CNoTrackObject::operator delete(*(void **)(a1 - 16));
}

//----- (10016850) --------------------------------------------------------
int __cdecl sub_10016850(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (1001685A) --------------------------------------------------------
void __usercall sub_1001685A(int a1<ebp>)
{
  sub_10002520(*(void **)(a1 - 16));
}

//----- (10016863) --------------------------------------------------------
int __cdecl sub_10016863(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016877) --------------------------------------------------------
int __usercall sub_10016877<eax>(int a1<ebp>)
{
  return nullsub_2(*(_DWORD *)(a1 - 16), &unk_1001E9A8);
}
// 10005ECA: using guessed type int __cdecl nullsub_2(_DWORD, _DWORD);

//----- (10016891) --------------------------------------------------------
int __usercall sub_10016891<eax>(int a1<ebp>)
{
  return CThreadLocalObject::_CThreadLocalObject(*(_DWORD *)(a1 - 16) + 4208);
}
// 100154BE: using guessed type int __thiscall CThreadLocalObject___CThreadLocalObject(_DWORD);

//----- (100168B3) --------------------------------------------------------
int __usercall sub_100168B3<eax>(int a1<ebp>)
{
  return CFixedAllocNoSync::FreeAll(*(_DWORD *)(a1 - 16) + 4);
}
// 10003B27: using guessed type int __thiscall CFixedAllocNoSync__FreeAll(_DWORD);

//----- (100168BE) --------------------------------------------------------
int __usercall sub_100168BE<eax>(int a1<ebp>)
{
  return sub_1000E9D0((void *)(*(_DWORD *)(a1 - 16) + 28));
}

//----- (100168C9) --------------------------------------------------------
int __usercall sub_100168C9<eax>(int a1<ebp>)
{
  return sub_1000E9D0((void *)(*(_DWORD *)(a1 - 16) + 56));
}

//----- (100168FC) --------------------------------------------------------
void __usercall sub_100168FC(int a1<ebp>)
{
  sub_10002520(*(void **)(a1 - 16));
}

//----- (10016905) --------------------------------------------------------
int __cdecl sub_10016905(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (1001690F) --------------------------------------------------------
int __usercall sub_1001690F<eax>(int a1<ebp>)
{
  return CObject::operator delete(*(void **)(a1 - 16), *(_DWORD *)(a1 + 8));
}

//----- (10016925) --------------------------------------------------------
void __usercall sub_10016925(int a1<ebp>)
{
  j__free(*(void **)(a1 + 8));
}

//----- (10016939) --------------------------------------------------------
int __cdecl sub_10016939(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016943) --------------------------------------------------------
int __usercall sub_10016943<eax>(int a1<ebp>)
{
  return CCmdTarget::_CCmdTarget(*(_DWORD *)(a1 - 16));
}
// 1000F342: using guessed type int __thiscall CCmdTarget___CCmdTarget(_DWORD);

//----- (1001694B) --------------------------------------------------------
int __cdecl sub_1001694B(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016955) --------------------------------------------------------
int __usercall sub_10016955<eax>(int a1<ebp>)
{
  return CWnd::_CWnd(a1 - 92);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (1001695D) --------------------------------------------------------
int __cdecl sub_1001695D(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016967) --------------------------------------------------------
void __usercall sub_10016967(int a1<ebp>)
{
  j__free(*(void **)(a1 - 28));
}

//----- (10016985) --------------------------------------------------------
int __usercall sub_10016985<eax>(int a1<ebp>)
{
  return CDC::_CDC(a1 - 36);
}
// 10013421: using guessed type int __thiscall CDC___CDC(_DWORD);

//----- (1001698D) --------------------------------------------------------
int __usercall sub_1001698D<eax>(int a1<ebp>)
{
  return CWnd::_CWnd(a1 - 116);
}
// 1001173D: using guessed type int __thiscall CWnd___CWnd(_DWORD);

//----- (10016995) --------------------------------------------------------
int __usercall sub_10016995<eax>(int a1<ebp>)
{
  return CDC::_CDC(a1 - 36);
}
// 10013421: using guessed type int __thiscall CDC___CDC(_DWORD);

//----- (100169A7) --------------------------------------------------------
int __usercall sub_100169A7<eax>(int a1<ebp>)
{
  int result; // eax@1

  result = *(_DWORD *)(a1 + 12);
  if ( result )
    result = (*(int (__stdcall **)(int))(*(_DWORD *)result + 8))(result);
  return result;
}

//----- (100169AF) --------------------------------------------------------
int __cdecl sub_100169AF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100169B9) --------------------------------------------------------
int __usercall sub_100169B9<eax>(int a1<ebp>)
{
  int v1; // eax@1

  v1 = AfxGetModuleState(a1 - 16);
  return CCmdTarget::EndWaitCursor(*(_DWORD *)(v1 + 4));
}
// 1000F615: using guessed type int __thiscall CCmdTarget__EndWaitCursor(_DWORD);
// 10015790: using guessed type int __thiscall AfxGetModuleState(_DWORD);

//----- (100169C1) --------------------------------------------------------
int __cdecl sub_100169C1(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100169CB) --------------------------------------------------------
void __usercall sub_100169CB(int a1<ebp>)
{
  j__free(*(void **)(a1 + 8));
}

//----- (100169DF) --------------------------------------------------------
void __cdecl sub_100169DF()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (100169E7) --------------------------------------------------------
void __cdecl sub_100169E7()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (100169EF) --------------------------------------------------------
int __cdecl sub_100169EF(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (100169F9) --------------------------------------------------------
void __cdecl sub_100169F9()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (10016A04) --------------------------------------------------------
int __cdecl sub_10016A04(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016A0E) --------------------------------------------------------
void __usercall sub_10016A0E(int a1<ebp>)
{
  sub_10002520(*(void **)(a1 - 20));
}

//----- (10016A17) --------------------------------------------------------
int __cdecl sub_10016A17(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016A21) --------------------------------------------------------
void __cdecl sub_10016A21()
{
  JUMPOUT(loc_1000294C);
}
// 1000294C: using guessed type int loc_1000294C();

//----- (10016A29) --------------------------------------------------------
int __cdecl sub_10016A29(struct EHExceptionRecord *a1, struct EHRegistrationNode *a2, struct _CONTEXT *a3, void *a4)
{
  return __CxxFrameHandler(a1, a2, a3, a4);
}

//----- (10016A40) --------------------------------------------------------
int __cdecl sub_10016A40()
{
  sub_10001010(&unk_1001E720);
  return atexit(sub_10016A90);
}

//----- (10016A5C) --------------------------------------------------------
int __cdecl sub_10016A5C()
{
  int result; // eax@1

  sub_10014F9A();
  result = atexit(sub_100026CE);
  byte_1001E7CC = result;
  return result;
}
// 1001E7CC: using guessed type char byte_1001E7CC;

//----- (10016A72) --------------------------------------------------------
int __cdecl sub_10016A72()
{
  sub_1000E1A1((int)&unk_10020C18);
  return atexit(sub_10016A9F);
}

//----- (10016A90) --------------------------------------------------------
int __cdecl sub_10016A90()
{
  return sub_100024C0();
}

//----- (10016A9F) --------------------------------------------------------
void __cdecl sub_10016A9F()
{
  DeleteCriticalSection((LPCRITICAL_SECTION)&unk_10020C18 + 1);
  if ( *((_DWORD *)&unk_10020C18 + 12) )
  {
    free(*((void **)&unk_10020C18 + 12));
    *((_DWORD *)&unk_10020C18 + 12) = 0;
  }
  *((_DWORD *)&unk_10020C18 + 13) = 0;
  *((_DWORD *)&unk_10020C18 + 14) = 0;
}
// 10016A9F: could not find valid save-restore pair for esi

// ALL OK, 279 function(s) have been successfully decompiled
