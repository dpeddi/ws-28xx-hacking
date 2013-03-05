
WNDCLASSA struc	; (sizeof=0x28,	standard type)
style dd ?
lpfnWndProc dd ?	; offset
cbClsExtra dd ?
cbWndExtra dd ?
hInstance dd ?		; offset
hIcon dd ?		; offset
hCursor	dd ?		; offset
hbrBackground dd ?	; offset
lpszMenuName dd	?	; offset
lpszClassName dd ?	; offset
WNDCLASSA ends


tagINITCOMMONCONTROLSEX	struc ;	(sizeof=0x8, standard type)
dwSize dd ?
dwICC dd ?
tagINITCOMMONCONTROLSEX	ends


tagSIZE	struc ;	(sizeof=0x8, standard type)
_cx dd ?
cy dd ?
tagSIZE	ends


MSG struc ; (sizeof=0x1C, standard type)
hwnd dd	?		; offset
message	dd ?
wParam dd ?
lParam dd ?
time dd	?
pt POINT ?
MSG ends


IID struc ; (sizeof=0x10, standard type)
Data1 dd ?
Data2 dw ?
Data3 dw ?
Data4 db 8 dup(?)
IID ends


tagDEC::$5450C884C987D55E7B3D2E94E15D6587::$674876891A86A76F12C10005982BCA56 struc ; (sizeof=0x8, standard type)
Lo32 dd	?
Mid32 dd ?
tagDEC::$5450C884C987D55E7B3D2E94E15D6587::$674876891A86A76F12C10005982BCA56 ends


tagDEC::$5450C884C987D55E7B3D2E94E15D6587 union	; (sizeof=0x8, standard	type)
anonymous_0 tagDEC::$5450C884C987D55E7B3D2E94E15D6587::$674876891A86A76F12C10005982BCA56 ?
Lo64 dq	?
tagDEC::$5450C884C987D55E7B3D2E94E15D6587 ends


tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26::$7F8459940C2B08BD5D82B0F27239141B struc ; (sizeof=0x2, standard type)
scale db ?
sign db	?
tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26::$7F8459940C2B08BD5D82B0F27239141B ends


tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26 union	; (sizeof=0x2, standard	type)
anonymous_0 tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26::$7F8459940C2B08BD5D82B0F27239141B ?
signscale dw ?
tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26 ends


DECIMAL	struc ;	(sizeof=0x10, standard type)
wReserved dw ?
anonymous_0 tagDEC::$00EA3C93EAB4EAE0D94D1E8C5BA4BC26 ?
Hi32 dd	?
anonymous_1 tagDEC::$5450C884C987D55E7B3D2E94E15D6587 ?
DECIMAL	ends


tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387::$0FDBD249F1AECD6A49409B6B82281578 struc ; (sizeof=0x8, standard type)
pvRecord dd ?		; offset
pRecInfo dd ?		; offset
tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387::$0FDBD249F1AECD6A49409B6B82281578 ends


tagCY::$4ADA6AE34E722E24764E0C4FBCDA3E73 struc ; (sizeof=0x8, standard type)
Lo dd ?
Hi dd ?
tagCY::$4ADA6AE34E722E24764E0C4FBCDA3E73 ends


CY union ; (sizeof=0x8,	standard type)
anonymous_0 tagCY::$4ADA6AE34E722E24764E0C4FBCDA3E73 ?
int64 dq ?
CY ends


tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387 union ; (sizeof=0x8, standard type)
lVal dd	?
bVal db	?
iVal dw	?
fltVal dd ?
dblVal dq ?
boolVal	dw ?
scode dd ?
cyVal CY ?
date dq	?
bstrVal	dd ?		; offset
punkVal	dd ?		; offset
pdispVal dd ?		; offset
parray dd ?		; offset
pbVal dd ?		; offset
piVal dd ?		; offset
plVal dd ?		; offset
pfltVal	dd ?		; offset
pdblVal	dd ?		; offset
pboolVal dd ?		; offset
pscode dd ?		; offset
pcyVal dd ?		; offset
pdate dd ?		; offset
pbstrVal dd ?		; offset
ppunkVal dd ?		; offset
ppdispVal dd ?		; offset
pparray	dd ?		; offset
pvarVal	dd ?		; offset
byref dd ?		; offset
cVal db	?
uiVal dw ?
ulVal dd ?
intVal dd ?
uintVal	dd ?
pdecVal	dd ?		; offset
pcVal dd ?		; offset
puiVal dd ?		; offset
pulVal dd ?		; offset
pintVal	dd ?		; offset
puintVal dd ?		; offset
anonymous_0 tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387::$0FDBD249F1AECD6A49409B6B82281578 ?
tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387 ends


tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2 struc ; (sizeof=0x10, standard	type)
vt dw ?
wReserved1 dw ?
wReserved2 dw ?
wReserved3 dw ?
anonymous_0 tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2::$1752C812EA74BB4956541A744E2B2387	?
tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2 ends


tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5 union ; (sizeof=0x10, standard type)
anonymous_0 tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5::$8749951CD3A823784AB28831F11D98F2 ?
decVal DECIMAL ?
tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5 ends


VARIANTARG struc ; (sizeof=0x10, standard type)
anonymous_0 tagVARIANT::$6474CD83C6657A6DABDF207000DC5FE5 ?
VARIANTARG ends


tagMONITORINFO struc ; (sizeof=0x28, standard type)
cbSize dd ?
rcMonitor RECT ?
rcWork RECT ?
dwFlags	dd ?
tagMONITORINFO ends


FILE struc ; (sizeof=0x20, standard type)
_ptr dd	?		; offset
_cnt dd	?
_base dd ?		; offset
_flag dd ?
_file dd ?
_charbuf dd ?
_bufsiz	dd ?
_tmpfname dd ?		; offset
FILE ends


_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E struc	; (sizeof=0x8, standard	type)
LowPart	dd ?
HighPart dd ?
_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ends


LARGE_INTEGER union ; (sizeof=0x8, standard type)
anonymous_0 _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
u _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
QuadPart dq ?
LARGE_INTEGER ends


_FILETIME struc	; (sizeof=0x8, standard	type)
dwLowDateTime dd ?
dwHighDateTime dd ?
_FILETIME ends


tagWNDCLASSA struc ; (sizeof=0x28, standard type)
style dd ?
lpfnWndProc dd ?	; offset
cbClsExtra dd ?
cbWndExtra dd ?
hInstance dd ?		; offset
hIcon dd ?		; offset
hCursor	dd ?		; offset
hbrBackground dd ?	; offset
lpszMenuName dd	?	; offset
lpszClassName dd ?	; offset
tagWNDCLASSA ends


_RTL_CRITICAL_SECTION struc ; (sizeof=0x18, standard type)
DebugInfo dd ?		; offset
LockCount dd ?
RecursionCount dd ?
OwningThread dd	?	; offset
LockSemaphore dd ?	; offset
SpinCount dd ?
_RTL_CRITICAL_SECTION ends


tagPOINT struc ; (sizeof=0x8, standard type)
x dd ?
y dd ?
tagPOINT ends


tagWNDCLASSEXA struc ; (sizeof=0x30, standard type)
cbSize dd ?
style dd ?
lpfnWndProc dd ?	; offset
cbClsExtra dd ?
cbWndExtra dd ?
hInstance dd ?		; offset
hIcon dd ?		; offset
hCursor	dd ?		; offset
hbrBackground dd ?	; offset
lpszMenuName dd	?	; offset
lpszClassName dd ?	; offset
hIconSm	dd ?		; offset
tagWNDCLASSEXA ends


tagRECT	struc ;	(sizeof=0x10, standard type)
left dd	?
top dd ?
right dd ?
bottom dd ?
tagRECT	ends


_STARTUPINFOA struc ; (sizeof=0x44, standard type)
cb dd ?
lpReserved dd ?		; offset
lpDesktop dd ?		; offset
lpTitle	dd ?		; offset
dwX dd ?
dwY dd ?
dwXSize	dd ?
dwYSize	dd ?
dwXCountChars dd ?
dwYCountChars dd ?
dwFillAttribute	dd ?
dwFlags	dd ?
wShowWindow dw ?
cbReserved2 dw ?
lpReserved2 dd ?	; offset
hStdInput dd ?		; offset
hStdOutput dd ?		; offset
hStdError dd ?		; offset
_STARTUPINFOA ends


_cpinfo	struc ;	(sizeof=0x14, standard type)
MaxCharSize dd ?
DefaultChar db 2 dup(?)
LeadByte db 12 dup(?)
_padding db 2 dup(?)
_cpinfo	ends


_SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937::$AA04DEB0C6383F89F13D312A174572A9 struc ; (sizeof=0x4,	standard type)
wProcessorArchitecture dw ?
wReserved dw ?
_SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937::$AA04DEB0C6383F89F13D312A174572A9 ends


_SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937	union ;	(sizeof=0x4, standard type)
dwOemId	dd ?
anonymous_0 _SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937::$AA04DEB0C6383F89F13D312A174572A9 ?
_SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937	ends


_SYSTEM_INFO struc ; (sizeof=0x24, standard type)
anonymous_0 _SYSTEM_INFO::$1593C2ABA4C275C0FBEC2498FA3B0937 ?
dwPageSize dd ?
lpMinimumApplicationAddress dd ? ; offset
lpMaximumApplicationAddress dd ? ; offset
dwActiveProcessorMask dd ?
dwNumberOfProcessors dd	?
dwProcessorType	dd ?
dwAllocationGranularity	dd ?
wProcessorLevel	dw ?
wProcessorRevision dw ?
_SYSTEM_INFO ends


_MEMORY_BASIC_INFORMATION struc	; (sizeof=0x1C,	standard type)
BaseAddress dd ?	; offset
AllocationBase dd ?	; offset
AllocationProtect dd ?
RegionSize dd ?
State dd ?
Protect	dd ?
Type dd	?
_MEMORY_BASIC_INFORMATION ends


RECT struc ; (sizeof=0x10, standard type)
left dd	?
top dd ?
right dd ?
bottom dd ?
RECT ends


POINT struc ; (sizeof=0x8, standard type)
x dd ?
y dd ?
POINT ends


WINDOWPLACEMENT	struc ;	(sizeof=0x2C, standard type)
length dd ?
flags dd ?
showCmd	dd ?
ptMinPosition POINT ?
ptMaxPosition POINT ?
rcNormalPosition RECT ?
WINDOWPLACEMENT	ends


_OSVERSIONINFOA	struc ;	(sizeof=0x94, standard type)
dwOSVersionInfoSize dd ?
dwMajorVersion dd ?
dwMinorVersion dd ?
dwBuildNumber dd ?
dwPlatformId dd	?
szCSDVersion db	128 dup(?)
_OSVERSIONINFOA	ends


GUID struc ; (sizeof=0x10, standard type)
Data1 dd ?
Data2 dw ?
Data3 dw ?
Data4 db 8 dup(?)
GUID ends


_SP_DEVICE_INTERFACE_DATA struc	; (sizeof=0x1C,	standard type)
cbSize dd ?
InterfaceClassGuid GUID	?
Flags dd ?
Reserved dd ?
_SP_DEVICE_INTERFACE_DATA ends


CPPEH_RECORD struc ; (sizeof=0x18, standard type)
old_esp	dd ?
exc_ptr	dd ?		; offset
prev_er	dd ?		; offset
handler	dd ?		; offset
msEH_ptr dd ?		; offset
disabled dd ?
CPPEH_RECORD ends


_SCOPETABLE_ENTRY struc	; (sizeof=0xC)
EnclosingLevel dd ?
FilterFunc dd ?		; offset
HandlerFunc dd ?	; offset
_SCOPETABLE_ENTRY ends


_msExcept7 struc ; (sizeof=0x1C)
Magic dd ?		; base 16
Count dd ?		; base 10
InfoPtr	dd ?		; offset
CountDtr dd ?		; base 10
DtrPtr dd ?		; offset
_unk dd	2 dup(?)
_msExcept7 ends


_msExcInfo struc ; (sizeof=0x8)
Id dd ?			; base 10
Proc dd	?		; offset
_msExcInfo ends


_ms_type_info struc ; (sizeof=0x8, variable size)
getInfoPtr dq ?		; offset
Name db	0 dup(?)	; string(C)
_ms_type_info ends


_msExcExt struc	; (sizeof=0x14)
_unk dd	3 dup(?)
Count dd ?		; base 10
RttiBlkPtr dd ?		; offset
_msExcExt ends


_msRttiDscr struc ; (sizeof=0x10)
_unk dd	?		; base 16
RttiPtr	dd ?		; offset
spoff dd ?		; base 10
Dtr dd ?		; offset
_msRttiDscr ends


;
; +-------------------------------------------------------------------------+
; |   This file	has been generated by The Interactive Disassembler (IDA)    |
; |	      Copyright	(c) 2011 Hex-Rays, <support@hex-rays.com>	    |
; |			 License info: 48-327F-7274-B7			    |
; |			       ESET spol. s r.o.			    |
; +-------------------------------------------------------------------------+
;
; Input	MD5   :	D2766BA0D32A720CB3F0FDB170368D66
; Input	CRC32 :	60E9C7ED


include	uni.inc	; see unicode subdir of	ida for	info on	unicode

.686p
.mmx
.model flat


; [00001000 BYTES: COLLAPSED SEGMENT HEADER. PRESS KEYPAD "+" TO EXPAND]
; File Name   :	C:\Programmi\HeavyWeatherWV5\sHID.dll
; Format      :	Portable executable for	80386 (PE)
; Imagebase   :	10000000
; Section 1. (virtual address 00001000)
; Virtual size			: 00015AA9 (  88745.)
; Section size in file		: 00016000 (  90112.)
; Offset to raw	data for section: 00001000
; Flags	60000020: Text Executable Readable
; Alignment	: default

; Segment type:	Pure code
; Segment permissions: Read/Execute
_text segment para public 'CODE' use32
assume cs:_text
;org 10001000h
assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing


; Attributes: bp-based frame

sub_10001000 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	eax, offset off_10017420
mov	esp, ebp
pop	ebp
retn
sub_10001000 endp



; Attributes: bp-based frame

sub_10001010 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
push	0		; char *
mov	ecx, [ebp+var_4]
call	??0CWinApp@@QAE@PBD@Z ;	CWinApp::CWinApp(char const *)
mov	eax, [ebp+var_4]
mov	dword ptr [eax], offset	off_10017440
mov	eax, [ebp+var_4]
mov	esp, ebp
pop	ebp
retn
sub_10001010 endp

align 10h


; Attributes: bp-based frame

sub_10001040 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	ecx, [ebp+var_4]
call	?InitInstance@CWinApp@@UAEHXZ ;	CWinApp::InitInstance(void)
mov	esp, ebp
pop	ebp
retn
sub_10001040 endp

align 10h


; Attributes: bp-based frame

sub_10001060 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	eax, [ebp+var_4]
mov	dword ptr [eax+50h], 0FFFFFFFFh
mov	ecx, [ebp+var_4]
mov	dword ptr [ecx+54h], 0FFFFFFFFh
mov	edx, [ebp+var_4]
mov	dword ptr [edx+58h], 0
mov	eax, [ebp+var_4]
push	eax
call	HidD_GetHidGuid
mov	eax, [ebp+var_4]
mov	esp, ebp
pop	ebp
retn
sub_10001060 endp

align 10h


; Attributes: bp-based frame

sub_100010A0 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	ecx, [ebp+var_4]
call	sub_100010C0
mov	esp, ebp
pop	ebp
retn
sub_100010A0 endp

align 10h


; Attributes: bp-based frame

sub_100010C0 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	eax, [ebp+var_4]
cmp	dword ptr [eax+50h], 0FFFFFFFFh
jz	short loc_100010DD
mov	ecx, [ebp+var_4]
mov	edx, [ecx+50h]
push	edx		; hObject
call	ds:CloseHandle

loc_100010DD:
mov	eax, [ebp+var_4]
mov	dword ptr [eax+50h], 0FFFFFFFFh
mov	ecx, [ebp+var_4]
cmp	dword ptr [ecx+54h], 0FFFFFFFFh
jz	short loc_100010FD
mov	edx, [ebp+var_4]
mov	eax, [edx+54h]
push	eax		; hObject
call	ds:CloseHandle

loc_100010FD:
mov	ecx, [ebp+var_4]
mov	dword ptr [ecx+54h], 0FFFFFFFFh
mov	edx, [ebp+var_4]
cmp	dword ptr [edx+58h], 0
jz	short loc_1000111D
mov	eax, [ebp+var_4]
mov	ecx, [eax+58h]
push	ecx		; hObject
call	ds:CloseHandle

loc_1000111D:
mov	edx, [ebp+var_4]
mov	dword ptr [edx+58h], 0
mov	esp, ebp
pop	ebp
retn
sub_100010C0 endp

align 10h


; Attributes: bp-based frame

sub_10001130 proc near

InterfaceClassGuid= dword ptr -4Ch
var_48=	dword ptr -48h
var_41=	byte ptr -41h
DeviceInterfaceData= _SP_DEVICE_INTERFACE_DATA ptr -40h
var_24=	dword ptr -24h
var_20=	dword ptr -20h
var_1C=	word ptr -1Ch
var_1A=	word ptr -1Ah
RequiredSize= dword ptr	-14h
DeviceInterfaceDetailDataSize= dword ptr -10h
MemberIndex= dword ptr -0Ch
DeviceInterfaceDetailData= dword ptr -8
DeviceInfoSet= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 4Ch
mov	eax, dword_1001D870
mov	[ebp+var_24], eax
mov	[ebp+InterfaceClassGuid], ecx
mov	ecx, [ebp+InterfaceClassGuid]
call	sub_100010C0
push	12h		; Flags
push	0		; hwndParent
push	0		; Enumerator
mov	eax, [ebp+InterfaceClassGuid]
push	eax		; ClassGuid
call	ds:SetupDiGetClassDevsA
mov	[ebp+DeviceInfoSet], eax
mov	[ebp+MemberIndex], 0
jmp	short loc_1000116E

loc_10001165:
mov	ecx, [ebp+MemberIndex]
add	ecx, 1
mov	[ebp+MemberIndex], ecx

loc_1000116E:
mov	[ebp+DeviceInterfaceData.cbSize], 1Ch
lea	edx, [ebp+DeviceInterfaceData]
push	edx		; DeviceInterfaceData
mov	eax, [ebp+MemberIndex]
push	eax		; MemberIndex
mov	ecx, [ebp+InterfaceClassGuid]
push	ecx		; InterfaceClassGuid
push	0		; DeviceInfoData
mov	edx, [ebp+DeviceInfoSet]
push	edx		; DeviceInfoSet
call	ds:SetupDiEnumDeviceInterfaces
test	eax, eax
jnz	short loc_100011A5
call	ds:GetLastError
cmp	eax, 103h
jnz	short loc_100011A3
jmp	loc_1000142E

loc_100011A3:
jmp	short loc_10001165

loc_100011A5:
mov	[ebp+DeviceInterfaceDetailDataSize], 0
push	0		; DeviceInfoData
lea	eax, [ebp+DeviceInterfaceDetailDataSize]
push	eax		; RequiredSize
push	0		; DeviceInterfaceDetailDataSize
push	0		; DeviceInterfaceDetailData
lea	ecx, [ebp+DeviceInterfaceData]
push	ecx		; DeviceInterfaceData
mov	edx, [ebp+DeviceInfoSet]
push	edx		; DeviceInfoSet
call	ds:SetupDiGetDeviceInterfaceDetailA
mov	eax, [ebp+DeviceInterfaceDetailDataSize]
push	eax		; size_t
call	_malloc
add	esp, 4
mov	[ebp+DeviceInterfaceDetailData], eax
mov	ecx, [ebp+DeviceInterfaceDetailData]
mov	dword ptr [ecx], 5
mov	[ebp+RequiredSize], 0
push	0		; DeviceInfoData
lea	edx, [ebp+RequiredSize]
push	edx		; RequiredSize
mov	eax, [ebp+DeviceInterfaceDetailDataSize]
push	eax		; DeviceInterfaceDetailDataSize
mov	ecx, [ebp+DeviceInterfaceDetailData]
push	ecx		; DeviceInterfaceDetailData
lea	edx, [ebp+DeviceInterfaceData]
push	edx		; DeviceInterfaceData
mov	eax, [ebp+DeviceInfoSet]
push	eax		; DeviceInfoSet
call	ds:SetupDiGetDeviceInterfaceDetailA
test	eax, eax
jnz	short loc_10001214
mov	ecx, [ebp+DeviceInterfaceDetailData]
push	ecx		; void *
call	_free
add	esp, 4
jmp	loc_10001165

loc_10001214:		; hTemplateFile
push	0
push	0		; dwFlagsAndAttributes
push	3		; dwCreationDisposition
push	0		; lpSecurityAttributes
push	3		; dwShareMode
push	0C0000000h	; dwDesiredAccess
mov	edx, [ebp+DeviceInterfaceDetailData]
add	edx, 4
push	edx		; lpFileName
call	ds:CreateFileA
mov	ecx, [ebp+InterfaceClassGuid]
mov	[ecx+50h], eax
mov	edx, [ebp+InterfaceClassGuid]
cmp	dword ptr [edx+50h], 0FFFFFFFFh
jnz	short loc_10001250
mov	eax, [ebp+DeviceInterfaceDetailData]
push	eax		; void *
call	_free
add	esp, 4
jmp	loc_10001165

loc_10001250:
mov	[ebp+var_1C], 0
mov	[ebp+var_1A], 0
mov	[ebp+var_20], 0Ch
lea	ecx, [ebp+var_20]
push	ecx
mov	edx, [ebp+InterfaceClassGuid]
mov	eax, [edx+50h]
push	eax
call	HidD_GetAttributes
movzx	ecx, al
test	ecx, ecx
jnz	short loc_100012A2
mov	edx, [ebp+DeviceInterfaceDetailData]
push	edx		; void *
call	_free
add	esp, 4
mov	eax, [ebp+InterfaceClassGuid]
mov	ecx, [eax+50h]
push	ecx		; hObject
call	ds:CloseHandle
mov	edx, [ebp+InterfaceClassGuid]
mov	dword ptr [edx+50h], 0FFFFFFFFh
jmp	loc_10001165

loc_100012A2:
movzx	eax, [ebp+var_1C]
cmp	eax, [ebp+arg_0]
jnz	short loc_100012B4
movzx	ecx, [ebp+var_1A]
cmp	ecx, [ebp+arg_4]
jz	short loc_100012DC

loc_100012B4:
mov	edx, [ebp+DeviceInterfaceDetailData]
push	edx		; void *
call	_free
add	esp, 4
mov	eax, [ebp+InterfaceClassGuid]
mov	ecx, [eax+50h]
push	ecx		; hObject
call	ds:CloseHandle
mov	edx, [ebp+InterfaceClassGuid]
mov	dword ptr [edx+50h], 0FFFFFFFFh
jmp	loc_10001165

loc_100012DC:
lea	eax, [ebp+var_48]
push	eax
mov	ecx, [ebp+InterfaceClassGuid]
mov	edx, [ecx+50h]
push	edx
call	HidD_GetPreparsedData
mov	[ebp+var_41], al
movzx	eax, [ebp+var_41]
test	eax, eax
jz	short loc_10001312
mov	ecx, [ebp+InterfaceClassGuid]
add	ecx, 10h
push	ecx
mov	edx, [ebp+var_48]
push	edx
call	HidP_GetCaps
cmp	eax, 110000h
setz	al
mov	[ebp+var_41], al

loc_10001312:
mov	ecx, [ebp+var_48]
push	ecx
call	HidD_FreePreparsedData
movzx	edx, [ebp+var_41]
test	edx, edx
jnz	short loc_1000134B
mov	eax, [ebp+DeviceInterfaceDetailData]
push	eax		; void *
call	_free
add	esp, 4
mov	ecx, [ebp+InterfaceClassGuid]
mov	edx, [ecx+50h]
push	edx		; hObject
call	ds:CloseHandle
mov	eax, [ebp+InterfaceClassGuid]
mov	dword ptr [eax+50h], 0FFFFFFFFh
jmp	loc_10001165

loc_1000134B:		; hTemplateFile
push	0
push	40000000h	; dwFlagsAndAttributes
push	3		; dwCreationDisposition
push	0		; lpSecurityAttributes
push	3		; dwShareMode
push	0C0000000h	; dwDesiredAccess
mov	ecx, [ebp+DeviceInterfaceDetailData]
add	ecx, 4
push	ecx		; lpFileName
call	ds:CreateFileA
mov	edx, [ebp+InterfaceClassGuid]
mov	[edx+54h], eax
mov	eax, [ebp+InterfaceClassGuid]
cmp	dword ptr [eax+54h], 0FFFFFFFFh
jnz	short loc_100013A1
mov	ecx, [ebp+DeviceInterfaceDetailData]
push	ecx		; void *
call	_free
add	esp, 4
mov	edx, [ebp+InterfaceClassGuid]
mov	eax, [edx+50h]
push	eax		; hObject
call	ds:CloseHandle
mov	ecx, [ebp+InterfaceClassGuid]
mov	dword ptr [ecx+50h], 0FFFFFFFFh
jmp	loc_10001165

loc_100013A1:
mov	edx, [ebp+DeviceInterfaceDetailData]
push	edx		; void *
call	_free
add	esp, 4
push	offset Name	; lpName
push	1		; bInitialState
push	0		; bManualReset
push	0		; lpEventAttributes
call	ds:CreateEventA
mov	ecx, [ebp+InterfaceClassGuid]
mov	[ecx+58h], eax
mov	edx, [ebp+InterfaceClassGuid]
mov	eax, [ebp+InterfaceClassGuid]
mov	ecx, [eax+58h]
mov	[edx+6Ch], ecx
mov	edx, [ebp+InterfaceClassGuid]
mov	dword ptr [edx+64h], 0
mov	eax, [ebp+InterfaceClassGuid]
mov	dword ptr [eax+68h], 0
mov	ecx, [ebp+InterfaceClassGuid]
cmp	dword ptr [ecx+58h], 0
jnz	short loc_10001420
mov	edx, [ebp+InterfaceClassGuid]
mov	eax, [edx+50h]
push	eax		; hObject
call	ds:CloseHandle
mov	ecx, [ebp+InterfaceClassGuid]
mov	dword ptr [ecx+50h], 0FFFFFFFFh
mov	edx, [ebp+InterfaceClassGuid]
mov	eax, [edx+54h]
push	eax		; hObject
call	ds:CloseHandle
mov	ecx, [ebp+InterfaceClassGuid]
mov	dword ptr [ecx+54h], 0FFFFFFFFh
jmp	loc_10001165

loc_10001420:
mov	edx, [ebp+DeviceInfoSet]
push	edx		; DeviceInfoSet
call	ds:SetupDiDestroyDeviceInfoList
mov	al, 1
jmp	short loc_1000143A

loc_1000142E:
mov	eax, [ebp+DeviceInfoSet]
push	eax		; DeviceInfoSet
call	ds:SetupDiDestroyDeviceInfoList
xor	al, al

loc_1000143A:
mov	ecx, [ebp+var_24]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	0Ch
sub_10001130 endp

align 10h


; Attributes: bp-based frame

sub_10001450 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_8= dword ptr -8
var_4= dword ptr -4

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0D1h
mov	[ebp+var_4], 1
jmp	short loc_10001477

loc_1000146E:
mov	eax, [ebp+var_4]
add	eax, 1
mov	[ebp+var_4], eax

loc_10001477:
cmp	[ebp+var_4], 15h
jnb	short loc_10001487
mov	ecx, [ebp+var_4]
mov	[ebp+ecx+var_20], 0
jmp	short loc_1000146E

loc_10001487:
push	15h
lea	edx, [ebp+var_20]
push	edx
mov	eax, [ebp+var_24]
mov	ecx, [eax+50h]
push	ecx
call	HidD_SetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_100014A4
xor	al, al
jmp	short loc_100014A6

loc_100014A4:
mov	al, 1

loc_100014A6:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn
sub_10001450 endp

align 10h


; Attributes: bp-based frame

sub_100014C0 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_8= dword ptr -8
var_4= dword ptr -4

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0D0h
mov	[ebp+var_4], 1
jmp	short loc_100014E7

loc_100014DE:
mov	eax, [ebp+var_4]
add	eax, 1
mov	[ebp+var_4], eax

loc_100014E7:
cmp	[ebp+var_4], 15h
jnb	short loc_100014F7
mov	ecx, [ebp+var_4]
mov	[ebp+ecx+var_20], 0
jmp	short loc_100014DE

loc_100014F7:
push	15h
lea	edx, [ebp+var_20]
push	edx
mov	eax, [ebp+var_24]
mov	ecx, [eax+50h]
push	ecx
call	HidD_SetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_10001514
xor	al, al
jmp	short loc_10001516

loc_10001514:
mov	al, 1

loc_10001516:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn
sub_100014C0 endp

align 10h


; Attributes: bp-based frame

sub_10001530 proc near

var_144= dword ptr -144h
var_140= byte ptr -140h
var_13F= byte ptr -13Fh
var_13E= byte ptr -13Eh
var_13D= byte ptr -13Dh
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 144h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_144], ecx
mov	[ebp+var_140], 0D5h
mov	eax, [ebp+arg_4]
shr	eax, 8
and	eax, 1
mov	[ebp+var_13F], al
mov	ecx, [ebp+arg_4]
and	ecx, 0FFh
mov	[ebp+var_13E], cl
mov	[ebp+var_4], 0
jmp	short loc_1000157E

loc_10001575:
mov	edx, [ebp+var_4]
add	edx, 1
mov	[ebp+var_4], edx

loc_1000157E:
mov	eax, [ebp+var_4]
cmp	eax, [ebp+arg_4]
jnb	short loc_100015A0
mov	ecx, [ebp+var_4]
mov	edx, [ebp+arg_0]
mov	al, [edx]
mov	[ebp+ecx+var_13D], al
mov	ecx, [ebp+arg_0]
add	ecx, 1
mov	[ebp+arg_0], ecx
jmp	short loc_10001575

loc_100015A0:
mov	edx, [ebp+arg_4]
add	edx, 3
mov	[ebp+var_4], edx
jmp	short loc_100015B4

loc_100015AB:
mov	eax, [ebp+var_4]
add	eax, 1
mov	[ebp+var_4], eax

loc_100015B4:
cmp	[ebp+var_4], 131h
jnb	short loc_100015CA
mov	ecx, [ebp+var_4]
mov	[ebp+ecx+var_140], 0
jmp	short loc_100015AB

loc_100015CA:
push	111h
lea	edx, [ebp+var_140]
push	edx
mov	eax, [ebp+var_144]
mov	ecx, [eax+50h]
push	ecx
call	HidD_SetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_100015F0
xor	al, al
jmp	short loc_100015F2

loc_100015F0:
mov	al, 1

loc_100015F2:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	8
sub_10001530 endp



; Attributes: bp-based frame

sub_10001600 proc near

var_150= dword ptr -150h
var_149= byte ptr -149h
var_148= byte ptr -148h
var_147= byte ptr -147h
var_146= byte ptr -146h
var_145= byte ptr -145h
var_C= dword ptr -0Ch
var_5= byte ptr	-5
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 150h
mov	eax, dword_1001D870
mov	[ebp+var_C], eax
mov	[ebp+var_150], ecx
mov	[ebp+var_4], 0
jmp	short loc_10001629

loc_10001620:
mov	eax, [ebp+var_4]
add	eax, 1
mov	[ebp+var_4], eax

loc_10001629:
cmp	[ebp+var_4], 131h
jnb	short loc_1000163F
mov	ecx, [ebp+var_4]
mov	[ebp+ecx+var_148], 0
jmp	short loc_10001620

loc_1000163F:
mov	[ebp+var_148], 0D6h
push	111h
lea	edx, [ebp+var_148]
push	edx
mov	eax, [ebp+var_150]
mov	ecx, [eax+50h]
push	ecx
call	HidD_GetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_1000166C
xor	al, al
jmp	short loc_100016D4

loc_1000166C:
mov	al, [ebp+var_147]
mov	[ebp+var_5], al
mov	cl, [ebp+var_146]
mov	[ebp+var_149], cl
movzx	edx, [ebp+var_5]
shl	edx, 8
movzx	eax, [ebp+var_149]
or	edx, eax
and	edx, 1FFh
mov	ecx, [ebp+arg_4]
mov	[ecx], edx
mov	[ebp+var_4], 0
jmp	short loc_100016AE

loc_100016A5:
mov	edx, [ebp+var_4]
add	edx, 1
mov	[ebp+var_4], edx

loc_100016AE:
mov	eax, [ebp+arg_4]
mov	ecx, [ebp+var_4]
cmp	ecx, [eax]
jnb	short loc_100016D2
mov	edx, [ebp+arg_0]
mov	eax, [ebp+var_4]
mov	cl, [ebp+eax+var_145]
mov	[edx], cl
mov	edx, [ebp+arg_0]
add	edx, 1
mov	[ebp+arg_0], edx
jmp	short loc_100016A5

loc_100016D2:
mov	al, 1

loc_100016D4:
mov	ecx, [ebp+var_C]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	8
sub_10001600 endp

align 10h


; Attributes: bp-based frame

sub_100016F0 proc near

var_148= dword ptr -148h
var_144= dword ptr -144h
Buffer=	byte ptr -140h
var_13F= byte ptr -13Fh
var_10=	dword ptr -10h
NumberOfBytesRead= dword ptr -0Ch
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= byte ptr	 8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 148h
mov	eax, dword_1001D870
mov	[ebp+var_10], eax
mov	[ebp+var_144], ecx
mov	al, [ebp+arg_0]
mov	[ebp+Buffer], al
mov	ecx, [ebp+var_144]
add	ecx, 5Ch
push	ecx		; lpOverlapped
lea	edx, [ebp+NumberOfBytesRead]
push	edx		; lpNumberOfBytesRead
mov	eax, [ebp+var_144]
movzx	ecx, word ptr [eax+14h]
push	ecx		; nNumberOfBytesToRead
lea	edx, [ebp+Buffer]
push	edx		; lpBuffer
mov	eax, [ebp+var_144]
mov	ecx, [eax+54h]
push	ecx		; hFile
call	ds:ReadFile
push	1F4h		; dwMilliseconds
mov	edx, [ebp+var_144]
mov	eax, [edx+58h]
push	eax		; hHandle
call	ds:WaitForSingleObject
mov	[ebp+var_8], eax
mov	ecx, [ebp+var_8]
mov	[ebp+var_148], ecx
cmp	[ebp+var_148], 0
jz	short loc_10001778
cmp	[ebp+var_148], 102h
jz	short loc_100017B7
jmp	short loc_100017CB

loc_10001778:
mov	[ebp+var_4], 0
jmp	short loc_1000178A

loc_10001781:
mov	edx, [ebp+var_4]
add	edx, 1
mov	[ebp+var_4], edx

loc_1000178A:
mov	eax, [ebp+var_144]
movzx	ecx, word ptr [eax+14h]
cmp	[ebp+var_4], ecx
jnb	short loc_100017B3
mov	edx, [ebp+arg_4]
mov	eax, [ebp+var_4]
mov	cl, [ebp+eax+var_13F]
mov	[edx], cl
mov	edx, [ebp+arg_4]
add	edx, 1
mov	[ebp+arg_4], edx
jmp	short loc_10001781

loc_100017B3:
mov	al, 1
jmp	short loc_100017DD

loc_100017B7:
mov	eax, [ebp+var_144]
mov	ecx, [eax+54h]
push	ecx		; hFile
call	ds:CancelIo
xor	al, al
jmp	short loc_100017DD

loc_100017CB:
mov	edx, [ebp+var_144]
mov	eax, [edx+54h]
push	eax		; hFile
call	ds:CancelIo
xor	al, al

loc_100017DD:
mov	ecx, [ebp+var_10]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	8
sub_100016F0 endp

align 10h


; Attributes: bp-based frame

sub_100017F0 proc near

var_10=	dword ptr -10h
var_C= byte ptr	-0Ch
var_B= byte ptr	-0Bh
var_A= byte ptr	-0Ah
var_9= byte ptr	-9
var_8= byte ptr	-8
var_4= dword ptr -4
arg_0= byte ptr	 8
arg_4= byte ptr	 0Ch

push	ebp
mov	ebp, esp
sub	esp, 10h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
mov	[ebp+var_10], ecx
mov	[ebp+var_C], 0F0h
movzx	eax, [ebp+arg_0]
and	eax, 7Fh
mov	[ebp+var_B], al
mov	[ebp+var_A], 1
mov	cl, [ebp+arg_4]
mov	[ebp+var_9], cl
mov	[ebp+var_8], 0
push	5
lea	edx, [ebp+var_C]
push	edx
mov	eax, [ebp+var_10]
mov	ecx, [eax+50h]
push	ecx
call	HidD_SetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_1000183A
xor	al, al
jmp	short loc_1000183C

loc_1000183A:
mov	al, 1

loc_1000183C:
mov	ecx, [ebp+var_4]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	8
sub_100017F0 endp

align 10h


; Attributes: bp-based frame

sub_10001850 proc near

var_4= dword ptr -4
arg_0= byte ptr	 8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	eax, [ebp+arg_4]
push	eax
mov	cl, [ebp+arg_0]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_10001890
movzx	edx, al
test	edx, edx
jnz	short loc_10001872
xor	al, al
jmp	short loc_10001886

loc_10001872:
mov	eax, [ebp+arg_4]
movsx	ecx, word ptr [eax]
and	ecx, 0FFh
mov	edx, [ebp+arg_4]
mov	[edx], cx
mov	al, 1

loc_10001886:
mov	esp, ebp
pop	ebp
retn	8
sub_10001850 endp

align 10h


; Attributes: bp-based frame

sub_10001890 proc near

var_14=	dword ptr -14h
var_10=	dword ptr -10h
var_C= byte ptr	-0Ch
var_B= word ptr	-0Bh
var_9= byte ptr	-9
var_8= byte ptr	-8
var_4= dword ptr -4
arg_0= byte ptr	 8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 14h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
mov	[ebp+var_14], ecx
mov	[ebp+var_C], 0F0h
movzx	eax, [ebp+arg_0]
and	eax, 7Fh
mov	byte ptr [ebp+var_B], al
mov	byte ptr [ebp+var_B+1],	0
mov	[ebp+var_9], 0
mov	[ebp+var_8], 0
push	5
lea	ecx, [ebp+var_C]
push	ecx
mov	edx, [ebp+var_14]
mov	eax, [edx+50h]
push	eax
call	HidD_SetFeature
movzx	ecx, al
test	ecx, ecx
jnz	short loc_100018D8
xor	al, al
jmp	short loc_10001911

loc_100018D8:
push	5
lea	edx, [ebp+var_C]
push	edx
mov	eax, [ebp+var_14]
mov	ecx, [eax+50h]
push	ecx
call	HidD_GetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_100018F5
xor	al, al
jmp	short loc_10001911

loc_100018F5:
movzx	eax, [ebp+var_8]
shl	eax, 8
movzx	ecx, [ebp+var_9]
or	eax, ecx
mov	[ebp+var_10], eax
mov	edx, [ebp+arg_4]
mov	ax, word ptr [ebp+var_10]
mov	[edx], ax
mov	al, 1

loc_10001911:
mov	ecx, [ebp+var_4]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	8
sub_10001890 endp

align 10h


; Attributes: bp-based frame

sub_10001920 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= byte ptr	 8

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0D7h
mov	al, [ebp+arg_0]
mov	[ebp+var_1F], al
mov	[ebp+var_4], 2
jmp	short loc_1000194D

loc_10001944:
mov	ecx, [ebp+var_4]
add	ecx, 1
mov	[ebp+var_4], ecx

loc_1000194D:
cmp	[ebp+var_4], 15h
jnb	short loc_1000195D
mov	edx, [ebp+var_4]
mov	[ebp+edx+var_20], 0
jmp	short loc_10001944

loc_1000195D:
push	15h
lea	eax, [ebp+var_20]
push	eax
mov	ecx, [ebp+var_24]
mov	edx, [ecx+50h]
push	edx
call	HidD_SetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_1000197A
xor	al, al
jmp	short loc_1000197C

loc_1000197A:
mov	al, 1

loc_1000197C:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	4
sub_10001920 endp

align 10h


; Attributes: bp-based frame

sub_10001990 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= byte ptr	 8

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0D8h
mov	al, [ebp+arg_0]
mov	[ebp+var_1F], al
mov	[ebp+var_4], 2
jmp	short loc_100019BD

loc_100019B4:
mov	ecx, [ebp+var_4]
add	ecx, 1
mov	[ebp+var_4], ecx

loc_100019BD:
cmp	[ebp+var_4], 15h
jnb	short loc_100019CD
mov	edx, [ebp+var_4]
mov	[ebp+edx+var_20], 0
jmp	short loc_100019B4

loc_100019CD:
push	15h
lea	eax, [ebp+var_20]
push	eax
mov	ecx, [ebp+var_24]
mov	edx, [ecx+50h]
push	edx
call	HidD_SetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_100019EA
xor	al, al
jmp	short loc_100019EC

loc_100019EA:
mov	al, 1

loc_100019EC:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	4
sub_10001990 endp

align 10h


; Attributes: bp-based frame

sub_10001A00 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= byte ptr	 8

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0D9h
mov	al, [ebp+arg_0]
mov	[ebp+var_1F], al
mov	[ebp+var_4], 2
jmp	short loc_10001A2D

loc_10001A24:
mov	ecx, [ebp+var_4]
add	ecx, 1
mov	[ebp+var_4], ecx

loc_10001A2D:
cmp	[ebp+var_4], 15h
jnb	short loc_10001A3D
mov	edx, [ebp+var_4]
mov	[ebp+edx+var_20], 0
jmp	short loc_10001A24

loc_10001A3D:
push	15h
lea	eax, [ebp+var_20]
push	eax
mov	ecx, [ebp+var_24]
mov	edx, [ecx+50h]
push	edx
call	HidD_SetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_10001A5A
xor	al, al
jmp	short loc_10001A5C

loc_10001A5A:
mov	al, 1

loc_10001A5C:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	4
sub_10001A00 endp

align 10h


; Attributes: bp-based frame

sub_10001A70 proc near

var_20=	dword ptr -20h
var_1C=	byte ptr -1Ch
var_1B=	byte ptr -1Bh
var_4= dword ptr -4

push	ebp
mov	ebp, esp
sub	esp, 20h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
mov	[ebp+var_20], ecx
mov	[ebp+var_1C], 0DAh
mov	[ebp+var_1B], 0Ah
push	15h
lea	eax, [ebp+var_1C]
push	eax
mov	ecx, [ebp+var_20]
mov	edx, [ecx+50h]
push	edx
call	HidD_SetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_10001AA6
xor	al, al
jmp	short loc_10001AA8

loc_10001AA6:
mov	al, 1

loc_10001AA8:
mov	ecx, [ebp+var_4]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn
sub_10001A70 endp

align 10h


; Attributes: bp-based frame

sub_10001AC0 proc near

var_28=	dword ptr -28h
var_24=	byte ptr -24h
var_23=	byte ptr -23h
var_22=	byte ptr -22h
var_21=	byte ptr -21h
var_20=	byte ptr -20h
var_8= dword ptr -8
var_1= byte ptr	-1
arg_0= word ptr	 8
arg_4= word ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
sub	esp, 28h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_28], ecx
movzx	eax, [ebp+arg_4]
cmp	eax, 200h
jle	short loc_10001AE3
xor	al, al
jmp	loc_10001BE3

loc_10001AE3:
movzx	ecx, [ebp+arg_4]
test	ecx, ecx
jz	loc_10001BE1
mov	[ebp+var_1], 0
jmp	short loc_10001AFE

loc_10001AF5:
mov	dl, [ebp+var_1]
add	dl, 1
mov	[ebp+var_1], dl

loc_10001AFE:
movzx	eax, [ebp+var_1]
cmp	eax, 19h
jnb	short loc_10001B12
movzx	ecx, [ebp+var_1]
mov	[ebp+ecx+var_24], 0FFh
jmp	short loc_10001AF5

loc_10001B12:
mov	[ebp+var_24], 0DBh
mov	[ebp+var_23], 0Ah
movzx	edx, [ebp+arg_0]
sar	edx, 8
and	edx, 0FFh
mov	[ebp+var_22], dl
movzx	eax, [ebp+arg_0]
and	eax, 0FFh
mov	[ebp+var_21], al
movzx	ecx, [ebp+arg_4]
cmp	ecx, 10h
jl	short loc_10001B7C
mov	[ebp+var_1], 0
jmp	short loc_10001B4E

loc_10001B45:
mov	dl, [ebp+var_1]
add	dl, 1
mov	[ebp+var_1], dl

loc_10001B4E:
movzx	eax, [ebp+var_1]
cmp	eax, 10h
jge	short loc_10001B6F
movzx	ecx, [ebp+var_1]
mov	edx, [ebp+arg_8]
mov	al, [edx]
mov	[ebp+ecx+var_20], al
mov	ecx, [ebp+arg_8]
add	ecx, 1
mov	[ebp+arg_8], ecx
jmp	short loc_10001B45

loc_10001B6F:
movzx	edx, [ebp+arg_4]
sub	edx, 10h
mov	[ebp+arg_4], dx
jmp	short loc_10001BB4

loc_10001B7C:
mov	[ebp+var_1], 0
jmp	short loc_10001B8A

loc_10001B82:
mov	al, [ebp+var_1]
add	al, 1
mov	[ebp+var_1], al

loc_10001B8A:
movzx	ecx, [ebp+var_1]
movzx	edx, [ebp+arg_4]
cmp	ecx, edx
jge	short loc_10001BAE
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_8]
mov	dl, [ecx]
mov	[ebp+eax+var_20], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001B82

loc_10001BAE:
mov	[ebp+arg_4], 0

loc_10001BB4:
push	19h
lea	ecx, [ebp+var_24]
push	ecx
mov	edx, [ebp+var_28]
mov	eax, [edx+50h]
push	eax
call	HidD_SetFeature
movzx	ecx, al
test	ecx, ecx
jnz	short loc_10001BD1
xor	al, al
jmp	short loc_10001BE3

loc_10001BD1:
movzx	edx, [ebp+arg_0]
add	edx, 10h
mov	[ebp+arg_0], dx
jmp	loc_10001AE3

loc_10001BE1:
mov	al, 1

loc_10001BE3:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	0Ch
sub_10001AC0 endp

align 10h


; Attributes: bp-based frame

sub_10001C00 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_1E=	byte ptr -1Eh
var_1D=	byte ptr -1Dh
var_1C=	byte ptr -1Ch
var_8= dword ptr -8
var_1= byte ptr	-1
arg_0= word ptr	 8
arg_4= word ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
movzx	eax, [ebp+arg_4]
cmp	eax, 200h
jle	short loc_10001C23
xor	al, al
jmp	loc_10001D37

loc_10001C23:
movzx	ecx, [ebp+arg_4]
test	ecx, ecx
jz	loc_10001D35
mov	[ebp+var_20], 0DDh
mov	[ebp+var_1F], 0Ah
movzx	edx, [ebp+arg_0]
sar	edx, 8
and	edx, 0FFh
mov	[ebp+var_1E], dl
movzx	eax, [ebp+arg_0]
and	eax, 0FFh
mov	[ebp+var_1D], al
push	15h
lea	ecx, [ebp+var_20]
push	ecx
mov	edx, [ebp+var_24]
mov	eax, [edx+50h]
push	eax
call	HidD_SetFeature
movzx	ecx, al
test	ecx, ecx
jnz	short loc_10001C73
xor	al, al
jmp	loc_10001D37

loc_10001C73:
mov	[ebp+var_20], 0DCh
mov	[ebp+var_1F], 0
mov	[ebp+var_1E], 0
mov	[ebp+var_1D], 0
mov	[ebp+var_1C], 0
push	15h
lea	edx, [ebp+var_20]
push	edx
mov	eax, [ebp+var_24]
mov	ecx, [eax+50h]
push	ecx
call	HidD_GetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_10001CA7
xor	al, al
jmp	loc_10001D37

loc_10001CA7:
movzx	eax, [ebp+arg_4]
cmp	eax, 10h
jl	short loc_10001CF8
mov	[ebp+var_1], 0
jmp	short loc_10001CBF

loc_10001CB6:
mov	cl, [ebp+var_1]
add	cl, 1
mov	[ebp+var_1], cl

loc_10001CBF:
movzx	edx, [ebp+var_1]
cmp	edx, 10h
jge	short loc_10001CE0
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_8]
mov	dl, [ebp+eax+var_1C]
mov	[ecx], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001CB6

loc_10001CE0:
movzx	ecx, [ebp+arg_4]
sub	ecx, 10h
mov	[ebp+arg_4], cx
movzx	edx, [ebp+arg_0]
add	edx, 10h
mov	[ebp+arg_0], dx
jmp	short loc_10001D30

loc_10001CF8:
mov	[ebp+var_1], 0
jmp	short loc_10001D06

loc_10001CFE:
mov	al, [ebp+var_1]
add	al, 1
mov	[ebp+var_1], al

loc_10001D06:
movzx	ecx, [ebp+var_1]
movzx	edx, [ebp+arg_4]
cmp	ecx, edx
jge	short loc_10001D2A
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_8]
mov	dl, [ebp+eax+var_1C]
mov	[ecx], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001CFE

loc_10001D2A:
mov	[ebp+arg_4], 0

loc_10001D30:
jmp	loc_10001C23

loc_10001D35:
mov	al, 1

loc_10001D37:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	0Ch
sub_10001C00 endp

align 10h


; Attributes: bp-based frame

sub_10001D50 proc near

var_20=	dword ptr -20h
var_1C=	byte ptr -1Ch
var_1B=	byte ptr -1Bh
var_4= dword ptr -4

push	ebp
mov	ebp, esp
sub	esp, 20h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
mov	[ebp+var_20], ecx
mov	[ebp+var_1C], 0DAh
mov	[ebp+var_1B], 0Bh
push	15h
lea	eax, [ebp+var_1C]
push	eax
mov	ecx, [ebp+var_20]
mov	edx, [ecx+50h]
push	edx
call	HidD_SetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_10001D86
xor	al, al
jmp	short loc_10001D88

loc_10001D86:
mov	al, 1

loc_10001D88:
mov	ecx, [ebp+var_4]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn
sub_10001D50 endp

align 10h


; Attributes: bp-based frame

sub_10001DA0 proc near

var_28=	dword ptr -28h
var_24=	byte ptr -24h
var_23=	byte ptr -23h
var_22=	byte ptr -22h
var_21=	byte ptr -21h
var_20=	byte ptr -20h
var_8= dword ptr -8
var_4= word ptr	-4
arg_0= word ptr	 8
arg_4= word ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
sub	esp, 28h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_28], ecx
movzx	eax, [ebp+arg_4]
cmp	eax, 200h
jle	short loc_10001DC3
xor	al, al
jmp	loc_10001ED3

loc_10001DC3:
movzx	ecx, [ebp+arg_4]
test	ecx, ecx
jz	loc_10001ED1
mov	[ebp+var_4], 0
jmp	short loc_10001DE3

loc_10001DD7:
mov	dx, [ebp+var_4]
add	dx, 1
mov	[ebp+var_4], dx

loc_10001DE3:
movzx	eax, [ebp+var_4]
cmp	eax, 19h
jnb	short loc_10001DF7
movzx	ecx, [ebp+var_4]
mov	[ebp+ecx+var_24], 0FFh
jmp	short loc_10001DD7

loc_10001DF7:
mov	[ebp+var_24], 0DBh
mov	[ebp+var_23], 0Bh
movzx	edx, [ebp+arg_0]
sar	edx, 8
and	edx, 0FFh
mov	[ebp+var_22], dl
movzx	eax, [ebp+arg_0]
and	eax, 0FFh
mov	[ebp+var_21], al
movzx	ecx, [ebp+arg_4]
cmp	ecx, 10h
jl	short loc_10001E66
mov	[ebp+var_4], 0
jmp	short loc_10001E38

loc_10001E2C:
mov	dx, [ebp+var_4]
add	dx, 1
mov	[ebp+var_4], dx

loc_10001E38:
movzx	eax, [ebp+var_4]
cmp	eax, 10h
jge	short loc_10001E59
movzx	ecx, [ebp+var_4]
mov	edx, [ebp+arg_8]
mov	al, [edx]
mov	[ebp+ecx+var_20], al
mov	ecx, [ebp+arg_8]
add	ecx, 1
mov	[ebp+arg_8], ecx
jmp	short loc_10001E2C

loc_10001E59:
movzx	edx, [ebp+arg_4]
sub	edx, 10h
mov	[ebp+arg_4], dx
jmp	short loc_10001EA4

loc_10001E66:
mov	[ebp+var_4], 0
jmp	short loc_10001E7A

loc_10001E6E:
mov	ax, [ebp+var_4]
add	ax, 1
mov	[ebp+var_4], ax

loc_10001E7A:
movzx	ecx, [ebp+var_4]
movzx	edx, [ebp+arg_4]
cmp	ecx, edx
jge	short loc_10001E9E
movzx	eax, [ebp+var_4]
mov	ecx, [ebp+arg_8]
mov	dl, [ecx]
mov	[ebp+eax+var_20], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001E6E

loc_10001E9E:
mov	[ebp+arg_4], 0

loc_10001EA4:
push	19h
lea	ecx, [ebp+var_24]
push	ecx
mov	edx, [ebp+var_28]
mov	eax, [edx+50h]
push	eax
call	HidD_SetFeature
movzx	ecx, al
test	ecx, ecx
jnz	short loc_10001EC1
xor	al, al
jmp	short loc_10001ED3

loc_10001EC1:
movzx	edx, [ebp+arg_0]
add	edx, 10h
mov	[ebp+arg_0], dx
jmp	loc_10001DC3

loc_10001ED1:
mov	al, 1

loc_10001ED3:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	0Ch
sub_10001DA0 endp

align 10h


; Attributes: bp-based frame

sub_10001EF0 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_1E=	byte ptr -1Eh
var_1D=	byte ptr -1Dh
var_1C=	byte ptr -1Ch
var_8= dword ptr -8
var_1= byte ptr	-1
arg_0= word ptr	 8
arg_4= word ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
movzx	eax, [ebp+arg_4]
cmp	eax, 200h
jle	short loc_10001F13
xor	al, al
jmp	loc_10002027

loc_10001F13:
movzx	ecx, [ebp+arg_4]
test	ecx, ecx
jz	loc_10002025
mov	[ebp+var_20], 0DDh
mov	[ebp+var_1F], 0Bh
movzx	edx, [ebp+arg_0]
sar	edx, 8
and	edx, 0FFh
mov	[ebp+var_1E], dl
movzx	eax, [ebp+arg_0]
and	eax, 0FFh
mov	[ebp+var_1D], al
push	15h
lea	ecx, [ebp+var_20]
push	ecx
mov	edx, [ebp+var_24]
mov	eax, [edx+50h]
push	eax
call	HidD_SetFeature
movzx	ecx, al
test	ecx, ecx
jnz	short loc_10001F63
xor	al, al
jmp	loc_10002027

loc_10001F63:
mov	[ebp+var_20], 0DCh
mov	[ebp+var_1F], 0
mov	[ebp+var_1E], 0
mov	[ebp+var_1D], 0
mov	[ebp+var_1C], 0
push	15h
lea	edx, [ebp+var_20]
push	edx
mov	eax, [ebp+var_24]
mov	ecx, [eax+50h]
push	ecx
call	HidD_GetFeature
movzx	edx, al
test	edx, edx
jnz	short loc_10001F97
xor	al, al
jmp	loc_10002027

loc_10001F97:
movzx	eax, [ebp+arg_4]
cmp	eax, 10h
jl	short loc_10001FE8
mov	[ebp+var_1], 0
jmp	short loc_10001FAF

loc_10001FA6:
mov	cl, [ebp+var_1]
add	cl, 1
mov	[ebp+var_1], cl

loc_10001FAF:
movzx	edx, [ebp+var_1]
cmp	edx, 10h
jge	short loc_10001FD0
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_8]
mov	dl, [ebp+eax+var_1C]
mov	[ecx], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001FA6

loc_10001FD0:
movzx	ecx, [ebp+arg_4]
sub	ecx, 10h
mov	[ebp+arg_4], cx
movzx	edx, [ebp+arg_0]
add	edx, 10h
mov	[ebp+arg_0], dx
jmp	short loc_10002020

loc_10001FE8:
mov	[ebp+var_1], 0
jmp	short loc_10001FF6

loc_10001FEE:
mov	al, [ebp+var_1]
add	al, 1
mov	[ebp+var_1], al

loc_10001FF6:
movzx	ecx, [ebp+var_1]
movzx	edx, [ebp+arg_4]
cmp	ecx, edx
jge	short loc_1000201A
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_8]
mov	dl, [ebp+eax+var_1C]
mov	[ecx], dl
mov	eax, [ebp+arg_8]
add	eax, 1
mov	[ebp+arg_8], eax
jmp	short loc_10001FEE

loc_1000201A:
mov	[ebp+arg_4], 0

loc_10002020:
jmp	loc_10001F13

loc_10002025:
mov	al, 1

loc_10002027:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	0Ch
sub_10001EF0 endp

align 10h


; Attributes: bp-based frame

sub_10002040 proc near

var_14=	dword ptr -14h
var_10=	byte ptr -10h
var_F= byte ptr	-0Fh
var_E= byte ptr	-0Eh
var_D= byte ptr	-0Dh
var_C= byte ptr	-0Ch
var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
sub	esp, 14h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
mov	[ebp+var_14], ecx
mov	[ebp+var_10], 0DEh
mov	[ebp+var_F], 0
mov	[ebp+var_E], 0
mov	[ebp+var_D], 0
mov	[ebp+var_C], 0
push	0Ah
lea	eax, [ebp+var_10]
push	eax
mov	ecx, [ebp+var_14]
mov	edx, [ecx+50h]
push	edx
call	HidD_GetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_10002082
xor	al, al
jmp	short loc_10002095

loc_10002082:
mov	ecx, [ebp+arg_0]
mov	dl, [ebp+var_F]
mov	[ecx], dl
mov	eax, [ebp+arg_0]
mov	cl, [ebp+var_E]
mov	[eax+1], cl
mov	al, 1

loc_10002095:
mov	ecx, [ebp+var_4]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	4
sub_10002040 endp

align 10h


; Attributes: bp-based frame

sub_100020B0 proc near

var_24=	dword ptr -24h
var_20=	byte ptr -20h
var_1F=	byte ptr -1Fh
var_1E=	byte ptr -1Eh
var_1D=	byte ptr -1Dh
var_1C=	byte ptr -1Ch
var_8= dword ptr -8
var_1= byte ptr	-1
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
sub	esp, 24h
mov	eax, dword_1001D870
mov	[ebp+var_8], eax
mov	[ebp+var_24], ecx
mov	[ebp+var_20], 0DFh
mov	[ebp+var_1F], 0
mov	[ebp+var_1E], 0
mov	[ebp+var_1D], 0
mov	[ebp+var_1C], 0
push	15h
lea	eax, [ebp+var_20]
push	eax
mov	ecx, [ebp+var_24]
mov	edx, [ecx+50h]
push	edx
call	HidD_GetFeature
movzx	eax, al
test	eax, eax
jnz	short loc_100020F2
xor	al, al
jmp	short loc_10002124

loc_100020F2:
mov	[ebp+var_1], 0
jmp	short loc_10002101

loc_100020F8:
mov	cl, [ebp+var_1]
add	cl, 1
mov	[ebp+var_1], cl

loc_10002101:
movzx	edx, [ebp+var_1]
cmp	edx, 14h
jge	short loc_10002122
movzx	eax, [ebp+var_1]
mov	ecx, [ebp+arg_0]
mov	dl, [ebp+eax+var_1F]
mov	[ecx], dl
mov	eax, [ebp+arg_0]
add	eax, 1
mov	[ebp+arg_0], eax
jmp	short loc_100020F8

loc_10002122:
mov	al, 1

loc_10002124:
mov	ecx, [ebp+var_8]
call	sub_10003E65
mov	esp, ebp
pop	ebp
retn	4
sub_100020B0 endp

align 10h
; Exported entry  21. _sHID_create@0


; Attributes: bp-based frame

; int __stdcall	sHID_create()
public _sHID_create@0
_sHID_create@0 proc near

var_C= dword ptr -0Ch
var_8= dword ptr -8
var_4= dword ptr -4

push	ebp
mov	ebp, esp
sub	esp, 0Ch
push	70h		; size_t
call	??2@YAPAXI@Z	; operator new(uint)
add	esp, 4
mov	[ebp+var_8], eax
cmp	[ebp+var_8], 0
jz	short loc_10002166
mov	ecx, [ebp+var_8]
call	sub_10001060
mov	[ebp+var_C], eax
jmp	short loc_1000216D

loc_10002166:
mov	[ebp+var_C], 0

loc_1000216D:
mov	eax, [ebp+var_C]
mov	[ebp+var_4], eax
mov	eax, [ebp+var_4]
mov	esp, ebp
pop	ebp
retn
_sHID_create@0 endp

align 10h
; Exported entry  22. _sHID_destroy@4


; Attributes: bp-based frame

; __stdcall sHID_destroy(x)
public _sHID_destroy@4
_sHID_destroy@4	proc near

var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_8= dword ptr -8
var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
sub	esp, 10h
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+var_4]
mov	[ebp+var_C], ecx
mov	edx, [ebp+var_C]
mov	[ebp+var_8], edx
cmp	[ebp+var_8], 0
jz	short loc_100021AD
push	1
mov	ecx, [ebp+var_8]
call	sub_100024E0
mov	[ebp+var_10], eax
jmp	short loc_100021B4

loc_100021AD:
mov	[ebp+var_10], 0

loc_100021B4:
mov	esp, ebp
pop	ebp
retn	4
_sHID_destroy@4	endp

align 10h
; Exported entry   4. _sHID_Find@16


; Attributes: bp-based frame

; __stdcall sHID_Find(x, x, x, x)
public _sHID_Find@16
_sHID_Find@16 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h
arg_C= dword ptr  14h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_C]
push	ecx
mov	edx, [ebp+arg_8]
push	edx
mov	eax, [ebp+arg_4]
push	eax
mov	ecx, [ebp+var_4]
call	sub_10001130
mov	esp, ebp
pop	ebp
retn	10h
_sHID_Find@16 endp

align 10h
; Exported entry  17. _sHID_SetTX@4


; Attributes: bp-based frame

; __stdcall sHID_SetTX(x)
public _sHID_SetTX@4
_sHID_SetTX@4 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+var_4]
call	sub_10001450
mov	esp, ebp
pop	ebp
retn	4
_sHID_SetTX@4 endp

align 10h
; Exported entry  15. _sHID_SetRX@4


; Attributes: bp-based frame

; __stdcall sHID_SetRX(x)
public _sHID_SetRX@4
_sHID_SetRX@4 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+var_4]
call	sub_100014C0
mov	esp, ebp
pop	ebp
retn	4
_sHID_SetRX@4 endp

align 10h
; Exported entry  16. _sHID_SetState@8


; Attributes: bp-based frame

; __stdcall sHID_SetState(x, x)
public _sHID_SetState@8
_sHID_SetState@8 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	cl, [ebp+arg_4]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_10001920
mov	esp, ebp
pop	ebp
retn	8
_sHID_SetState@8 endp

align 10h
; Exported entry  13. _sHID_SetFrame@12


; Attributes: bp-based frame

; __stdcall sHID_SetFrame(x, x,	x)
public _sHID_SetFrame@12
_sHID_SetFrame@12 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_8]
push	ecx
mov	edx, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_10001530
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_SetFrame@12 endp

; Exported entry   5. _sHID_GetFrame@12


; Attributes: bp-based frame

; __stdcall sHID_GetFrame(x, x,	x)
public _sHID_GetFrame@12
_sHID_GetFrame@12 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_8]
push	ecx
mov	edx, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_10001600
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_GetFrame@12 endp

; Exported entry  20. _sHID_WriteReg@12


; Attributes: bp-based frame

; __stdcall sHID_WriteReg(x, x,	x)
public _sHID_WriteReg@12
_sHID_WriteReg@12 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch
arg_8= byte ptr	 10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	cl, [ebp+arg_8]
push	ecx
mov	dl, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_100017F0
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_WriteReg@12 endp

; Exported entry  12. _sHID_ReadReg@12


; Attributes: bp-based frame

; __stdcall sHID_ReadReg(x, x, x)
public _sHID_ReadReg@12
_sHID_ReadReg@12 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_8]
push	ecx
mov	dl, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_10001850
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_ReadReg@12 endp

; Exported entry  11. _sHID_ReadReg16@12


; Attributes: bp-based frame

; __stdcall sHID_ReadReg16(x, x, x)
public _sHID_ReadReg16@12
_sHID_ReadReg16@12 proc	near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_8]
push	ecx
mov	dl, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_10001890
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_ReadReg16@12 endp

; Exported entry   6. _sHID_GetReport@12


; Attributes: bp-based frame

; __stdcall sHID_GetReport(x, x, x)
public _sHID_GetReport@12
_sHID_GetReport@12 proc	near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch
arg_8= dword ptr  10h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_8]
push	ecx
mov	dl, [ebp+arg_4]
push	edx
mov	ecx, [ebp+var_4]
call	sub_100016F0
mov	esp, ebp
pop	ebp
retn	0Ch
_sHID_GetReport@12 endp

; Exported entry  14. _sHID_SetPreamblePattern@8


; Attributes: bp-based frame

; __stdcall sHID_SetPreamblePattern(x, x)
public _sHID_SetPreamblePattern@8
_sHID_SetPreamblePattern@8 proc	near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	cl, [ebp+arg_4]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_10001990
mov	esp, ebp
pop	ebp
retn	8
_sHID_SetPreamblePattern@8 endp

align 10h
; Exported entry   3. _sHID_Execute@8


; Attributes: bp-based frame

; __stdcall sHID_Execute(x, x)
public _sHID_Execute@8
_sHID_Execute@8	proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= byte ptr	 0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	cl, [ebp+arg_4]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_10001A00
mov	esp, ebp
pop	ebp
retn	8
_sHID_Execute@8	endp

align 10h
; Exported entry   1. _sHID_EraseConfigFlash@4


; Attributes: bp-based frame

; __stdcall sHID_EraseConfigFlash(x)
public _sHID_EraseConfigFlash@4
_sHID_EraseConfigFlash@4 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+var_4]
call	sub_10001A70
mov	esp, ebp
pop	ebp
retn	4
_sHID_EraseConfigFlash@4 endp

align 10h
; Exported entry  18. _sHID_WriteConfigFlash@16


; Attributes: bp-based frame

; __stdcall sHID_WriteConfigFlash(x, x,	x, x)
public _sHID_WriteConfigFlash@16
_sHID_WriteConfigFlash@16 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= word ptr	 0Ch
arg_8= word ptr	 10h
arg_C= dword ptr  14h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_C]
push	ecx
mov	dx, [ebp+arg_8]
push	edx
mov	ax, [ebp+arg_4]
push	eax
mov	ecx, [ebp+var_4]
call	sub_10001AC0
mov	esp, ebp
pop	ebp
retn	10h
_sHID_WriteConfigFlash@16 endp

align 10h
; Exported entry   9. _sHID_ReadConfigFlash@16


; Attributes: bp-based frame

; __stdcall sHID_ReadConfigFlash(x, x, x, x)
public _sHID_ReadConfigFlash@16
_sHID_ReadConfigFlash@16 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= word ptr	 0Ch
arg_8= word ptr	 10h
arg_C= dword ptr  14h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_C]
push	ecx
mov	dx, [ebp+arg_8]
push	edx
mov	ax, [ebp+arg_4]
push	eax
mov	ecx, [ebp+var_4]
call	sub_10001C00
mov	esp, ebp
pop	ebp
retn	10h
_sHID_ReadConfigFlash@16 endp

align 10h
; Exported entry   2. _sHID_EraseDataFlash@4


; Attributes: bp-based frame

; __stdcall sHID_EraseDataFlash(x)
public _sHID_EraseDataFlash@4
_sHID_EraseDataFlash@4 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+var_4]
call	sub_10001D50
mov	esp, ebp
pop	ebp
retn	4
_sHID_EraseDataFlash@4 endp

align 10h
; Exported entry  19. _sHID_WriteDataFlash@16


; Attributes: bp-based frame

; __stdcall sHID_WriteDataFlash(x, x, x, x)
public _sHID_WriteDataFlash@16
_sHID_WriteDataFlash@16	proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= word ptr	 0Ch
arg_8= word ptr	 10h
arg_C= dword ptr  14h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_C]
push	ecx
mov	dx, [ebp+arg_8]
push	edx
mov	ax, [ebp+arg_4]
push	eax
mov	ecx, [ebp+var_4]
call	sub_10001DA0
mov	esp, ebp
pop	ebp
retn	10h
_sHID_WriteDataFlash@16	endp

align 10h
; Exported entry  10. _sHID_ReadDataFlash@16


; Attributes: bp-based frame

; __stdcall sHID_ReadDataFlash(x, x, x,	x)
public _sHID_ReadDataFlash@16
_sHID_ReadDataFlash@16 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= word ptr	 0Ch
arg_8= word ptr	 10h
arg_C= dword ptr  14h

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_C]
push	ecx
mov	dx, [ebp+arg_8]
push	edx
mov	ax, [ebp+arg_4]
push	eax
mov	ecx, [ebp+var_4]
call	sub_10001EF0
mov	esp, ebp
pop	ebp
retn	10h
_sHID_ReadDataFlash@16 endp

align 10h
; Exported entry   8. _sHID_GetState@8


; Attributes: bp-based frame

; __stdcall sHID_GetState(x, x)
public _sHID_GetState@8
_sHID_GetState@8 proc near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_4]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_10002040
mov	esp, ebp
pop	ebp
retn	8
_sHID_GetState@8 endp

align 10h
; Exported entry   7. _sHID_GetRevInfo@8


; Attributes: bp-based frame

; __stdcall sHID_GetRevInfo(x, x)
public _sHID_GetRevInfo@8
_sHID_GetRevInfo@8 proc	near

var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
push	ecx
mov	eax, [ebp+arg_0]
mov	[ebp+var_4], eax
mov	ecx, [ebp+arg_4]
push	ecx
mov	ecx, [ebp+var_4]
call	sub_100020B0
mov	esp, ebp
pop	ebp
retn	8
_sHID_GetRevInfo@8 endp

align 10h


; Attributes: bp-based frame

sub_10002490 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	ecx, [ebp+var_4]
call	sub_100024C0
mov	eax, [ebp+arg_0]
and	eax, 1
jz	short loc_100024B0
mov	ecx, [ebp+var_4]
push	ecx		; void *
call	sub_10002520

loc_100024B0:
mov	eax, [ebp+var_4]
mov	esp, ebp
pop	ebp
retn	4
sub_10002490 endp

align 10h


; Attributes: bp-based frame

sub_100024C0 proc near

var_4= dword ptr -4

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	ecx, [ebp+var_4]
call	??1CWinApp@@UAE@XZ ; CWinApp::~CWinApp(void)
mov	esp, ebp
pop	ebp
retn
sub_100024C0 endp

align 10h


; Attributes: bp-based frame

sub_100024E0 proc near

var_4= dword ptr -4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
mov	[ebp+var_4], ecx
mov	ecx, [ebp+var_4]
call	sub_100010A0
mov	eax, [ebp+arg_0]
and	eax, 1
jz	short loc_10002503
mov	ecx, [ebp+var_4]
push	ecx		; void *
call	j__free
add	esp, 4

loc_10002503:
mov	eax, [ebp+var_4]
mov	esp, ebp
pop	ebp
retn	4
sub_100024E0 endp

align 10h
; [0000000D BYTES: COLLAPSED FUNCTION unknown_libname_11. PRESS	KEYPAD "+" TO EXPAND]
align 10h


; Attributes: bp-based frame

; int __stdcall	sub_10002520(void *)
sub_10002520 proc near

arg_0= dword ptr  8

push	ebp
mov	ebp, esp
mov	eax, [ebp+arg_0]
push	eax		; void *
call	j__free
add	esp, 4
pop	ebp
retn	4
sub_10002520 endp

align 10h
; [00000073 BYTES: COLLAPSED FUNCTION ATL::_AtlGetThreadACPThunk(void).	PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000015 BYTES: COLLAPSED FUNCTION InterlockedExchangePointer(void *	*,void *). PRESS KEYPAD	"+" TO EXPAND]
align 10h
; [00000089 BYTES: COLLAPSED FUNCTION ATL::_AtlGetThreadACPFake(void). PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [0000000A BYTES: COLLAPSED FUNCTION ATL::_AtlGetThreadACPReal(void). PRESS KEYPAD "+"	TO EXPAND]
align 10h


; Attributes: noreturn bp-based	frame

sub_10002680 proc near

arg_0= dword ptr  8

push	ebp
mov	ebp, esp
cmp	[ebp+arg_0], 8007000Eh
jnz	short loc_10002691
call	unknown_libname_20 ; MFC 3.1-10.0 32bit

loc_10002691:
mov	eax, [ebp+arg_0]
push	eax		; __int32
call	?AfxThrowOleException@@YGXJ@Z ;	AfxThrowOleException(long)
sub_10002680 endp

db  5Dh	; ]
db 0C2h	; Â
db    4
db    0
; [00000006 BYTES: COLLAPSED FUNCTION HidD_GetHidGuid. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidD_FreePreparsedData. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidP_GetCaps. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidD_GetPreparsedData. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidD_GetAttributes. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidD_SetFeature. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HidD_GetFeature. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _DllMain@12_0. PRESS KEYPAD "+" TO EXPAND]



; void __cdecl sub_100026CE()
sub_100026CE proc near
push	1		; int
push	0		; struct HINSTANCE__ *
call	?AfxTermLocalData@@YGXPAUHINSTANCE__@@H@Z ; AfxTermLocalData(HINSTANCE__ *,int)
call	?AfxCriticalTerm@@YGXXZ	; AfxCriticalTerm(void)
jmp	?AfxTlsRelease@@YGXXZ ;	AfxTlsRelease(void)
sub_100026CE endp

; [000000C9 BYTES: COLLAPSED FUNCTION DllMain(x,x,x). PRESS KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION ATL::CStringData::Release(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000013 BYTES: COLLAPSED FUNCTION AfxGetMainWnd(void). PRESS KEYPAD	"+" TO EXPAND]



sub_100027D7 proc near

arg_0= dword ptr  4

mov	eax, [esp+arg_0]
test	eax, eax
jl	short loc_100027F2
mov	edx, [ecx]
cmp	eax, [edx-8]
jg	short loc_100027F2
mov	[edx-0Ch], eax
mov	ecx, [ecx]
mov	byte ptr [eax+ecx], 0
retn	4

loc_100027F2:
push	80070057h
call	sub_10002680
sub_100027D7 endp

db 0CCh


; Attributes: noreturn

sub_100027FD proc near
push	8007000Eh
call	sub_10002680
sub_100027FD endp

align 4
; [00000028 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::Reallocate(int). PRESS KEYPAD "+" TO	EXPAND]



sub_10002830 proc near
push	esi
mov	esi, ecx
mov	eax, [esi]
lea	ecx, [eax-10h]
xor	edx, edx
cmp	[ecx+4], edx
push	edi
mov	edi, [ecx]
jz	short loc_10002870
cmp	[ecx+0Ch], edx
jge	short loc_1000285F
cmp	[eax-8], edx
jge	short loc_10002856
push	80070057h
call	sub_10002680

loc_10002856:
mov	[eax-0Ch], edx
mov	eax, [esi]
mov	[eax], dl
jmp	short loc_10002870

loc_1000285F:		; ATL::CStringData::Release(void)
call	?Release@CStringData@ATL@@QAEXXZ
mov	eax, [edi]
mov	ecx, edi
call	dword ptr [eax+0Ch]
add	eax, 10h
mov	[esi], eax

loc_10002870:
pop	edi
pop	esi
retn
sub_10002830 endp

; [00000017 BYTES: COLLAPSED FUNCTION unknown_libname_12. PRESS	KEYPAD "+" TO EXPAND]
; [00000067 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::Fork(int). PRESS KEYPAD "+" TO EXPAND]
; [00000047 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::PrepareWrite2(int). PRESS KEYPAD "+"	TO EXPAND]



sub_10002938 proc near
push	esi
mov	esi, ecx
call	sub_1000FB8F
push	eax
mov	ecx, esi
call	unknown_libname_12 ; MFC 3.1-10.0 32bit
mov	eax, esi
pop	esi
retn
sub_10002938 endp

; START	OF FUNCTION CHUNK FOR sub_100167B5

loc_1000294C:
mov	ecx, [ecx]
sub	ecx, 10h
jmp	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
; END OF FUNCTION CHUNK	FOR sub_100167B5
; [0000002A BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::PrepareWrite(int). PRESS KEYPAD "+" TO EXPAND]
; [00000067 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::SetString(char const	*,int).	PRESS KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::SetString(char const	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000005C BYTES: COLLAPSED FUNCTION ATL::_AtlGetStringResourceImage(HINSTANCE__ *,HRSRC__ *,uint). PRESS KEYPAD "+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION ATL::AtlGetStringResourceImage(HINSTANCE__ *,uint). PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION ATL::ChTraitsCRT<char>::GetBaseTypeLength(wchar_t	const *,int). PRESS KEYPAD "+" TO EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION ATL::ChTraitsCRT<char>::ConvertToBaseType(char *,int,wchar_t const *,int). PRESS KEYPAD "+" TO EXPAND]
; [00000059 BYTES: COLLAPSED FUNCTION unknown_libname_13. PRESS	KEYPAD "+" TO EXPAND]



sub_10002B30 proc near

arg_0= dword ptr  4

push	esi
push	[esp+4+arg_0]	; unsigned int
mov	esi, ecx
call	?AfxFindStringResourceHandle@@YGPAUHINSTANCE__@@I@Z ; AfxFindStringResourceHandle(uint)
test	eax, eax
jz	short loc_10002B4C
push	[esp+4+arg_0]	; int
mov	ecx, esi
push	eax		; hModule
call	unknown_libname_13 ; MFC 3.1-10.0 32bit

loc_10002B4C:
pop	esi
retn	4
sub_10002B30 endp

; [0000005A BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::CloneData(ATL::CStringData *). PRESS	KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::ReleaseBuffer(int). PRESS KEYPAD "+"	TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::CSimpleStringT<char,0>(CSimpleStringT<char,0>::CSimpleStringT<char,0> const &). PRESS KEYPAD	"+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::Append(char const *,int). PRESS KEYPAD "+" TO EXPAND]



sub_10002C39 proc near

arg_0= dword ptr  4

mov	edx, [esp+arg_0]
xor	al, al
test	edx, edx
jz	short locret_10002C56
test	edx, 0FFFF0000h
jnz	short locret_10002C56
movzx	eax, dx
push	eax
call	sub_10002B30
mov	al, 1

locret_10002C56:
retn	4
sub_10002C39 endp



; Attributes: bp-based frame

; int __stdcall	sub_10002C59(char *)
sub_10002C59 proc near

var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8

mov	eax, offset sub_100167E1
call	__EH_prolog
push	ecx
push	esi
mov	esi, ecx
mov	[ebp+var_10], esi
call	sub_1000FB8F
push	eax
mov	ecx, esi
call	unknown_libname_12 ; MFC 3.1-10.0 32bit
push	[ebp+arg_0]
and	[ebp+var_4], 0
mov	ecx, esi
call	sub_10002C39
test	al, al
jnz	short loc_10002C93
push	[ebp+arg_0]	; char *
mov	ecx, esi
call	?SetString@?$CSimpleStringT@D$0A@@ATL@@QAEXPBD@Z ; ATL::CSimpleStringT<char,0>::SetString(char const *)

loc_10002C93:
mov	ecx, [ebp+var_C]
mov	eax, esi
pop	esi
mov	large fs:0, ecx
leave
retn	4
sub_10002C59 endp

; [0000001B BYTES: COLLAPSED FUNCTION unknown_libname_14. PRESS	KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION unknown_libname_15. PRESS	KEYPAD "+" TO EXPAND]



; int __stdcall	sub_10002CD7(UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem)
sub_10002CD7 proc near

uPosition= dword ptr  4
uFlags=	dword ptr  8
uIDNewItem= dword ptr  0Ch
lpNewItem= dword ptr  10h

push	[esp+lpNewItem]	; lpNewItem
push	[esp+4+uIDNewItem] ; uIDNewItem
push	[esp+8+uFlags]	; uFlags
push	[esp+0Ch+uPosition] ; uPosition
push	dword ptr [ecx+4] ; hMnu
call	ds:ModifyMenuA
retn	10h
sub_10002CD7 endp

; [00000016 BYTES: COLLAPSED FUNCTION COleException::COleException(void). PRESS	KEYPAD "+" TO EXPAND]



; int __thiscall sub_10002D09(void *, char)
sub_10002D09 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002D25
test	[esp+4+arg_0], 1
jz	short loc_10002D1F
push	esi		; void *
call	j__free
pop	ecx

loc_10002D1F:
mov	eax, esi
pop	esi
retn	4
sub_10002D09 endp




sub_10002D25 proc near
mov	dword ptr [ecx], offset	off_10017A44
retn
sub_10002D25 endp




sub_10002D2C proc near
mov	dword ptr [ecx], offset	off_10017B24
retn
sub_10002D2C endp




sub_10002D33 proc near
mov	dword ptr [ecx], offset	off_10017B3C
retn
sub_10002D33 endp




sub_10002D3A proc near
mov	dword ptr [ecx], offset	off_10017B54
retn
sub_10002D3A endp

; [00000018 BYTES: COLLAPSED FUNCTION CSimpleException::CSimpleException(int). PRESS KEYPAD "+"	TO EXPAND]



; int __thiscall sub_10002D59(void *, char)
sub_10002D59 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002D2C
test	[esp+4+arg_0], 1
jz	short loc_10002D6F
push	esi		; void *
call	j__free
pop	ecx

loc_10002D6F:
mov	eax, esi
pop	esi
retn	4
sub_10002D59 endp




sub_10002D75 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	[esp+4+arg_0]
mov	esi, ecx
call	??0CSimpleException@@QAE@H@Z ; CSimpleException::CSimpleException(int)
mov	eax, [esp+4+arg_4]
mov	[esi+94h], eax
mov	dword ptr [esi], offset	off_10017B24
mov	eax, esi
pop	esi
retn	8
sub_10002D75 endp




; int __thiscall sub_10002D97(void *, char)
sub_10002D97 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002D33
test	[esp+4+arg_0], 1
jz	short loc_10002DAD
push	esi		; void *
call	j__free
pop	ecx

loc_10002DAD:
mov	eax, esi
pop	esi
retn	4
sub_10002D97 endp




sub_10002DB3 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	[esp+4+arg_0]
mov	esi, ecx
call	??0CSimpleException@@QAE@H@Z ; CSimpleException::CSimpleException(int)
mov	eax, [esp+4+arg_4]
mov	[esi+94h], eax
mov	dword ptr [esi], offset	off_10017B3C
mov	eax, esi
pop	esi
retn	8
sub_10002DB3 endp




; int __thiscall sub_10002DD5(void *, char)
sub_10002DD5 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002D3A
test	[esp+4+arg_0], 1
jz	short loc_10002DEB
push	esi		; void *
call	j__free
pop	ecx

loc_10002DEB:
mov	eax, esi
pop	esi
retn	4
sub_10002DD5 endp




sub_10002DF1 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	[esp+4+arg_0]
mov	esi, ecx
call	??0CSimpleException@@QAE@H@Z ; CSimpleException::CSimpleException(int)
mov	eax, [esp+4+arg_4]
mov	[esi+94h], eax
mov	dword ptr [esi], offset	off_10017B54
mov	eax, esi
pop	esi
retn	8
sub_10002DF1 endp

; [0000001C BYTES: COLLAPSED FUNCTION CHandleMap::`scalar deleting destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000054 BYTES: COLLAPSED FUNCTION CHandleMap::~CHandleMap(void). PRESS KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION CObject::operator	delete(void *,void *). PRESS KEYPAD "+"	TO EXPAND]



sub_10002E90 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	[esp+4+arg_0]
mov	esi, ecx
call	??0CSimpleException@@QAE@H@Z ; CSimpleException::CSimpleException(int)
mov	eax, [esp+4+arg_4]
mov	[esi+94h], eax
mov	dword ptr [esi], offset	off_10017C84
mov	eax, esi
pop	esi
retn	8
sub_10002E90 endp




sub_10002EB2 proc near
mov	dword ptr [ecx], offset	off_10017C84
retn
sub_10002EB2 endp




sub_10002EB9 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	[esp+4+arg_0]
mov	esi, ecx
call	??0CSimpleException@@QAE@H@Z ; CSimpleException::CSimpleException(int)
mov	eax, [esp+4+arg_4]
mov	[esi+94h], eax
mov	dword ptr [esi], offset	off_10017C9C
mov	eax, esi
pop	esi
retn	8
sub_10002EB9 endp




sub_10002EDB proc near
mov	dword ptr [ecx], offset	off_10017C9C
retn
sub_10002EDB endp




; int __stdcall	sub_10002EE2(int x, int	y)
sub_10002EE2 proc near

x= dword ptr  4
y= dword ptr  8

push	[esp+y]		; y
push	[esp+4+x]	; x
push	dword ptr [ecx+4] ; hdc
call	ds:PtVisible
retn	8
sub_10002EE2 endp




; int __stdcall	sub_10002EF6(RECT *lprect)
sub_10002EF6 proc near

lprect=	dword ptr  4

push	[esp+lprect]	; lprect
push	dword ptr [ecx+4] ; hdc
call	ds:RectVisible
retn	4
sub_10002EF6 endp




; int __stdcall	sub_10002F06(int x, int	y, LPCSTR lpString, int	c)
sub_10002F06 proc near

x= dword ptr  4
y= dword ptr  8
lpString= dword	ptr  0Ch
c= dword ptr  10h

push	[esp+c]		; c
push	[esp+4+lpString] ; lpString
push	[esp+8+y]	; y
push	[esp+0Ch+x]	; x
push	dword ptr [ecx+4] ; hdc
call	ds:TextOutA
retn	10h
sub_10002F06 endp

; [00000025 BYTES: COLLAPSED FUNCTION CDC::ExtTextOutA(int,int,uint,tagRECT const *,char const *,uint,int *). PRESS KEYPAD "+" TO EXPAND]
; [00000038 BYTES: COLLAPSED FUNCTION CDC::TabbedTextOutA(int,int,char const *,int,int,int *,int). PRESS KEYPAD	"+" TO EXPAND]



; int __stdcall	sub_10002F7F(LPCSTR lpchText, int cchText, LPRECT lprc,	UINT format)
sub_10002F7F proc near

lpchText= dword	ptr  4
cchText= dword ptr  8
lprc= dword ptr	 0Ch
format=	dword ptr  10h

push	[esp+format]	; format
push	[esp+4+lprc]	; lprc
push	[esp+8+cchText]	; cchText
push	[esp+0Ch+lpchText] ; lpchText
push	dword ptr [ecx+4] ; hdc
call	ds:DrawTextA
retn	10h
sub_10002F7F endp

; [0000001F BYTES: COLLAPSED FUNCTION CDC::DrawTextExA(char *,int,tagRECT *,uint,tagDRAWTEXTPARAMS *). PRESS KEYPAD "+"	TO EXPAND]
; [00000030 BYTES: COLLAPSED FUNCTION CDC::GrayStringA(CBrush *,int (*)(HDC__ *,long,int),long,int,int,int,int,int). PRESS KEYPAD "+" TO EXPAND]



; int __stdcall	sub_10002FEA(int iEscape, int cjIn, LPCSTR pvIn, LPVOID	pvOut)
sub_10002FEA proc near

iEscape= dword ptr  4
cjIn= dword ptr	 8
pvIn= dword ptr	 0Ch
pvOut= dword ptr  10h

push	[esp+pvOut]	; pvOut
push	[esp+4+pvIn]	; pvIn
push	[esp+8+cjIn]	; cjIn
push	[esp+0Ch+iEscape] ; iEscape
push	dword ptr [ecx+4] ; hdc
call	ds:Escape
retn	10h
sub_10002FEA endp




; int __thiscall sub_10003006(void *, char)
sub_10003006 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002EB2
test	[esp+4+arg_0], 1
jz	short loc_1000301C
push	esi		; void *
call	j__free
pop	ecx

loc_1000301C:
mov	eax, esi
pop	esi
retn	4
sub_10003006 endp




; int __thiscall sub_10003022(void *, char)
sub_10003022 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10002EDB
test	[esp+4+arg_0], 1
jz	short loc_10003038
push	esi		; void *
call	j__free
pop	ecx

loc_10003038:
mov	eax, esi
pop	esi
retn	4
sub_10003022 endp




sub_1000303E proc near

; FUNCTION CHUNK AT 100134EE SIZE 00000016 BYTES

mov	dword ptr [ecx], offset	off_10017CB4
jmp	loc_100134EE
sub_1000303E endp




; int __thiscall sub_10003049(void *, char)
sub_10003049 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_1000303E
test	[esp+4+arg_0], 1
jz	short loc_1000305F
push	esi		; void *
call	j__free
pop	ecx

loc_1000305F:
mov	eax, esi
pop	esi
retn	4
sub_10003049 endp

; [00000014 BYTES: COLLAPSED FUNCTION ATL::CComCriticalSection::CComCriticalSection(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000050 BYTES: COLLAPSED FUNCTION ATL::CComCriticalSection::Init(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000004D BYTES: COLLAPSED FUNCTION _IsPlatformNT. PRESS KEYPAD "+" TO EXPAND]
; [000000FA BYTES: COLLAPSED FUNCTION _InitMultipleMonitorStubs. PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION xMonitorFromRect(x,x). PRESS KEYPAD "+" TO EXPAND]
; [0000006B BYTES: COLLAPSED FUNCTION xMonitorFromWindow(x,x). PRESS KEYPAD "+"	TO EXPAND]
; [00000095 BYTES: COLLAPSED FUNCTION xGetMonitorInfo(x,x). PRESS KEYPAD "+" TO	EXPAND]
; [0000059B BYTES: COLLAPSED FUNCTION ATL::AtlIAccessibleInvokeHelper(IAccessible *,long,_GUID const &,ulong,ushort,tagDISPPARAMS *,tagVARIANT *,tagEXCEPINFO *,uint *). PRESS KEYPAD "+" TO EXPAND]
off_100038F7 dd	offset loc_10003441 ; jump table for switch statement
dd offset loc_1000346A
dd offset loc_100034E1
dd offset loc_1000352A
dd offset loc_100035A0
dd offset loc_100035EA
dd offset loc_10003624
dd offset loc_10003632
dd offset loc_10003640
dd offset loc_10003665
dd offset loc_100036F2
dd offset loc_1000371A
dd offset loc_1000373E
dd offset loc_10003762
dd offset loc_1000378A
dd offset loc_1000380E
dd offset loc_10003892
dd offset loc_100038B7
dd offset loc_100038C9
; [00000060 BYTES: COLLAPSED FUNCTION ATL::AtlIAccessibleGetIDsOfNamesHelper(_GUID const &,wchar_t * *,uint,ulong,long *). PRESS KEYPAD	"+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION CMenu::GetSubMenu(int). PRESS KEYPAD "+" TO EXPAND]
; [00000003 BYTES: COLLAPSED FUNCTION nullsub_4. PRESS KEYPAD "+" TO EXPAND]



sub_100039BC proc near
push	0		; bEnable
push	dword ptr [ecx+1Ch] ; hWnd
call	ds:EnableWindow
retn
sub_100039BC endp

; [0000000C BYTES: COLLAPSED FUNCTION CWnd::EndModalState(void). PRESS KEYPAD "+" TO EXPAND]
; START	OF FUNCTION CHUNK FOR sub_100169B9

loc_100039D4:		; AfxGetModuleState(void)
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ
mov	ecx, [eax+4]
jmp	?EndWaitCursor@CCmdTarget@@QAEXXZ ; CCmdTarget::EndWaitCursor(void)
; END OF FUNCTION CHUNK	FOR sub_100169B9



sub_100039E1 proc near
xor	eax, eax
retn	8
sub_100039E1 endp




sub_100039E6 proc near
mov	eax, 80004001h
retn	8
sub_100039E6 endp

; [00000015 BYTES: COLLAPSED FUNCTION ATL::CAccessibleProxy::FinalRelease(void). PRESS KEYPAD "+" TO EXPAND]
; [000000CE BYTES: COLLAPSED FUNCTION ATL::AtlInternalQueryInterface(void *,ATL::_ATL_INTMAP_ENTRY const *,_GUID const &,void *	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION CWnd::GetOwner(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000002A BYTES: COLLAPSED FUNCTION CFixedAllocNoSync::CFixedAllocNoSync(uint,uint). PRESS KEYPAD "+"	TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION CFixedAllocNoSync::FreeAll(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION CFixedAllocNoSync::FreeAll(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION CFixedAllocNoSync::Alloc(void). PRESS KEYPAD "+" TO EXPAND]



sub_10003B6D proc near

; FUNCTION CHUNK AT 10012E96 SIZE 00000016 BYTES

mov	dword ptr [ecx], offset	off_10018788
jmp	loc_10012E96
sub_10003B6D endp




; int __thiscall sub_10003B78(void *, char)
sub_10003B78 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_10003B6D
test	[esp+4+arg_0], 1
jz	short loc_10003B8E
push	esi		; void *
call	j__free
pop	ecx

loc_10003B8E:
mov	eax, esi
pop	esi
retn	4
sub_10003B78 endp

; [0000003C BYTES: COLLAPSED FUNCTION CArchive::operator<<(ushort). PRESS KEYPAD "+" TO	EXPAND]
; [0000003B BYTES: COLLAPSED FUNCTION unknown_libname_16. PRESS	KEYPAD "+" TO EXPAND]
; [00000043 BYTES: COLLAPSED FUNCTION unknown_libname_17. PRESS	KEYPAD "+" TO EXPAND]
; [00000042 BYTES: COLLAPSED FUNCTION unknown_libname_18. PRESS	KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

; int __stdcall	sub_10003C90(int, char *)
sub_10003C90 proc near

var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

mov	eax, offset sub_10016A04
call	__EH_prolog
push	ecx
push	esi
mov	esi, ecx
push	edi
mov	[ebp+var_10], esi
call	??0CException@@QAE@XZ ;	CException::CException(void)
lea	edi, [esi+0Ch]
mov	ecx, edi
mov	dword ptr [esi], offset	off_100187D0
call	sub_10002938
mov	eax, [ebp+arg_0]
push	[ebp+arg_4]	; char *
and	[ebp+var_4], 0
mov	ecx, edi
mov	[esi+8], eax
call	?SetString@?$CSimpleStringT@D$0A@@ATL@@QAEXPBD@Z ; ATL::CSimpleStringT<char,0>::SetString(char const *)
mov	ecx, [ebp+var_C]
pop	edi
mov	eax, esi
pop	esi
mov	large fs:0, ecx
leave
retn	8
sub_10003C90 endp




; int __thiscall sub_10003CDD(void *, char)
sub_10003CDD proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1CArchiveException@@UAE@XZ ; CArchiveException::~CArchiveException(void)
test	[esp+4+arg_0], 1
jz	short loc_10003CF3
push	esi		; void *
call	j__free
pop	ecx

loc_10003CF3:
mov	eax, esi
pop	esi
retn	4
sub_10003CDD endp

; [00000011 BYTES: COLLAPSED FUNCTION CArchiveException::~CArchiveException(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000005C BYTES: COLLAPSED FUNCTION _free. PRESS KEYPAD "+" TO EXPAND]
; [00000015 BYTES: COLLAPSED CHUNK OF FUNCTION _free. PRESS KEYPAD "+" TO EXPAND]
; [0000007B BYTES: COLLAPSED FUNCTION __heap_alloc. PRESS KEYPAD "+" TO	EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION __nh_malloc. PRESS KEYPAD	"+" TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION _malloc. PRESS KEYPAD "+"	TO EXPAND]
; [00000030 BYTES: COLLAPSED FUNCTION _report_failure. PRESS KEYPAD "+"	TO EXPAND]
db 0CCh



sub_10003E65 proc near
cmp	ecx, dword_1001D870
jnz	short loc_10003E6E
retn

loc_10003E6E:
jmp	_report_failure
sub_10003E65 endp

; [00000080 BYTES: COLLAPSED FUNCTION __onexit_lk. PRESS KEYPAD	"+" TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION ___onexitinit. PRESS KEYPAD "+" TO EXPAND]
; [00000038 BYTES: COLLAPSED FUNCTION __onexit.	PRESS KEYPAD "+" TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION _atexit. PRESS KEYPAD "+"	TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION _JumpToContinuation(void *,EHRegistrationNode *).	PRESS KEYPAD "+" TO EXPAND]
pop	ebx
leave
retn	8
; [00000007 BYTES: COLLAPSED FUNCTION sub_10003F95. PRESS KEYPAD "+" TO	EXPAND]
; [00000052 BYTES: COLLAPSED FUNCTION unknown_libname_2. PRESS KEYPAD "+" TO EXPAND]
; [00000036 BYTES: COLLAPSED FUNCTION ___CxxFrameHandler. PRESS	KEYPAD "+" TO EXPAND]
; [0000003B BYTES: COLLAPSED FUNCTION CatchGuardHandler(EHExceptionRecord *,CatchGuardRN *,void	*,void *). PRESS KEYPAD	"+" TO EXPAND]
; [000000C7 BYTES: COLLAPSED FUNCTION _CallSETranslator(EHExceptionRecord *,EHRegistrationNode *,void *,void *,_s_FuncInfo const *,int,EHRegistrationNode *). PRESS KEYPAD "+" TO EXPAND]
; [000000B2 BYTES: COLLAPSED FUNCTION TranslatorGuardHandler(EHExceptionRecord *,TranslatorGuardRN *,void *,void *). PRESS KEYPAD "+" TO EXPAND]
; [0000007A BYTES: COLLAPSED FUNCTION _GetRangeOfTrysToCheck(_s_FuncInfo const *,int,int,uint *,uint *). PRESS KEYPAD "+" TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION _CreateFrameInfo(FrameInfo *,void	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION IsExceptionObjectToBeDestroyed(void *). PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION _FindAndUnlinkFrame(FrameInfo *).	PRESS KEYPAD "+" TO EXPAND]
; [00000059 BYTES: COLLAPSED FUNCTION _CallCatchBlock2(EHRegistrationNode *,_s_FuncInfo	const *,void *,int,ulong). PRESS KEYPAD	"+" TO EXPAND]
; [00000020 BYTES: COLLAPSED FUNCTION __global_unwind2.	PRESS KEYPAD "+" TO EXPAND]
; [00000022 BYTES: COLLAPSED FUNCTION __unwind_handler.	PRESS KEYPAD "+" TO EXPAND]
; [00000068 BYTES: COLLAPSED FUNCTION __local_unwind2. PRESS KEYPAD "+"	TO EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION __abnormal_termination. PRESS KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION __NLG_Notify1. PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION __NLG_Notify. PRESS KEYPAD "+" TO	EXPAND]
align 10h
; [0000003D BYTES: COLLAPSED FUNCTION __alloca_probe. PRESS KEYPAD "+" TO EXPAND]
; [000000E3 BYTES: COLLAPSED FUNCTION __resetstkoflw. PRESS KEYPAD "+" TO EXPAND]
push	esi
inc	ebx
xor	dh, [eax]
pop	eax
inc	ebx
xor	[eax], dh
; [000000E6 BYTES: COLLAPSED FUNCTION __except_handler3. PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION _seh_longjmp_unwind(x). PRESS KEYPAD "+" TO EXPAND]
; [00000181 BYTES: COLLAPSED FUNCTION _CRT_INIT(x,x,x).	PRESS KEYPAD "+" TO EXPAND]
; [000000E4 BYTES: COLLAPSED FUNCTION DllEntryPoint. PRESS KEYPAD "+" TO EXPAND]
; [00000030 BYTES: COLLAPSED FUNCTION __amsg_exit. PRESS KEYPAD	"+" TO EXPAND]
pop	ecx
pop	ecx
retn
; [00000057 BYTES: COLLAPSED FUNCTION __snprintf. PRESS	KEYPAD "+" TO EXPAND]
; [00000034 BYTES: COLLAPSED FUNCTION _sscanf. PRESS KEYPAD "+"	TO EXPAND]
; [0000001F BYTES: COLLAPSED FUNCTION __EH_prolog. PRESS KEYPAD	"+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION unknown_libname_4. PRESS KEYPAD "+" TO EXPAND]
db 0CCh
; [00000009 BYTES: COLLAPSED FUNCTION __lockexit. PRESS	KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION __unlockexit. PRESS KEYPAD "+" TO	EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION __initterm. PRESS	KEYPAD "+" TO EXPAND]
; [0000006A BYTES: COLLAPSED FUNCTION __cinit. PRESS KEYPAD "+"	TO EXPAND]
; [000000C3 BYTES: COLLAPSED FUNCTION _doexit. PRESS KEYPAD "+"	TO EXPAND]
; [00000011 BYTES: COLLAPSED FUNCTION __exit. PRESS KEYPAD "+" TO EXPAND]
; [0000000F BYTES: COLLAPSED FUNCTION __cexit. PRESS KEYPAD "+"	TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION type_info::~type_info(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000001C BYTES: COLLAPSED FUNCTION type_info::`scalar deleting destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
align 10h
; [0000033D BYTES: COLLAPSED FUNCTION _memcpy. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [0000008B BYTES: COLLAPSED FUNCTION _strlen. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [0000033D BYTES: COLLAPSED FUNCTION _memcpy_0. PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION __strdup.	PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000060 BYTES: COLLAPSED FUNCTION _memset. PRESS KEYPAD "+"	TO EXPAND]
; [000000B8 BYTES: COLLAPSED FUNCTION _memcmp. PRESS KEYPAD "+"	TO EXPAND]
; [0000003A BYTES: COLLAPSED FUNCTION _CxxThrowException(x,x). PRESS KEYPAD "+"	TO EXPAND]
; [00000076 BYTES: COLLAPSED FUNCTION __msize. PRESS KEYPAD "+"	TO EXPAND]
; [0000007B BYTES: COLLAPSED FUNCTION __mbschr.	PRESS KEYPAD "+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION _CPtoLCID. PRESS KEYPAD "+" TO EXPAND]
; [00000029 BYTES: COLLAPSED FUNCTION _setSBCS.	PRESS KEYPAD "+" TO EXPAND]
; [0000018C BYTES: COLLAPSED FUNCTION _setSBUpLow. PRESS KEYPAD	"+" TO EXPAND]
; [0000006F BYTES: COLLAPSED FUNCTION ___updatetmbcinfo. PRESS KEYPAD "+" TO EXPAND]
; [00000190 BYTES: COLLAPSED FUNCTION __setmbcp_lk. PRESS KEYPAD "+" TO	EXPAND]
; [00000150 BYTES: COLLAPSED FUNCTION __setmbcp. PRESS KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION ___initmbctable. PRESS KEYPAD "+"	TO EXPAND]
; [00000087 BYTES: COLLAPSED FUNCTION __expand.	PRESS KEYPAD "+" TO EXPAND]
; [00000023 BYTES: COLLAPSED CHUNK OF FUNCTION __expand. PRESS KEYPAD "+" TO EXPAND]
; [00000088 BYTES: COLLAPSED FUNCTION _atol. PRESS KEYPAD "+" TO EXPAND]
align 4
; [0000003B BYTES: COLLAPSED FUNCTION __SEH_prolog. PRESS KEYPAD "+" TO	EXPAND]
; [00000011 BYTES: COLLAPSED FUNCTION __SEH_epilog. PRESS KEYPAD "+" TO	EXPAND]
; [00000171 BYTES: COLLAPSED FUNCTION _realloc.	PRESS KEYPAD "+" TO EXPAND]
; [0000003C BYTES: COLLAPSED CHUNK OF FUNCTION _realloc. PRESS KEYPAD "+" TO EXPAND]
; [00000094 BYTES: COLLAPSED FUNCTION __mbscmp.	PRESS KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION __errno. PRESS KEYPAD "+"	TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION ___doserrno. PRESS KEYPAD	"+" TO EXPAND]
; [00000073 BYTES: COLLAPSED FUNCTION __dosmaperr. PRESS KEYPAD	"+" TO EXPAND]
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_2. PRESS KEYPAD "+" TO EXPAND]
; [00000038 BYTES: COLLAPSED FUNCTION __cfltcvt_init. PRESS KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION __fpmath.	PRESS KEYPAD "+" TO EXPAND]
align 4
; [00000075 BYTES: COLLAPSED FUNCTION __ftol2. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [00000034 BYTES: COLLAPSED FUNCTION __allmul.	PRESS KEYPAD "+" TO EXPAND]
align 10h

__alldiv:
push	edi
push	esi
push	ebx
xor	edi, edi
mov	eax, [esp+14h]
or	eax, eax
jge	short loc_10006001
inc	edi
mov	edx, [esp+10h]
neg	eax
neg	edx
sbb	eax, 0
mov	[esp+14h], eax
mov	[esp+10h], edx

loc_10006001:
mov	eax, [esp+1Ch]
or	eax, eax
jge	short loc_1000601D
inc	edi
mov	edx, [esp+18h]
neg	eax
neg	edx
sbb	eax, 0
mov	[esp+1Ch], eax
mov	[esp+18h], edx

loc_1000601D:
or	eax, eax
jnz	short loc_10006039
mov	ecx, [esp+18h]
mov	eax, [esp+14h]
xor	edx, edx
div	ecx
mov	ebx, eax
mov	eax, [esp+10h]
div	ecx
mov	edx, ebx
jmp	short loc_1000607A

loc_10006039:
mov	ebx, eax
mov	ecx, [esp+18h]
mov	edx, [esp+14h]
mov	eax, [esp+10h]

loc_10006047:
shr	ebx, 1
rcr	ecx, 1
shr	edx, 1
rcr	eax, 1
or	ebx, ebx
jnz	short loc_10006047
div	ecx
mov	esi, eax
mul	dword ptr [esp+1Ch]
mov	ecx, eax
mov	eax, [esp+18h]
mul	esi
add	edx, ecx
jb	short loc_10006075
cmp	edx, [esp+14h]
ja	short loc_10006075
jb	short loc_10006076
cmp	eax, [esp+10h]
jbe	short loc_10006076

loc_10006075:
dec	esi

loc_10006076:
xor	edx, edx
mov	eax, esi

loc_1000607A:
dec	edi
jnz	short loc_10006084
neg	edx
neg	eax
sbb	edx, 0

loc_10006084:
pop	ebx
pop	esi
pop	edi
retn	10h
; [0000001A BYTES: COLLAPSED FUNCTION ___heap_select. PRESS KEYPAD "+" TO EXPAND]
; [00000051 BYTES: COLLAPSED FUNCTION __heap_init. PRESS KEYPAD	"+" TO EXPAND]
; [0000007F BYTES: COLLAPSED FUNCTION __heap_term. PRESS KEYPAD	"+" TO EXPAND]
; [00000049 BYTES: COLLAPSED FUNCTION __mtinitlocks. PRESS KEYPAD "+" TO EXPAND]
; [00000055 BYTES: COLLAPSED CHUNK OF FUNCTION __mtterm. PRESS KEYPAD "+" TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION __unlock.	PRESS KEYPAD "+" TO EXPAND]
; [000000A0 BYTES: COLLAPSED FUNCTION __mtinitlocknum. PRESS KEYPAD "+"	TO EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION __lock. PRESS KEYPAD "+" TO EXPAND]
; [00000048 BYTES: COLLAPSED FUNCTION ___sbh_heap_init.	PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION ___sbh_find_block. PRESS KEYPAD "+" TO EXPAND]
; [00000318 BYTES: COLLAPSED FUNCTION ___sbh_free_block. PRESS KEYPAD "+" TO EXPAND]
; [000000B7 BYTES: COLLAPSED FUNCTION ___sbh_alloc_new_region. PRESS KEYPAD "+"	TO EXPAND]
; [00000106 BYTES: COLLAPSED FUNCTION ___sbh_alloc_new_group. PRESS KEYPAD "+" TO EXPAND]
; [000002DF BYTES: COLLAPSED FUNCTION ___sbh_resize_block. PRESS KEYPAD	"+" TO EXPAND]
; [000002FC BYTES: COLLAPSED FUNCTION ___sbh_alloc_block. PRESS	KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION __callnewh. PRESS	KEYPAD "+" TO EXPAND]
; [00000066 BYTES: COLLAPSED FUNCTION ___security_init_cookie. PRESS KEYPAD "+"	TO EXPAND]
; [00000147 BYTES: COLLAPSED FUNCTION ___security_error_handler. PRESS KEYPAD "+" TO EXPAND]
align 4
; [0000004F BYTES: COLLAPSED FUNCTION TypeMatch(_s_HandlerType const *,_s_CatchableType	const *,_s_ThrowInfo const *). PRESS KEYPAD "+"	TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION FrameUnwindFilter(_EXCEPTION_POINTERS *).	PRESS KEYPAD "+" TO EXPAND]
; [000000CE BYTES: COLLAPSED FUNCTION ___FrameUnwindToState. PRESS KEYPAD "+" TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION ___DestructExceptionObject. PRESS	KEYPAD "+" TO EXPAND]
; [0000001F BYTES: COLLAPSED FUNCTION AdjustPointer(void *,PMD const &). PRESS KEYPAD "+" TO EXPAND]
; [000001C4 BYTES: COLLAPSED FUNCTION CallCatchBlock(EHExceptionRecord *,EHRegistrationNode *,_CONTEXT *,_s_FuncInfo const *,void *,int,ulong).	PRESS KEYPAD "+" TO EXPAND]
; [0000017C BYTES: COLLAPSED FUNCTION BuildCatchObject(EHExceptionRecord *,void	*,_s_HandlerType const *,_s_CatchableType const	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000067 BYTES: COLLAPSED FUNCTION CatchIt(EHExceptionRecord	*,EHRegistrationNode *,_CONTEXT	*,void *,_s_FuncInfo const *,_s_HandlerType const *,_s_CatchableType const *,_s_TryBlockMapEntry const *,int,EHRegistrationNode	*,uchar). PRESS	KEYPAD "+" TO EXPAND]
; [000000BE BYTES: COLLAPSED FUNCTION FindHandlerForForeignException(EHExceptionRecord *,EHRegistrationNode *,_CONTEXT *,void *,_s_FuncInfo const *,int,int,EHRegistrationNode *). PRESS KEYPAD	"+" TO EXPAND]
; [00000204 BYTES: COLLAPSED FUNCTION FindHandler(EHExceptionRecord *,EHRegistrationNode *,_CONTEXT *,void *,_s_FuncInfo const *,uchar,int,EHRegistrationNode *). PRESS	KEYPAD "+" TO EXPAND]
; [000000A2 BYTES: COLLAPSED FUNCTION ___InternalCxxFrameHandler. PRESS	KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION __crtTlsAlloc(x).	PRESS KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION __mtterm.	PRESS KEYPAD "+" TO EXPAND]
; [00000013 BYTES: COLLAPSED FUNCTION __initptd. PRESS KEYPAD "+" TO EXPAND]
; [00000071 BYTES: COLLAPSED FUNCTION __getptd.	PRESS KEYPAD "+" TO EXPAND]
; [00000147 BYTES: COLLAPSED FUNCTION _freefls(x). PRESS KEYPAD	"+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION __freeptd. PRESS KEYPAD "+" TO EXPAND]
; [000000EF BYTES: COLLAPSED FUNCTION __mtinit.	PRESS KEYPAD "+" TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION terminate(void). PRESS KEYPAD "+"	TO EXPAND]


; Attributes: noreturn bp-based	frame

sub_10007BD2 proc near

ms_exc=	CPPEH_RECORD ptr -18h

push	8
push	offset stru_10018BB0
call	__SEH_prolog
mov	eax, off_1001DC60
test	eax, eax
jz	short loc_10007BFA
and	[ebp+ms_exc.disabled], 0
call	eax ; terminate(void) ;	terminate(void)
unk_10007BED db	0EBh ; ë
db    7

loc_10007BEF:		; Exception filter 0 for function 10007BD2
xor	eax, eax
inc	eax
retn

loc_10007BF3:		; Exception handler 0 for function 10007BD2
mov	esp, [ebp+ms_exc.old_esp]
or	[ebp+ms_exc.disabled], 0FFFFFFFFh

loc_10007BFA:		; terminate(void)
jmp	?terminate@@YAXXZ
sub_10007BD2 endp

align 10h
; [0000004C BYTES: COLLAPSED FUNCTION unknown_libname_5. PRESS KEYPAD "+" TO EXPAND]
; [00000229 BYTES: COLLAPSED FUNCTION __ValidateEH3RN. PRESS KEYPAD "+"	TO EXPAND]
; [000000BB BYTES: COLLAPSED FUNCTION _calloc. PRESS KEYPAD "+"	TO EXPAND]
; [000001FE BYTES: COLLAPSED FUNCTION __ioinit.	PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION __ioterm.	PRESS KEYPAD "+" TO EXPAND]
; [000000C7 BYTES: COLLAPSED FUNCTION __setenvp. PRESS KEYPAD "+" TO EXPAND]
; [0000016C BYTES: COLLAPSED FUNCTION _parse_cmdline. PRESS KEYPAD "+" TO EXPAND]
; [000000A2 BYTES: COLLAPSED FUNCTION __setargv. PRESS KEYPAD "+" TO EXPAND]
; [00000122 BYTES: COLLAPSED FUNCTION ___crtGetEnvironmentStringsA. PRESS KEYPAD "+" TO	EXPAND]


; Attributes: bp-based frame

sub_10008571 proc near

var_1C=	dword ptr -1Ch
ms_exc=	CPPEH_RECORD ptr -18h

push	0Ch
push	offset stru_10018BD0
call	__SEH_prolog
mov	[ebp+var_1C], offset unk_1001A510

loc_10008584:
cmp	[ebp+var_1C], offset unk_1001A510
jnb	short loc_100085AF
and	[ebp+ms_exc.disabled], 0
mov	eax, [ebp+var_1C]
mov	eax, [eax]
test	eax, eax
jz	short loc_100085A5
call	eax
jmp	short loc_100085A5

loc_1000859E:		; Exception filter 0 for function 10008571
xor	eax, eax
inc	eax
retn

loc_100085A2:		; Exception handler 0 for function 10008571
mov	esp, [ebp+ms_exc.old_esp]

loc_100085A5:
or	[ebp+ms_exc.disabled], 0FFFFFFFFh
add	[ebp+var_1C], 4
jmp	short loc_10008584

loc_100085AF:
call	__SEH_epilog
retn
sub_10008571 endp



; Attributes: bp-based frame

; void __cdecl sub_100085B5()
sub_100085B5 proc near

var_1C=	dword ptr -1Ch
ms_exc=	CPPEH_RECORD ptr -18h

push	0Ch
push	offset stru_10018BE0
call	__SEH_prolog
mov	[ebp+var_1C], offset unk_1001A518

loc_100085C8:
cmp	[ebp+var_1C], offset unk_1001A518
jnb	short loc_100085F3
and	[ebp+ms_exc.disabled], 0
mov	eax, [ebp+var_1C]
mov	eax, [eax]
test	eax, eax
jz	short loc_100085E9
call	eax
jmp	short loc_100085E9

loc_100085E2:		; Exception filter 0 for function 100085B5
xor	eax, eax
inc	eax
retn

loc_100085E6:		; Exception handler 0 for function 100085B5
mov	esp, [ebp+ms_exc.old_esp]

loc_100085E9:
or	[ebp+ms_exc.disabled], 0FFFFFFFFh
add	[ebp+var_1C], 4
jmp	short loc_100085C8

loc_100085F3:
call	__SEH_epilog
retn
sub_100085B5 endp

; [00000164 BYTES: COLLAPSED FUNCTION __XcptFilter. PRESS KEYPAD "+" TO	EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION ___CppXcptFilter.	PRESS KEYPAD "+" TO EXPAND]
; [00000177 BYTES: COLLAPSED FUNCTION __NMSG_WRITE. PRESS KEYPAD "+" TO	EXPAND]
; [00000039 BYTES: COLLAPSED FUNCTION __FF_MSGBANNER. PRESS KEYPAD "+" TO EXPAND]
; [00000119 BYTES: COLLAPSED FUNCTION __flsbuf.	PRESS KEYPAD "+" TO EXPAND]
; [00000033 BYTES: COLLAPSED FUNCTION _write_char. PRESS KEYPAD	"+" TO EXPAND]
; [00000024 BYTES: COLLAPSED FUNCTION _write_multi_char. PRESS KEYPAD "+" TO EXPAND]
; [00000037 BYTES: COLLAPSED FUNCTION _write_string. PRESS KEYPAD "+" TO EXPAND]
; [000007DA BYTES: COLLAPSED FUNCTION __output.	PRESS KEYPAD "+" TO EXPAND]
off_100092A9 dd	offset loc_10008CEB ; jump table for switch statement
dd offset loc_10008B5B
dd offset loc_10008B78
dd offset loc_10008BC4
dd offset loc_10008C05
dd offset loc_10008C0E
dd offset loc_10008C4C
dd offset loc_10008D2D
; [00000016 BYTES: COLLAPSED FUNCTION __inc. PRESS KEYPAD "+" TO EXPAND]
; [00000D7C BYTES: COLLAPSED FUNCTION __input. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [00000088 BYTES: COLLAPSED FUNCTION _strcmp. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [00000007 BYTES: COLLAPSED FUNCTION _strcpy. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [000000E8 BYTES: COLLAPSED FUNCTION _strcat. PRESS KEYPAD "+"	TO EXPAND]
; [0000004E BYTES: COLLAPSED FUNCTION __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS	*). PRESS KEYPAD "+" TO	EXPAND]



sub_1000A236 proc near
push	offset ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z ; lpTopLevelExceptionFilter
call	ds:SetUnhandledExceptionFilter
mov	lpTopLevelExceptionFilter, eax
xor	eax, eax
retn
sub_1000A236 endp




sub_1000A249 proc near
push	lpTopLevelExceptionFilter ; lpTopLevelExceptionFilter
call	ds:SetUnhandledExceptionFilter
retn
sub_1000A249 endp

align 10h
; [00000005 BYTES: COLLAPSED CHUNK OF FUNCTION __mbschr. PRESS KEYPAD "+" TO EXPAND]
align 10h
; [000000BE BYTES: COLLAPSED CHUNK OF FUNCTION __mbschr. PRESS KEYPAD "+" TO EXPAND]
; [000003BC BYTES: COLLAPSED FUNCTION ___crtLCMapStringA. PRESS	KEYPAD "+" TO EXPAND]
; [000001BA BYTES: COLLAPSED FUNCTION ___crtGetStringTypeA. PRESS KEYPAD "+" TO	EXPAND]
; [00000077 BYTES: COLLAPSED FUNCTION ___isctype_mt. PRESS KEYPAD "+" TO EXPAND]
; [000000D0 BYTES: COLLAPSED FUNCTION ___freetlocinfo. PRESS KEYPAD "+"	TO EXPAND]
; [000000C1 BYTES: COLLAPSED FUNCTION ___updatetlocinfo_lk. PRESS KEYPAD "+" TO	EXPAND]
; [0000003B BYTES: COLLAPSED FUNCTION ___updatetlocinfo. PRESS KEYPAD "+" TO EXPAND]
align 10h
; [0000002D BYTES: COLLAPSED FUNCTION _strrchr.	PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000046 BYTES: COLLAPSED FUNCTION _strspn. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [00000046 BYTES: COLLAPSED FUNCTION _strcspn.	PRESS KEYPAD "+" TO EXPAND]

__forcdecpt:
push	esi
mov	esi, [esp+8]
movsx	eax, byte ptr [esi]
push	eax
call	sub_1000C3A8
cmp	eax, 65h
jmp	short loc_1000ABD5

loc_1000ABC9:
inc	esi
movsx	eax, byte ptr [esi]
push	eax
call	_isdigit
test	eax, eax

loc_1000ABD5:
pop	ecx
jnz	short loc_1000ABC9
mov	al, [esi]
mov	cl, byte_1001E324
mov	[esi], cl
inc	esi

loc_1000ABE3:
mov	cl, [esi]
mov	[esi], al
mov	al, cl
mov	cl, [esi]
inc	esi
test	cl, cl
jnz	short loc_1000ABE3
pop	esi
retn

__cropzeros:
mov	eax, [esp+4]
push	ebx
mov	bl, byte_1001E324
jmp	short loc_1000AC04

loc_1000ABFF:
cmp	cl, bl
jz	short loc_1000AC0A
inc	eax

loc_1000AC04:
mov	cl, [eax]
test	cl, cl
jnz	short loc_1000ABFF

loc_1000AC0A:
mov	cl, [eax]
inc	eax
test	cl, cl
jz	short loc_1000AC3B
jmp	short loc_1000AC1E

loc_1000AC13:
cmp	cl, 65h
jz	short loc_1000AC24
cmp	cl, 45h
jz	short loc_1000AC24
inc	eax

loc_1000AC1E:
mov	cl, [eax]
test	cl, cl
jnz	short loc_1000AC13

loc_1000AC24:
mov	edx, eax

loc_1000AC26:
dec	eax
cmp	byte ptr [eax],	30h
jz	short loc_1000AC26
cmp	[eax], bl
jnz	short loc_1000AC31
dec	eax

loc_1000AC31:
mov	cl, [edx]
inc	eax
inc	edx
test	cl, cl
mov	[eax], cl
jnz	short loc_1000AC31

loc_1000AC3B:
pop	ebx
retn

__positive:
mov	eax, [esp+4]
fld	qword ptr [eax]
fcomp	ds:dbl_10019200
fnstsw	ax
test	ah, 1
jnz	short loc_1000AC54
xor	eax, eax
inc	eax
retn

loc_1000AC54:
xor	eax, eax
retn
; [0000003E BYTES: COLLAPSED FUNCTION __fassign. PRESS KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION __shift. PRESS KEYPAD "+"	TO EXPAND]
; [000000AE BYTES: COLLAPSED FUNCTION __cftoe2.	PRESS KEYPAD "+" TO EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION __cftoe. PRESS KEYPAD "+"	TO EXPAND]
; [0000009C BYTES: COLLAPSED FUNCTION __cftof2.	PRESS KEYPAD "+" TO EXPAND]
; [00000062 BYTES: COLLAPSED FUNCTION __cftof. PRESS KEYPAD "+"	TO EXPAND]
; [0000009A BYTES: COLLAPSED FUNCTION __cftog. PRESS KEYPAD "+"	TO EXPAND]
; [00000051 BYTES: COLLAPSED FUNCTION __cfltcvt. PRESS KEYPAD "+" TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION __setdefaultprecision. PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION __ms_p5_test_fdiv. PRESS KEYPAD "+" TO EXPAND]
; [00000029 BYTES: COLLAPSED FUNCTION __ms_p5_mp_test_fdiv. PRESS KEYPAD "+" TO	EXPAND]

__allrem:
push	ebx
push	edi
xor	edi, edi
mov	eax, [esp+10h]
or	eax, eax
jge	short loc_1000B050
inc	edi
mov	edx, [esp+0Ch]
neg	eax
neg	edx
sbb	eax, 0
mov	[esp+10h], eax
mov	[esp+0Ch], edx

loc_1000B050:
mov	eax, [esp+18h]
or	eax, eax
jge	short loc_1000B06B
mov	edx, [esp+14h]
neg	eax
neg	edx
sbb	eax, 0
mov	[esp+18h], eax
mov	[esp+14h], edx

loc_1000B06B:
or	eax, eax
jnz	short loc_1000B08A
mov	ecx, [esp+14h]
mov	eax, [esp+10h]
xor	edx, edx
div	ecx
mov	eax, [esp+0Ch]
div	ecx
mov	eax, edx
xor	edx, edx
dec	edi
jns	short loc_1000B0D6
jmp	short loc_1000B0DD

loc_1000B08A:
mov	ebx, eax
mov	ecx, [esp+14h]
mov	edx, [esp+10h]
mov	eax, [esp+0Ch]

loc_1000B098:
shr	ebx, 1
rcr	ecx, 1
shr	edx, 1
rcr	eax, 1
or	ebx, ebx
jnz	short loc_1000B098
div	ecx
mov	ecx, eax
mul	dword ptr [esp+18h]
xchg	eax, ecx
mul	dword ptr [esp+14h]
add	edx, ecx
jb	short loc_1000B0C3
cmp	edx, [esp+10h]
ja	short loc_1000B0C3
jb	short loc_1000B0CB
cmp	eax, [esp+0Ch]
jbe	short loc_1000B0CB

loc_1000B0C3:
sub	eax, [esp+14h]
sbb	edx, [esp+18h]

loc_1000B0CB:
sub	eax, [esp+0Ch]
sbb	edx, [esp+10h]
dec	edi
jns	short loc_1000B0DD

loc_1000B0D6:
neg	edx
neg	eax
sbb	edx, 0

loc_1000B0DD:
pop	edi
pop	ebx
retn	10h
; [00000010 BYTES: COLLAPSED FUNCTION __crtInitCritSecNoSpinCount(x,x).	PRESS KEYPAD "+" TO EXPAND]
; [0000008B BYTES: COLLAPSED FUNCTION ___crtInitCritSecAndSpinCount. PRESS KEYPAD "+" TO EXPAND]
; [000000F9 BYTES: COLLAPSED FUNCTION ___crtMessageBoxA. PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000124 BYTES: COLLAPSED FUNCTION _strncpy.	PRESS KEYPAD "+" TO EXPAND]
; [0000001C BYTES: COLLAPSED FUNCTION _ValidateRead(void const *,uint).	PRESS KEYPAD "+" TO EXPAND]
; [0000001C BYTES: COLLAPSED FUNCTION _ValidateWrite(void *,uint). PRESS KEYPAD	"+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION _ValidateExecute(int (*)(void)). PRESS KEYPAD "+"	TO EXPAND]
; [00000018 BYTES: COLLAPSED CHUNK OF FUNCTION terminate(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000074 BYTES: COLLAPSED FUNCTION __lseek_lk. PRESS	KEYPAD "+" TO EXPAND]
; [0000008F BYTES: COLLAPSED FUNCTION __lseek. PRESS KEYPAD "+"	TO EXPAND]
; [0000001C BYTES: COLLAPSED CHUNK OF FUNCTION __lseek.	PRESS KEYPAD "+" TO EXPAND]
; [000001CE BYTES: COLLAPSED FUNCTION __write_lk. PRESS	KEYPAD "+" TO EXPAND]
; [0000008F BYTES: COLLAPSED FUNCTION __write. PRESS KEYPAD "+"	TO EXPAND]
; [0000001C BYTES: COLLAPSED CHUNK OF FUNCTION __write.	PRESS KEYPAD "+" TO EXPAND]
; [00000044 BYTES: COLLAPSED FUNCTION __getbuf.	PRESS KEYPAD "+" TO EXPAND]
; [0000002A BYTES: COLLAPSED FUNCTION __isatty.	PRESS KEYPAD "+" TO EXPAND]
; [000000A9 BYTES: COLLAPSED FUNCTION ___initstdio. PRESS KEYPAD "+" TO	EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION ___endstdio. PRESS KEYPAD	"+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION __lock_file. PRESS KEYPAD	"+" TO EXPAND]



sub_1000B8FE proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

mov	eax, [esp+arg_0]
cmp	eax, 14h
jge	short loc_1000B912
add	eax, 10h
push	eax
call	__lock
pop	ecx
retn

loc_1000B912:
mov	eax, [esp+arg_4]
add	eax, 20h
push	eax		; lpCriticalSection
call	ds:EnterCriticalSection
retn
sub_1000B8FE endp

; [0000002F BYTES: COLLAPSED FUNCTION __unlock_file. PRESS KEYPAD "+" TO EXPAND]



sub_1000B950 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

mov	eax, [esp+arg_0]
cmp	eax, 14h
jge	short loc_1000B964
add	eax, 10h
push	eax
call	__unlock
pop	ecx
retn

loc_1000B964:
mov	eax, [esp+arg_4]
add	eax, 20h
push	eax		; lpCriticalSection
call	ds:LeaveCriticalSection
retn
sub_1000B950 endp

; [00000060 BYTES: COLLAPSED FUNCTION ___wctomb_mt. PRESS KEYPAD "+" TO	EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION _wctomb. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [00000095 BYTES: COLLAPSED FUNCTION __aulldvrm. PRESS	KEYPAD "+" TO EXPAND]
; [0000003A BYTES: COLLAPSED FUNCTION _isdigit.	PRESS KEYPAD "+" TO EXPAND]
; [0000003F BYTES: COLLAPSED FUNCTION _isxdigit. PRESS KEYPAD "+" TO EXPAND]
; [0000003A BYTES: COLLAPSED FUNCTION _isspace.	PRESS KEYPAD "+" TO EXPAND]
; [000000E1 BYTES: COLLAPSED FUNCTION __filbuf.	PRESS KEYPAD "+" TO EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION _ungetc. PRESS KEYPAD "+"	TO EXPAND]
; [000000C0 BYTES: COLLAPSED FUNCTION ___mbtowc_mt. PRESS KEYPAD "+" TO	EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION _mbtowc. PRESS KEYPAD "+"	TO EXPAND]
; [00000043 BYTES: COLLAPSED FUNCTION ___ansicp. PRESS KEYPAD "+" TO EXPAND]
; [000001C9 BYTES: COLLAPSED FUNCTION ___convertcp. PRESS KEYPAD "+" TO	EXPAND]
; [00000190 BYTES: COLLAPSED FUNCTION __free_lc_time. PRESS KEYPAD "+" TO EXPAND]
; [0000005F BYTES: COLLAPSED FUNCTION ___free_lconv_num. PRESS KEYPAD "+" TO EXPAND]
; [000000D9 BYTES: COLLAPSED FUNCTION ___free_lconv_mon. PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000039 BYTES: COLLAPSED FUNCTION _strncmp.	PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000040 BYTES: COLLAPSED FUNCTION _strpbrk.	PRESS KEYPAD "+" TO EXPAND]
; [000000C8 BYTES: COLLAPSED FUNCTION ___tolower_mt. PRESS KEYPAD "+" TO EXPAND]



; int __cdecl sub_1000C3A8(WORD	CharType)
sub_1000C3A8 proc near

CharType= word ptr  4

call	__getptd
mov	eax, [eax+64h]
cmp	eax, off_1001DE24
jz	short loc_1000C3BD
call	___updatetlocinfo

loc_1000C3BD:		; CharType
push	dword ptr [esp+CharType]
push	eax		; MultiByteStr
call	___tolower_mt
pop	ecx
pop	ecx
retn
sub_1000C3A8 endp

; [00000032 BYTES: COLLAPSED FUNCTION __ZeroTail. PRESS	KEYPAD "+" TO EXPAND]
; [0000004D BYTES: COLLAPSED FUNCTION __IncMan.	PRESS KEYPAD "+" TO EXPAND]
; [00000072 BYTES: COLLAPSED FUNCTION __RoundMan. PRESS	KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION __CopyMan. PRESS KEYPAD "+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION __IsZeroMan. PRESS KEYPAD	"+" TO EXPAND]
; [0000007B BYTES: COLLAPSED FUNCTION __ShrMan.	PRESS KEYPAD "+" TO EXPAND]
; [00000158 BYTES: COLLAPSED FUNCTION __ld12cvt. PRESS KEYPAD "+" TO EXPAND]



sub_1000C6C2 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	offset unk_1001E420
push	[esp+4+arg_4]
push	[esp+8+arg_0]
call	__ld12cvt
add	esp, 0Ch
retn
sub_1000C6C2 endp




sub_1000C6D8 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	offset unk_1001E438
push	[esp+4+arg_4]
push	[esp+8+arg_0]
call	__ld12cvt
add	esp, 0Ch
retn
sub_1000C6D8 endp



; Attributes: bp-based frame

sub_1000C6EE proc near

var_14=	byte ptr -14h
var_10=	byte ptr -10h
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 14h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
xor	eax, eax
push	eax
push	eax
push	eax
push	eax
push	[ebp+arg_4]
lea	eax, [ebp+var_14]
push	eax
lea	eax, [ebp+var_10]
push	eax
call	___strgtold12
push	[ebp+arg_0]
lea	eax, [ebp+var_10]
push	eax
call	sub_1000C6C2
mov	ecx, [ebp+var_4]
add	esp, 24h
call	sub_10003E65
leave
retn
sub_1000C6EE endp



; Attributes: bp-based frame

sub_1000C72B proc near

var_14=	byte ptr -14h
var_10=	byte ptr -10h
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 14h
mov	eax, dword_1001D870
mov	[ebp+var_4], eax
xor	eax, eax
push	eax
push	eax
push	eax
push	eax
push	[ebp+arg_4]
lea	eax, [ebp+var_14]
push	eax
lea	eax, [ebp+var_10]
push	eax
call	___strgtold12
push	[ebp+arg_0]
lea	eax, [ebp+var_10]
push	eax
call	sub_1000C6D8
mov	ecx, [ebp+var_4]
add	esp, 24h
call	sub_10003E65
leave
retn
sub_1000C72B endp

; [00000077 BYTES: COLLAPSED FUNCTION __fptostr. PRESS KEYPAD "+" TO EXPAND]
; [000000BA BYTES: COLLAPSED FUNCTION ___dtold.	PRESS KEYPAD "+" TO EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION __fltout2. PRESS KEYPAD "+" TO EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION __fptrap.	PRESS KEYPAD "+" TO EXPAND]
db  59h	; Y
db 0C3h	; Ã
; [00000092 BYTES: COLLAPSED FUNCTION __abstract_cw. PRESS KEYPAD "+" TO EXPAND]
; [0000008E BYTES: COLLAPSED FUNCTION __hw_cw. PRESS KEYPAD "+"	TO EXPAND]
; [00000032 BYTES: COLLAPSED FUNCTION __control87. PRESS KEYPAD	"+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION __controlfp. PRESS KEYPAD	"+" TO EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION _siglookup. PRESS	KEYPAD "+" TO EXPAND]
; [00000171 BYTES: COLLAPSED FUNCTION _raise. PRESS KEYPAD "+" TO EXPAND]
; [00000008 BYTES: COLLAPSED CHUNK OF FUNCTION _raise. PRESS KEYPAD "+"	TO EXPAND]
; [0000007F BYTES: COLLAPSED FUNCTION __free_osfhnd. PRESS KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION __get_osfhandle. PRESS KEYPAD "+"	TO EXPAND]
; [000000A0 BYTES: COLLAPSED FUNCTION __lock_fhandle. PRESS KEYPAD "+" TO EXPAND]
; [00000022 BYTES: COLLAPSED FUNCTION __unlock_fhandle.	PRESS KEYPAD "+" TO EXPAND]
; [00000083 BYTES: COLLAPSED FUNCTION __lseeki64_lk. PRESS KEYPAD "+" TO EXPAND]
; [0000009B BYTES: COLLAPSED FUNCTION __fcloseall. PRESS KEYPAD	"+" TO EXPAND]
; [0000005D BYTES: COLLAPSED FUNCTION __flush. PRESS KEYPAD "+"	TO EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION __fflush_lk. PRESS KEYPAD	"+" TO EXPAND]
; [000000B1 BYTES: COLLAPSED FUNCTION _flsall. PRESS KEYPAD "+"	TO EXPAND]
; [00000024 BYTES: COLLAPSED CHUNK OF FUNCTION _flsall.	PRESS KEYPAD "+" TO EXPAND]



sub_1000D01D proc near
push	1
call	_flsall
pop	ecx
retn
sub_1000D01D endp

; [000001DB BYTES: COLLAPSED FUNCTION __read_lk. PRESS KEYPAD "+" TO EXPAND]
; [0000008F BYTES: COLLAPSED FUNCTION __read. PRESS KEYPAD "+" TO EXPAND]
; [0000001C BYTES: COLLAPSED CHUNK OF FUNCTION __read. PRESS KEYPAD "+"	TO EXPAND]
align 10h
; [0000004E BYTES: COLLAPSED FUNCTION ___ascii_stricmp.	PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION ___addl. PRESS KEYPAD "+"	TO EXPAND]
; [0000005E BYTES: COLLAPSED FUNCTION ___add_12. PRESS KEYPAD "+" TO EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION ___shl_12. PRESS KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION ___shr_12. PRESS KEYPAD "+" TO EXPAND]
; [000000DE BYTES: COLLAPSED FUNCTION ___mtold12. PRESS	KEYPAD "+" TO EXPAND]
; [00000404 BYTES: COLLAPSED FUNCTION ___strgtold12. PRESS KEYPAD "+" TO EXPAND]
off_1000D8BA dd	offset loc_1000D520 ; jump table for switch statement
dd offset loc_1000D573
dd offset loc_1000D5D4
dd offset loc_1000D5FF
dd offset loc_1000D63A
dd offset loc_1000D692
dd offset loc_1000D6B2
dd offset loc_1000D73F
dd offset loc_1000D6EA
dd offset loc_1000D7A4
dd offset loc_1000D78C
dd offset loc_1000D75C
; [0000028E BYTES: COLLAPSED FUNCTION _$I10_OUTPUT. PRESS KEYPAD "+" TO	EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION __fclose_lk. PRESS KEYPAD	"+" TO EXPAND]
; [00000051 BYTES: COLLAPSED FUNCTION _fclose. PRESS KEYPAD "+"	TO EXPAND]
; [000000BC BYTES: COLLAPSED FUNCTION __commit.	PRESS KEYPAD "+" TO EXPAND]
align 10h
; [00000061 BYTES: COLLAPSED FUNCTION ___ascii_strnicmp. PRESS KEYPAD "+" TO EXPAND]
; [00000232 BYTES: COLLAPSED FUNCTION ___ld12mul. PRESS	KEYPAD "+" TO EXPAND]
; [00000086 BYTES: COLLAPSED FUNCTION ___multtenpow12. PRESS KEYPAD "+"	TO EXPAND]
; [00000083 BYTES: COLLAPSED FUNCTION __close_lk. PRESS	KEYPAD "+" TO EXPAND]
; [0000007F BYTES: COLLAPSED FUNCTION __close. PRESS KEYPAD "+"	TO EXPAND]
; [0000001C BYTES: COLLAPSED CHUNK OF FUNCTION __close.	PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION __freebuf. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION ClosePrinter. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION DocumentPropertiesA. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION OpenPrinterA. PRESS KEYPAD "+" TO	EXPAND]
; START	OF FUNCTION CHUNK FOR sub_10016A9F

unknown_libname_19:	; MFC 3.1-10.0 32bit
push	esi
mov	esi, ecx
mov	eax, [esi]
test	eax, eax
jz	short loc_1000E167
push	eax		; void *
call	_free
and	dword ptr [esi], 0
pop	ecx

loc_1000E167:
and	dword ptr [esi+4], 0
and	dword ptr [esi+8], 0
pop	esi
retn
; END OF FUNCTION CHUNK	FOR sub_10016A9F



sub_1000E171 proc near
push	esi
mov	esi, ecx
lea	ecx, [esi+18h]	; void *
call	??0CComCriticalSection@ATL@@QAE@XZ ; ATL::CComCriticalSection::CComCriticalSection(void)
xor	eax, eax
mov	[esi+30h], eax
mov	[esi+34h], eax
mov	[esi+38h], eax
mov	eax, esi
pop	esi
retn
sub_1000E171 endp

; START	OF FUNCTION CHUNK FOR sub_10016A9F

loc_1000E18B:
push	esi
mov	esi, ecx
lea	eax, [esi+18h]
push	eax		; lpCriticalSection
call	ds:DeleteCriticalSection
lea	ecx, [esi+30h]
pop	esi
jmp	unknown_libname_19 ; MFC 3.1-10.0 32bit
; END OF FUNCTION CHUNK	FOR sub_10016A9F


; Attributes: bp-based frame fpd=78h

sub_1000E1A1 proc near

VersionInformation= _OSVERSIONINFOA ptr	-98h
var_4= dword ptr -4

push	ebp
lea	ebp, [esp-78h]
sub	esp, 98h
mov	eax, dword_1001D870
push	esi
mov	[ebp+78h+var_4], eax
mov	esi, ecx
call	sub_1000E171
mov	eax, offset __ImageBase
push	94h		; size_t
mov	[esi+8], eax
mov	[esi+4], eax
lea	eax, [ebp+78h+VersionInformation]
push	0		; int
push	eax		; void *
mov	dword ptr [esi], 3Ch
mov	byte ptr [esi+0Ch], 0
call	_memset
add	esp, 0Ch
lea	eax, [ebp+78h+VersionInformation]
push	eax		; lpVersionInformation
mov	[ebp+78h+VersionInformation.dwOSVersionInfoSize], 94h
call	ds:GetVersionExA
cmp	[ebp+78h+VersionInformation.dwPlatformId], 2
jnz	short loc_1000E203
cmp	[ebp+78h+VersionInformation.dwMajorVersion], 5
jb	short loc_1000E21B
jmp	short loc_1000E217

loc_1000E203:
cmp	[ebp+78h+VersionInformation.dwPlatformId], 1
jnz	short loc_1000E21B
cmp	[ebp+78h+VersionInformation.dwMajorVersion], 4
ja	short loc_1000E217
jnz	short loc_1000E21B
cmp	[ebp+78h+VersionInformation.dwMinorVersion], 0
jbe	short loc_1000E21B

loc_1000E217:
mov	byte ptr [esi+0Ch], 1

loc_1000E21B:
lea	ecx, [esi+18h]
mov	dword ptr [esi+10h], 710h
mov	dword ptr [esi+14h], offset unk_10019A60
call	?Init@CComCriticalSection@ATL@@QAEJXZ ;	ATL::CComCriticalSection::Init(void)
test	eax, eax
jge	short loc_1000E23C
mov	byte_1001E7C0, 1

loc_1000E23C:
mov	ecx, [ebp+78h+var_4]
mov	eax, esi
pop	esi
call	sub_10003E65
add	ebp, 78h
leave
retn
sub_1000E1A1 endp

mov	eax, offset __imp_CreateStdAccessibleObject
jmp	$+5

loc_1000E256:
push	ecx
push	edx
push	eax
push	offset OLEACC_dll_import_table
call	sub_1000E284
pop	edx
pop	ecx
jmp	eax
; [00000006 BYTES: COLLAPSED FUNCTION CreateStdAccessibleObject. PRESS KEYPAD "+" TO EXPAND]
mov	eax, offset __imp_LresultFromObject
jmp	loc_1000E256
; [00000006 BYTES: COLLAPSED FUNCTION LresultFromObject. PRESS KEYPAD "+" TO EXPAND]
align 2
; [00000006 BYTES: COLLAPSED FUNCTION RtlUnwind. PRESS KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

; int __stdcall	sub_1000E284(int, ULONG_PTR Arguments)
sub_1000E284 proc near

var_44=	dword ptr -44h
var_40=	dword ptr -40h
var_3C=	dword ptr -3Ch
lpLibFileName= dword ptr -38h
var_34=	dword ptr -34h
lpProcName= dword ptr -30h
var_2C=	dword ptr -2Ch
var_28=	dword ptr -28h
var_24=	dword ptr -24h
Target=	dword ptr -18h
var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8
Arguments= dword ptr  0Ch

push	ebp
mov	ebp, esp
sub	esp, 44h
push	ebx
mov	eax, offset __ImageBase
push	esi
mov	esi, [ebp+arg_0]
mov	edx, [esi+8]
mov	ecx, [esi+4]
mov	ebx, [esi+0Ch]
add	edx, eax
push	edi
mov	edi, [esi+14h]
add	edi, eax
add	ecx, eax
mov	[ebp+Target], edx
mov	edx, [esi+10h]
add	ebx, eax
add	edx, eax
mov	eax, [esi+1Ch]
mov	[ebp+var_4], eax
mov	eax, [ebp+Arguments]
mov	[ebp+lpLibFileName], ecx
xor	ecx, ecx
mov	[ebp+var_C], edi
mov	[ebp+var_3C], eax
xor	eax, eax
test	dword ptr [esi], 1
lea	edi, [ebp+lpProcName]
mov	[ebp+var_44], 24h
mov	[ebp+var_40], esi
mov	[ebp+var_34], ecx
stosd
mov	[ebp+var_2C], ecx
mov	[ebp+var_28], ecx
mov	[ebp+var_24], ecx
jnz	short loc_1000E308
lea	eax, [ebp+var_44]
mov	[ebp+Arguments], eax
lea	eax, [ebp+Arguments]
push	eax		; lpArguments
push	1		; nNumberOfArguments
push	ecx		; dwExceptionFlags
push	0C06D0057h	; dwExceptionCode
call	ds:RaiseException
xor	eax, eax
jmp	loc_1000E4C0

loc_1000E308:
mov	eax, [ebp+Target]
mov	edi, [eax]
mov	eax, [ebp+Arguments]
sub	eax, ebx
sar	eax, 2
shl	eax, 2
add	edx, eax
mov	edx, [edx]
mov	[ebp+arg_0], eax
mov	eax, edx
shr	eax, 1Fh
not	eax
and	eax, 1
mov	[ebp+var_34], eax
jz	short loc_1000E339
lea	eax, unk_10000002[edx]
mov	[ebp+lpProcName], eax
jmp	short loc_1000E342

loc_1000E339:
and	edx, 0FFFFh
mov	[ebp+lpProcName], edx

loc_1000E342:
mov	eax, dword_10020C60
xor	ebx, ebx
cmp	eax, ecx
jz	short loc_1000E35E
lea	edx, [ebp+var_44]
push	edx
push	ecx
call	eax ; dword_10020C60
mov	ebx, eax
test	ebx, ebx
jnz	loc_1000E4A3

loc_1000E35E:
test	edi, edi
jnz	loc_1000E408
mov	eax, dword_10020C60
test	eax, eax
jz	short loc_1000E37D
lea	ecx, [ebp+var_44]
push	ecx
push	1
call	eax ; dword_10020C60
mov	edi, eax
test	edi, edi
jnz	short loc_1000E3CD

loc_1000E37D:		; lpLibFileName
push	[ebp+lpLibFileName]
call	ds:LoadLibraryA
mov	edi, eax
test	edi, edi
jnz	short loc_1000E3CD
call	ds:GetLastError
mov	[ebp+var_24], eax
mov	eax, dword_10020C5C
test	eax, eax
jz	short loc_1000E3AC
lea	ecx, [ebp+var_44]
push	ecx
push	3
call	eax ; dword_10020C5C
mov	edi, eax
test	edi, edi
jnz	short loc_1000E3CD

loc_1000E3AC:
lea	eax, [ebp+var_44]
mov	[ebp+Arguments], eax
lea	eax, [ebp+Arguments]
push	eax		; lpArguments
push	1		; nNumberOfArguments
push	0		; dwExceptionFlags
push	0C06D007Eh	; dwExceptionCode
call	ds:RaiseException
mov	eax, [ebp+var_28]
jmp	loc_1000E4C0

loc_1000E3CD:		; Value
push	edi
push	[ebp+Target]	; Target
call	ds:InterlockedExchange
cmp	eax, edi
jz	short loc_1000E401
cmp	dword ptr [esi+18h], 0
jz	short loc_1000E408
push	8		; uBytes
push	40h		; uFlags
call	ds:LocalAlloc
test	eax, eax
jz	short loc_1000E408
mov	[eax+4], esi
mov	ecx, dword_10020C58
mov	[eax], ecx
mov	dword_10020C58,	eax
jmp	short loc_1000E408

loc_1000E401:		; hLibModule
push	edi
call	ds:FreeLibrary

loc_1000E408:
mov	eax, dword_10020C60
test	eax, eax
mov	[ebp+var_2C], edi
jz	short loc_1000E41E
lea	ecx, [ebp+var_44]
push	ecx
push	2
call	eax ; dword_10020C60
mov	ebx, eax

loc_1000E41E:
test	ebx, ebx
jnz	short loc_1000E49E
cmp	[esi+14h], ebx
jz	short loc_1000E453
cmp	[esi+1Ch], ebx
jz	short loc_1000E453
mov	eax, [edi+3Ch]
add	eax, edi
cmp	dword ptr [eax], 4550h
jnz	short loc_1000E453
mov	ecx, [ebp+var_4]
cmp	[eax+8], ecx
jnz	short loc_1000E453
cmp	edi, [eax+34h]
jnz	short loc_1000E453
mov	eax, [ebp+var_C]
mov	ecx, [ebp+arg_0]
mov	ebx, [ecx+eax]
test	ebx, ebx
jnz	short loc_1000E49E

loc_1000E453:		; lpProcName
push	[ebp+lpProcName]
push	edi		; hModule
call	ds:GetProcAddress
mov	ebx, eax
test	ebx, ebx
jnz	short loc_1000E49E
call	ds:GetLastError
mov	[ebp+var_24], eax
mov	eax, dword_10020C5C
test	eax, eax
jz	short loc_1000E47F
lea	ecx, [ebp+var_44]
push	ecx
push	4
call	eax ; dword_10020C5C
mov	ebx, eax

loc_1000E47F:
test	ebx, ebx
jnz	short loc_1000E49E
lea	eax, [ebp+var_44]
mov	[ebp+arg_0], eax
lea	eax, [ebp+arg_0]
push	eax		; lpArguments
push	1		; nNumberOfArguments
push	ebx		; dwExceptionFlags
push	0C06D007Fh	; dwExceptionCode
call	ds:RaiseException
mov	ebx, [ebp+var_28]

loc_1000E49E:
mov	eax, [ebp+Arguments]
mov	[eax], ebx

loc_1000E4A3:
mov	eax, dword_10020C60
test	eax, eax
jz	short loc_1000E4BE
and	[ebp+var_24], 0
lea	ecx, [ebp+var_44]
push	ecx
push	5
mov	[ebp+var_2C], edi
mov	[ebp+var_28], ebx
call	eax ; dword_10020C60

loc_1000E4BE:
mov	eax, ebx

loc_1000E4C0:
pop	edi
pop	esi
pop	ebx
leave
retn	8
sub_1000E284 endp

; [00000029 BYTES: COLLAPSED FUNCTION CSimpleException::InitString(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000050 BYTES: COLLAPSED FUNCTION CSimpleException::GetErrorMessage(char *,uint,uint *). PRESS KEYPAD "+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION unknown_libname_20. PRESS	KEYPAD "+" TO EXPAND]
align 2
; [0000003A BYTES: COLLAPSED FUNCTION unknown_libname_21. PRESS	KEYPAD "+" TO EXPAND]
; [00000022 BYTES: COLLAPSED FUNCTION unknown_libname_22. PRESS	KEYPAD "+" TO EXPAND]



sub_1000E5B6 proc near
mov	eax, [ecx+4]
mov	edx, [eax]
test	edx, edx
push	esi
mov	esi, [eax+8]
mov	[ecx+4], edx
jz	short loc_1000E5CC
and	dword ptr [edx+4], 0
jmp	short loc_1000E5D0

loc_1000E5CC:
and	dword ptr [ecx+8], 0

loc_1000E5D0:
push	eax
call	unknown_libname_22 ; MFC 3.1-10.0 32bit
mov	eax, esi
pop	esi
retn
sub_1000E5B6 endp

; [00000030 BYTES: COLLAPSED FUNCTION unknown_libname_23. PRESS	KEYPAD "+" TO EXPAND]
db 0CCh
; [00000016 BYTES: COLLAPSED FUNCTION CPlex::FreeDataChain(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000105 BYTES: COLLAPSED FUNCTION CByteArray::SetSize(int,int). PRESS KEYPAD "+" TO	EXPAND]
; START	OF FUNCTION CHUNK FOR sub_100163F0

loc_1000E726:
mov	eax, ecx
xor	ecx, ecx
mov	dword ptr [eax], offset	off_100187F4
mov	[eax+4], ecx
mov	[eax+10h], ecx
mov	[eax+0Ch], ecx
mov	[eax+8], ecx
retn
; END OF FUNCTION CHUNK	FOR sub_100163F0
; [00000010 BYTES: COLLAPSED FUNCTION Concurrency::details::_Concurrent_queue_base_v4::~_Concurrent_queue_base_v4(void). PRESS KEYPAD "+" TO EXPAND]
; [0000007D BYTES: COLLAPSED FUNCTION CByteArray::Serialize(CArchive &). PRESS KEYPAD "+" TO EXPAND]



; int __thiscall sub_1000E7CA(void *, char)
sub_1000E7CA proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1_Concurrent_queue_base_v4@details@Concurrency@@MAE@XZ ; Concurrency::details::_Concurrent_queue_base_v4::~_Concurrent_queue_base_v4(void)
test	[esp+4+arg_0], 1
jz	short loc_1000E7E0
push	esi		; void *
call	j__free
pop	ecx

loc_1000E7E0:
mov	eax, esi
pop	esi
retn	4
sub_1000E7CA endp

; [0000004C BYTES: COLLAPSED FUNCTION unknown_libname_24. PRESS	KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION sub_1000E832. PRESS KEYPAD "+" TO	EXPAND]



sub_1000E85D proc near

arg_0= dword ptr  4

mov	edx, [ecx+10h]
mov	eax, [esp+arg_0]
mov	[eax], edx
dec	dword ptr [ecx+0Ch]
mov	[ecx+10h], eax
jnz	short locret_1000E873
call	sub_1000E832	; ?RemoveAll@CMapPtrToPtr@@QAEXXZ
			; doubtful name

locret_1000E873:
retn	4
sub_1000E85D endp

; [00000038 BYTES: COLLAPSED FUNCTION unknown_libname_25. PRESS	KEYPAD "+" TO EXPAND]
; [00000037 BYTES: COLLAPSED FUNCTION CMapPtrToPtr::GetValueAt(void *).	PRESS KEYPAD "+" TO EXPAND]



sub_1000E8E5 proc near

arg_0= dword ptr  4

push	esi
mov	esi, [ecx+4]
test	esi, esi
jnz	short loc_1000E8F1
xor	eax, eax
jmp	short loc_1000E915

loc_1000E8F1:
push	edi
mov	edi, [esp+8+arg_0]
mov	eax, edi
shr	eax, 4
xor	edx, edx
div	dword ptr [ecx+8]
lea	edx, [esi+edx*4]
mov	eax, [edx]
jmp	short loc_1000E910

loc_1000E907:
cmp	[eax+4], edi
jz	short loc_1000E919
mov	edx, eax
mov	eax, [eax]

loc_1000E910:
test	eax, eax
jnz	short loc_1000E907

loc_1000E914:
pop	edi

loc_1000E915:
pop	esi
retn	4

loc_1000E919:
mov	esi, [eax]
push	eax
mov	[edx], esi
call	sub_1000E85D
xor	eax, eax
inc	eax
jmp	short loc_1000E914
sub_1000E8E5 endp

; [0000007A BYTES: COLLAPSED FUNCTION CMapPtrToPtr::GetNextAssoc(__POSITION * &,void * &,void *	&). PRESS KEYPAD "+" TO	EXPAND]



sub_1000E9A2 proc near

arg_0= dword ptr  4

mov	eax, ecx
mov	ecx, [esp+arg_0]
xor	edx, edx
cmp	ecx, edx
mov	dword ptr [eax], offset	off_10018754
jg	short loc_1000E9B7
push	0Ah
pop	ecx

loc_1000E9B7:
mov	[eax+4], edx
mov	dword ptr [eax+8], 11h
mov	[eax+0Ch], edx
mov	[eax+10h], edx
mov	[eax+14h], edx
mov	[eax+18h], ecx
retn	4
sub_1000E9A2 endp




sub_1000E9D0 proc near
mov	dword ptr [ecx], offset	off_10018754
jmp	sub_1000E832	; ?RemoveAll@CMapPtrToPtr@@QAEXXZ
sub_1000E9D0 endp	; doubtful name

; [0000004B BYTES: COLLAPSED FUNCTION CMapPtrToPtr::NewAssoc(void). PRESS KEYPAD "+" TO	EXPAND]


; Attributes: bp-based frame

sub_1000EA26 proc near

var_4= byte ptr	-4
arg_0= dword ptr  8

push	ebp
mov	ebp, esp
push	ecx
push	esi
push	edi
mov	edi, [ebp+arg_0]
lea	eax, [ebp+var_4]
push	eax
lea	eax, [ebp+arg_0]
push	eax
push	edi
mov	esi, ecx
call	unknown_libname_25 ; MFC 3.1-10.0 32bit
test	eax, eax
jnz	short loc_1000EA72
cmp	[esi+4], eax
jnz	short loc_1000EA54
push	1
push	dword ptr [esi+8]
mov	ecx, esi
call	unknown_libname_24 ; MFC 3.1-10.0 32bit

loc_1000EA54:
mov	ecx, esi
call	?NewAssoc@CMapPtrToPtr@@IAEPAUCAssoc@1@XZ ; CMapPtrToPtr::NewAssoc(void)
mov	ecx, [ebp+arg_0]
mov	[eax+4], edi
mov	edx, [esi+4]
shl	ecx, 2
mov	edx, [ecx+edx]
mov	[eax], edx
mov	edx, [esi+4]
mov	[ecx+edx], eax

loc_1000EA72:
pop	edi
add	eax, 8
pop	esi
leave
retn	4
sub_1000EA26 endp




; int __thiscall sub_1000EA7B(void *, char)
sub_1000EA7B proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_1000E9D0
test	[esp+4+arg_0], 1
jz	short loc_1000EA91
push	esi		; void *
call	j__free
pop	ecx

loc_1000EA91:
mov	eax, esi
pop	esi
retn	4
sub_1000EA7B endp




sub_1000EA97 proc near
mov	eax, offset off_10017548
retn
sub_1000EA97 endp

; [00000075 BYTES: COLLAPSED FUNCTION CWinApp::ProcessWndProcException(CException *,tagMSG const *). PRESS KEYPAD "+" TO EXPAND]
; [00000066 BYTES: COLLAPSED FUNCTION CWinApp::OnIdle(long). PRESS KEYPAD "+" TO EXPAND]
; [0000009E BYTES: COLLAPSED FUNCTION CWinApp::DevModeChange(char *). PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWinApp::Run(void). PRESS	KEYPAD "+" TO EXPAND]



sub_1000EC37 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	edi
mov	edi, ecx
call	?AfxGetMainWnd@@YGPAVCWnd@@XZ ;	AfxGetMainWnd(void)
mov	esi, eax
xor	eax, eax
push	eax		; lParam
push	eax		; wParam
push	36Ah		; Msg
mov	[edi+58h], eax
push	dword ptr [esi+1Ch] ; hWnd
call	ds:PostMessageA
push	[esp+8+arg_4]
mov	eax, [esi]
push	[esp+0Ch+arg_0]
mov	ecx, esi
call	dword ptr [eax+74h]
pop	edi
pop	esi
retn	8
sub_1000EC37 endp




sub_1000EC6B proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push	esi
push	edi
mov	edi, ecx
call	?AfxGetMainWnd@@YGPAVCWnd@@XZ ;	AfxGetMainWnd(void)
mov	esi, eax
xor	eax, eax
push	eax		; lParam
push	eax		; wParam
push	36Ah		; Msg
mov	[edi+58h], eax
push	dword ptr [esi+1Ch] ; hWnd
call	ds:PostMessageA
push	[esp+8+arg_4]
mov	eax, [esi]
push	[esp+0Ch+arg_0]
mov	ecx, esi
call	dword ptr [eax+78h]
pop	edi
pop	esi
retn	8
sub_1000EC6B endp

; [00000034 BYTES: COLLAPSED FUNCTION CWinApp::WinHelpInternal(ulong,uint). PRESS KEYPAD "+" TO	EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION AfxGetThread(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION AfxGetCurrentMessage(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION unknown_libname_26. PRESS	KEYPAD "+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION AfxProcessWndProcException(CException *,tagMSG const *). PRESS KEYPAD "+"	TO EXPAND]
; [00000084 BYTES: COLLAPSED FUNCTION AfxTermThread(HINSTANCE__	*). PRESS KEYPAD "+" TO	EXPAND]



sub_1000EDA4 proc near
mov	ecx, [ebp-14h]
call	?Delete@CException@@QAEXXZ ; CException::Delete(void)
mov	eax, offset loc_1000ED42
retn
sub_1000EDA4 endp




sub_1000EDB2 proc near
mov	ecx, [ebp-14h]
call	?Delete@CException@@QAEXXZ ; CException::Delete(void)
mov	eax, offset loc_1000ED78
retn
sub_1000EDB2 endp




sub_1000EDC0 proc near
mov	ecx, [ebp-14h]
call	?Delete@CException@@QAEXXZ ; CException::Delete(void)
mov	eax, offset loc_1000ED93
retn
sub_1000EDC0 endp

; [0000000E BYTES: COLLAPSED FUNCTION CWinThread::Delete(void).	PRESS KEYPAD "+" TO EXPAND]
; [0000008D BYTES: COLLAPSED FUNCTION CWinThread::Run(void). PRESS KEYPAD "+" TO EXPAND]



sub_1000EE69 proc near
call	?AfxGetThreadState@@YGPAV_AFX_THREAD_STATE@@XZ ; AfxGetThreadState(void)
mov	eax, [eax+38h]
retn
sub_1000EE69 endp

; [00000076 BYTES: COLLAPSED FUNCTION CWinThread::DispatchThreadMessageEx(tagMSG *). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION j_unknown_libname_26. PRESS KEYPAD "+" TO	EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION IsEnterKey(tagMSG	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION AfxInternalPreTranslateMessage(tagMSG *).	PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION AfxPreTranslateMessage(tagMSG *).	PRESS KEYPAD "+" TO EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION AfxInternalIsIdleMessage(tagMSG *). PRESS	KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION std::allocator<char>::allocate(uint). PRESS KEYPAD "+" TO	EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION std::allocator<char>::allocate(uint). PRESS KEYPAD "+" TO	EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION CWinThread::GetMainWnd(void). PRESS KEYPAD "+" TO	EXPAND]
; [00000044 BYTES: COLLAPSED FUNCTION AfxInternalPumpMessage(void). PRESS KEYPAD "+" TO	EXPAND]
; [00000059 BYTES: COLLAPSED FUNCTION _AfxMsgFilterHook(int,uint,long).	PRESS KEYPAD "+" TO EXPAND]
; [00000120 BYTES: COLLAPSED FUNCTION CWinThread::ProcessMessageFilter(int,tagMSG *). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION AfxInternalPumpMessage(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION AfxInitThread(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000109 BYTES: COLLAPSED FUNCTION CWinThread::OnIdle(long).	PRESS KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CCmdTarget::CCmdTarget(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION CCmdTarget::~CCmdTarget(void). PRESS KEYPAD "+" TO EXPAND]
; [000000E6 BYTES: COLLAPSED FUNCTION _AfxDispatchCmdMsg(CCmdTarget *,uint,int,void (CCmdTarget::*)(void),void *,uint,AFX_CMDHANDLERINFO *). PRESS KEYPAD "+" TO EXPAND]
off_1000F435 dd	offset loc_1000F386 ; jump table for switch statement
dd offset loc_1000F391
dd offset loc_1000F39C
dd offset loc_1000F3A1
dd offset loc_1000F3A6
dd offset loc_1000F3B6
dd offset loc_1000F3C6
dd offset loc_1000F3D9
dd offset loc_1000F3EC
dd offset loc_1000F3F8
dd offset loc_1000F413
dd offset loc_1000F41E
; [0000010C BYTES: COLLAPSED FUNCTION CCmdTarget::OnCmdMsg(uint,int,void *,AFX_CMDHANDLERINFO *). PRESS	KEYPAD "+" TO EXPAND]



sub_1000F571 proc near
xor	eax, eax
inc	eax
retn	4
sub_1000F571 endp

; [00000008 BYTES: COLLAPSED FUNCTION CCmdTarget::GetTypeLib(ulong,ITypeLib * *). PRESS	KEYPAD "+" TO EXPAND]



sub_1000F57F proc near
mov	eax, offset unk_10017958
retn
sub_1000F57F endp




sub_1000F585 proc near
mov	eax, offset unk_10017980
retn
sub_1000F585 endp




sub_1000F58B proc near
mov	eax, offset unk_100179B8
retn
sub_1000F58B endp




sub_1000F591 proc near
mov	eax, offset unk_100179D4
retn
sub_1000F591 endp

; [0000002E BYTES: COLLAPSED FUNCTION CCmdTarget::OnFinalRelease(void).	PRESS KEYPAD "+" TO EXPAND]



sub_1000F5C5 proc near
xor	eax, eax
inc	eax
retn
sub_1000F5C5 endp




sub_1000F5C9 proc near
mov	eax, offset unk_100179E4
retn
sub_1000F5C9 endp




sub_1000F5CF proc near
xor	eax, eax
retn	4
sub_1000F5CF endp




sub_1000F5D4 proc near
mov	eax, offset unk_100179F8
retn
sub_1000F5D4 endp

; [00000026 BYTES: COLLAPSED FUNCTION CCmdUI::CCmdUI(void). PRESS KEYPAD "+" TO	EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION CCmdTarget::BeginWaitCursor(void). PRESS KEYPAD "+" TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION CCmdTarget::EndWaitCursor(void). PRESS KEYPAD "+"	TO EXPAND]
; [0000007F BYTES: COLLAPSED FUNCTION CCmdUI::Enable(int). PRESS KEYPAD	"+" TO EXPAND]
; [00000065 BYTES: COLLAPSED FUNCTION CCmdUI::SetCheck(int). PRESS KEYPAD "+" TO EXPAND]
; [00000056 BYTES: COLLAPSED FUNCTION CCmdUI::SetRadio(int). PRESS KEYPAD "+" TO EXPAND]



; int __stdcall	sub_1000F764(LPCSTR lpString)
sub_1000F764 proc near

lpString= dword	ptr  4

push	esi
mov	esi, ecx
mov	eax, [esi+0Ch]
test	eax, eax
jz	short loc_1000F7A5
cmp	dword ptr [esi+10h], 0
jnz	short loc_1000F7B4
mov	ecx, [esi+8]
push	edi
mov	edi, 400h
push	edi		; uFlags
push	ecx		; uId
push	dword ptr [eax+4] ; hMenu
call	ds:GetMenuState
push	[esp+8+lpString] ; lpNewItem
mov	ecx, [esi+0Ch]
push	dword ptr [esi+4] ; uIDNewItem
and	eax, 0FFFFF6FBh
or	eax, edi
push	eax		; uFlags
push	dword ptr [esi+8] ; uPosition
call	sub_10002CD7
pop	edi
jmp	short loc_1000F7B4

loc_1000F7A5:		; lpString
push	[esp+4+lpString]
mov	eax, [esi+14h]
push	dword ptr [eax+1Ch] ; hWnd
call	?AfxSetWindowText@@YGXPAUHWND__@@PBD@Z ; AfxSetWindowText(HWND__ *,char	const *)

loc_1000F7B4:
pop	esi
retn	4
sub_1000F764 endp

; [00000005 BYTES: COLLAPSED FUNCTION j_unknown_libname_20. PRESS KEYPAD "+" TO	EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION AfxSetNewHandler(int (*)(uint)). PRESS KEYPAD "+"	TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION operator new(uint). PRESS	KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION j__free. PRESS KEYPAD "+"	TO EXPAND]
; [0000000E BYTES: COLLAPSED FUNCTION CException::Delete(void).	PRESS KEYPAD "+" TO EXPAND]
; [0000006E BYTES: COLLAPSED FUNCTION CException::ReportError(uint,uint). PRESS	KEYPAD "+" TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION CException::CException(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION CException::CException(int). PRESS KEYPAD	"+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION AfxLockTempMaps(void). PRESS KEYPAD "+" TO EXPAND]
; [00000084 BYTES: COLLAPSED FUNCTION CHandleMap::CHandleMap(CRuntimeClass *,void (*)(CObject *),void (*)(CObject *),uint,int).	PRESS KEYPAD "+" TO EXPAND]
; [000000B0 BYTES: COLLAPSED FUNCTION CHandleMap::FromHandle(void *). PRESS KEYPAD "+" TO EXPAND]


; Attributes: noreturn

sub_1000F9CE proc near
push	dword ptr [ebp+8] ; int	(__cdecl *)(unsigned int)
call	?AfxSetNewHandler@@YGP6AHI@ZP6AHI@Z@Z ;	AfxSetNewHandler(int (*)(uint))
push	0
push	0
call	__CxxThrowException@8 ;	_CxxThrowException(x,x)
sub_1000F9CE endp

align 10h
; [00000063 BYTES: COLLAPSED FUNCTION CHandleMap::DeleteTemp(void). PRESS KEYPAD "+" TO	EXPAND]
; [000000F9 BYTES: COLLAPSED FUNCTION AfxUnlockTempMaps(int). PRESS KEYPAD "+" TO EXPAND]
; [00000022 BYTES: COLLAPSED CHUNK OF FUNCTION CObject::IsKindOf(CRuntimeClass const *). PRESS KEYPAD "+" TO EXPAND]
; [0000000B BYTES: COLLAPSED FUNCTION CObject::IsKindOf(CRuntimeClass const *).	PRESS KEYPAD "+" TO EXPAND]
; [00000026 BYTES: COLLAPSED FUNCTION AfxClassInit(CRuntimeClass *). PRESS KEYPAD "+" TO EXPAND]



sub_1000FB8F proc near
mov	eax, offset unk_1001ED18
retn
sub_1000FB8F endp

; [0000003B BYTES: COLLAPSED FUNCTION CAfxStringMgr::Allocate(int,int).	PRESS KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION std::allocator<char>::allocate(uint). PRESS KEYPAD "+" TO	EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION CAfxStringMgr::Reallocate(ATL::CStringData *,int,int). PRESS KEYPAD "+" TO EXPAND]



sub_1000FC0C proc near
mov	eax, ecx
retn
sub_1000FC0C endp

; [00000026 BYTES: COLLAPSED FUNCTION CAfxStringMgr::CAfxStringMgr(void). PRESS	KEYPAD "+" TO EXPAND]
; [0000000E BYTES: COLLAPSED FUNCTION CAfxStringMgr::GetNilString(void). PRESS KEYPAD "+" TO EXPAND]



sub_1000FC43 proc near
mov	ecx, offset unk_1001ED18
jmp	??0CAfxStringMgr@@QAE@XZ ; CAfxStringMgr::CAfxStringMgr(void)
sub_1000FC43 endp

; [00000044 BYTES: COLLAPSED FUNCTION AUX_DATA::UpdateSysColors(void). PRESS KEYPAD "+"	TO EXPAND]
; [0000005A BYTES: COLLAPSED FUNCTION AUX_DATA::UpdateSysMetrics(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000008 BYTES: COLLAPSED FUNCTION CWnd::OnAmbientProperty(COleControlSite *,long,tagVARIANT	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CWnd::GetStyle(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CWnd::GetExStyle(void). PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::ShowWindow(int). PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION CWnd::IsWindowEnabled(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::EnableWindow(int). PRESS KEYPAD "+"	TO EXPAND]
; [0000003C BYTES: COLLAPSED FUNCTION CWnd::SetWindowPos(CWnd const *,int,int,int,int,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION CWnd::AttachControlSite(CHandleMap *). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION CProcessLocalObject::~CProcessLocalObject(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION CWnd::CWnd(HWND__	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_3. PRESS KEYPAD "+" TO EXPAND]
; [00000011 BYTES: COLLAPSED FUNCTION CWnd::OnFinalRelease(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000047 BYTES: COLLAPSED FUNCTION CWnd::DefWindowProcA(uint,uint,long). PRESS KEYPAD "+" TO	EXPAND]



sub_1000FEA5 proc near
lea	eax, [ecx+3Ch]
retn
sub_1000FEA5 endp

; [0000001F BYTES: COLLAPSED FUNCTION CWnd::PreTranslateMessage(tagMSG *). PRESS KEYPAD	"+" TO EXPAND]
; [00000071 BYTES: COLLAPSED FUNCTION CWnd::OnToolHitTest(CPoint,tagTOOLINFOA *). PRESS	KEYPAD "+" TO EXPAND]
; [000000F1 BYTES: COLLAPSED FUNCTION AfxRegisterClass(tagWNDCLASSA *).	PRESS KEYPAD "+" TO EXPAND]


; Attributes: noreturn

sub_1001002A proc near
push	1		; int
call	?AfxUnlockGlobals@@YGXH@Z ; AfxUnlockGlobals(int)
push	0
push	0
call	__CxxThrowException@8 ;	_CxxThrowException(x,x)
sub_1001002A endp

db 0CCh



sub_1001003B proc near
mov	dword ptr [ecx], offset	off_10018580
mov	ecx, [ecx+4]
test	ecx, ecx
jz	short locret_1001004F
push	ecx		; hLibModule
call	ds:FreeLibrary

locret_1001004F:
retn
sub_1001003B endp




; int __thiscall sub_10010050(void *, char)
sub_10010050 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	sub_1001003B
test	[esp+4+arg_0], 1
jz	short loc_10010065
push	esi		; void *
call	??3CNoTrackObject@@SGXPAX@Z ; CNoTrackObject::operator delete(void *)

loc_10010065:
mov	eax, esi
pop	esi
retn	4
sub_10010050 endp




sub_1001006B proc near
mov	eax, offset off_10017E10
retn
sub_1001006B endp

; [00000040 BYTES: COLLAPSED FUNCTION sub_10010071. PRESS KEYPAD "+" TO	EXPAND]
; [00000044 BYTES: COLLAPSED FUNCTION CWnd::WindowProc(uint,uint,long).	PRESS KEYPAD "+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION CTestCmdUI::CTestCmdUI(void). PRESS KEYPAD "+" TO	EXPAND]
; [00000011 BYTES: COLLAPSED FUNCTION CTestCmdUI::Enable(int). PRESS KEYPAD "+"	TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION CWnd::CalcWindowRect(tagRECT *,uint). PRESS KEYPAD "+" TO	EXPAND]



sub_1001014C proc near
mov	eax, offset off_10017E00
retn
sub_1001014C endp

; [0000000F BYTES: COLLAPSED FUNCTION unknown_libname_27. PRESS	KEYPAD "+" TO EXPAND]
; [0000000F BYTES: COLLAPSED FUNCTION unknown_libname_28. PRESS	KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION unknown_libname_29. PRESS	KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::Invoke(long,_GUID const &,ulong,ushort,tagDISPPARAMS *,tagVARIANT *,tagEXCEPINFO *,uint *). PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION CWnd::XAccessible::GetIDsOfNames(_GUID const &,wchar_t * *,uint,ulong,long *). PRESS KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CWnd::XAccessible::GetTypeInfoCount(uint *). PRESS KEYPAD	"+" TO EXPAND]



sub_100101C5 proc near
mov	eax, 80004001h
retn	10h
sub_100101C5 endp

; [00000016 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accParent(IDispatch * *). PRESS KEYPAD "+"	TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accChildCount(long	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accChild(tagVARIANT,IDispatch * *). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accName(tagVARIANT,wchar_t	* *). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accValue(tagVARIANT,wchar_t * *). PRESS KEYPAD "+"	TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accDescription(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accRole(tagVARIANT,tagVARIANT *). PRESS KEYPAD "+"	TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accState(tagVARIANT,tagVARIANT *).	PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accHelp(tagVARIANT,wchar_t	* *). PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accHelpTopic(wchar_t * *,tagVARIANT,long *). PRESS	KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accKeyboardShortcut(tagVARIANT,wchar_t * *). PRESS	KEYPAD "+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accFocus(tagVARIANT *). PRESS KEYPAD "+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accSelection(tagVARIANT *). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::get_accDefaultAction(tagVARIANT,wchar_t * *). PRESS KEYPAD "+"	TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::accSelect(long,tagVARIANT). PRESS KEYPAD "+" TO EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::accLocation(long *,long *,long	*,long *,tagVARIANT). PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION CWnd::XAccessible::accNavigate(long,tagVARIANT,tagVARIANT	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION CWnd::XAccessible::accHitTest(long,long,tagVARIANT *). PRESS KEYPAD "+" TO EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::accDoDefaultAction(tagVARIANT). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::put_accName(tagVARIANT,wchar_t	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::XAccessible::put_accValue(tagVARIANT,wchar_t *). PRESS KEYPAD "+" TO EXPAND]
; [0000000F BYTES: COLLAPSED FUNCTION COleDataSource::XDataObject::AddRef(void). PRESS KEYPAD "+" TO EXPAND]



sub_100104D0 proc near

arg_0= dword ptr  4

mov	ecx, [esp+arg_0]
add	ecx, 0FFFFFFD0h
call	?ExternalRelease@CCmdTarget@@QAEKXZ ; CCmdTarget::ExternalRelease(void)
retn	4
sub_100104D0 endp

; [00000017 BYTES: COLLAPSED FUNCTION COleDataSource::XDataObject::QueryInterface(_GUID	const &,void * *). PRESS KEYPAD	"+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION CWnd::XAccessibleServer::SetProxy(IAccessibleProxy *). PRESS KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION CWnd::XAccessibleServer::GetHWND(HWND__ *	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CWnd::XAccessibleServer::GetEnumVariant(IEnumVARIANT * *). PRESS KEYPAD "+" TO EXPAND]
; [0000001F BYTES: COLLAPSED FUNCTION CWnd::EnsureStdObj(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION CWnd::get_accParent(IDispatch * *). PRESS	KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION CWnd::get_accChildCount(long *). PRESS KEYPAD "+"	TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accChild(tagVARIANT,IDispatch *	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accName(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accValue(tagVARIANT,wchar_t * *). PRESS	KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accDescription(tagVARIANT,wchar_t * *).	PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accRole(tagVARIANT,tagVARIANT *). PRESS	KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accState(tagVARIANT,tagVARIANT *). PRESS KEYPAD	"+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accHelp(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION CWnd::get_accHelpTopic(wchar_t * *,tagVARIANT,long *). PRESS KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accKeyboardShortcut(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION CWnd::get_accFocus(tagVARIANT *).	PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION CWnd::get_accSelection(tagVARIANT	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::get_accDefaultAction(tagVARIANT,wchar_t * *). PRESS	KEYPAD "+" TO EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION CWnd::accSelect(long,tagVARIANT).	PRESS KEYPAD "+" TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION CWnd::accLocation(long *,long *,long *,long *,tagVARIANT). PRESS KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION CWnd::accNavigate(long,tagVARIANT,tagVARIANT *). PRESS KEYPAD "+"	TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION CWnd::accHitTest(long,long,tagVARIANT *).	PRESS KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION CWnd::accDoDefaultAction(tagVARIANT). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION unknown_libname_30. PRESS	KEYPAD "+" TO EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION CWnd::SetProxy(IAccessibleProxy *). PRESS	KEYPAD "+" TO EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION CWnd::ContinueModal(void). PRESS KEYPAD "+" TO EXPAND]
; [00000078 BYTES: COLLAPSED FUNCTION _AfxInitCommonControls(tagINITCOMMONCONTROLSEX *,long). PRESS KEYPAD "+" TO EXPAND]



sub_10010843 proc near
xor	eax, eax
retn
sub_10010843 endp

; [0000001F BYTES: COLLAPSED FUNCTION CFrameWnd::IsTracking(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION CWnd::CreateControlContainer(COleControlContainer	* *). PRESS KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION CWnd::CreateControlSite(COleControlContainer *,COleControlSite * *,uint,_GUID const &). PRESS KEYPAD "+" TO EXPAND]
; [00000043 BYTES: COLLAPSED FUNCTION CWnd::CWnd(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION _AfxPreInitDialog(CWnd *,tagRECT *,ulong *). PRESS KEYPAD	"+" TO EXPAND]
; [00000049 BYTES: COLLAPSED FUNCTION CWnd::CreateEx(ulong,char	const *,char const *,ulong,tagRECT const &,CWnd	*,uint,void *).	PRESS KEYPAD "+" TO EXPAND]
; [0000004E BYTES: COLLAPSED FUNCTION unknown_libname_31. PRESS	KEYPAD "+" TO EXPAND]
; [00000051 BYTES: COLLAPSED FUNCTION CWnd::CancelToolTips(int). PRESS KEYPAD "+" TO EXPAND]
; [0000005B BYTES: COLLAPSED FUNCTION _AfxFindPopupMenuFromID(CMenu *,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000051 BYTES: COLLAPSED FUNCTION CWnd::WinHelpInternal(ulong,uint). PRESS KEYPAD "+" TO EXPAND]
; [0000001F BYTES: COLLAPSED FUNCTION CWnd::OnActivateTopLevel(uint,long). PRESS KEYPAD	"+" TO EXPAND]
; START	OF FUNCTION CHUNK FOR sub_100169A7

unknown_libname_32:	; MFC 3.1-10.0 32bit
mov	eax, [ecx]
test	eax, eax
jz	short locret_10010AA4
mov	ecx, [eax]
push	eax
call	dword ptr [ecx+8]

locret_10010AA4:
retn
; END OF FUNCTION CHUNK	FOR sub_100169A7
; [000001B5 BYTES: COLLAPSED FUNCTION CWnd::CenterWindow(CWnd *). PRESS	KEYPAD "+" TO EXPAND]
; [00000025 BYTES: COLLAPSED FUNCTION CWnd::EndModalLoop(int). PRESS KEYPAD "+"	TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION unknown_libname_33. PRESS	KEYPAD "+" TO EXPAND]
; [000002CF BYTES: COLLAPSED FUNCTION AfxEndDeferRegisterClass(long). PRESS KEYPAD "+" TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION CWnd::GetCurrentMessage(void). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::Default(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000007C BYTES: COLLAPSED FUNCTION afxMapHWND(int). PRESS KEYPAD "+"	TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::FromHandle(HWND__ *). PRESS	KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CWnd::FromHandlePermanent(HWND__ *). PRESS KEYPAD	"+" TO EXPAND]
; [00000039 BYTES: COLLAPSED FUNCTION CWnd::Attach(HWND__ *). PRESS KEYPAD "+" TO EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION CWnd::Detach(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000042 BYTES: COLLAPSED FUNCTION AfxUnhookWindowCreate(void). PRESS KEYPAD	"+" TO EXPAND]



sub_10011151 proc near

arg_0= dword ptr  4

push	esi
mov	esi, [esp+4+arg_0]
cmp	dword ptr [esi+28h], 0
jnz	short loc_1001116A
push	1		; __int32
call	?AfxEndDeferRegisterClass@@YGHJ@Z ; AfxEndDeferRegisterClass(long)
mov	dword ptr [esi+28h], offset aAfxwnd70s ; "AfxWnd70s"

loc_1001116A:
xor	eax, eax
inc	eax
pop	esi
retn	4
sub_10011151 endp

; [0000003B BYTES: COLLAPSED FUNCTION CWnd::OnDestroy(void). PRESS KEYPAD "+" TO EXPAND]
; [00000111 BYTES: COLLAPSED FUNCTION CWnd::OnNcDestroy(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000054 BYTES: COLLAPSED FUNCTION CWnd::DestroyWindow(void). PRESS KEYPAD "+" TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION CWnd::OnNTCtlColor(uint,long). PRESS KEYPAD "+" TO EXPAND]
; [00000077 BYTES: COLLAPSED FUNCTION CWnd::GetDescendantWindow(HWND__ *,int,int). PRESS KEYPAD	"+" TO EXPAND]
; [00000042 BYTES: COLLAPSED FUNCTION CWnd::WalkPreTranslateTree(HWND__	*,tagMSG *). PRESS KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION CWnd::SendChildNotifyLastMsg(long	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION CWnd::OnSetFocus(CWnd *).	PRESS KEYPAD "+" TO EXPAND]
; [0000006A BYTES: COLLAPSED FUNCTION CWnd::OnHelpInfo(tagHELPINFO *). PRESS KEYPAD "+"	TO EXPAND]
; [0000003A BYTES: COLLAPSED FUNCTION CWnd::OnGetObject(uint,long). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION sub_10011504. PRESS KEYPAD "+" TO	EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION CWnd::OnEnterIdle(uint,CWnd *). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION CWnd::OnCtlColor(CDC *,CWnd *,uint). PRESS KEYPAD	"+" TO EXPAND]
; [00000079 BYTES: COLLAPSED FUNCTION _AfxPostInitDialog(CWnd *,tagRECT	const &,ulong).	PRESS KEYPAD "+" TO EXPAND]
; [000000ED BYTES: COLLAPSED FUNCTION AfxCallWndProc(CWnd *,HWND__ *,uint,uint,long). PRESS KEYPAD "+" TO EXPAND]
; [0000004B BYTES: COLLAPSED FUNCTION AfxWndProc(HWND__	*,uint,uint,long). PRESS KEYPAD	"+" TO EXPAND]
; [0000007C BYTES: COLLAPSED FUNCTION CWnd::~CWnd(void). PRESS KEYPAD "+" TO EXPAND]
; [0000002B BYTES: COLLAPSED FUNCTION sub_100117B9. PRESS KEYPAD "+" TO	EXPAND]
; [00000078 BYTES: COLLAPSED FUNCTION CWnd::OnMeasureItem(int,tagMEASUREITEMSTRUCT *). PRESS KEYPAD "+"	TO EXPAND]
; [0000003F BYTES: COLLAPSED FUNCTION CWnd::GetParentFrame(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION CWnd::GetTopLevelFrame(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000007D BYTES: COLLAPSED FUNCTION CWnd::SendMessageToDescendants(HWND__ *,uint,uint,long,int,int). PRESS KEYPAD "+"	TO EXPAND]
; [000000AF BYTES: COLLAPSED FUNCTION CWnd::ReflectLastMsg(HWND__ *,long *). PRESS KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION CWnd::OnParentNotify(uint,long). PRESS KEYPAD "+"	TO EXPAND]
; [0000002A BYTES: COLLAPSED FUNCTION CWnd::OnDragList(uint,long). PRESS KEYPAD	"+" TO EXPAND]



; int __thiscall sub_10011A5F(void *, char)
sub_10011A5F proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
test	[esp+4+arg_0], 1
jz	short loc_10011A75
push	esi		; void *
call	j__free
pop	ecx

loc_10011A75:
mov	eax, esi
pop	esi
retn	4
sub_10011A5F endp

; [0000003D BYTES: COLLAPSED FUNCTION CWnd::OnDrawItem(int,tagDRAWITEMSTRUCT *). PRESS KEYPAD "+" TO EXPAND]
; [0000002A BYTES: COLLAPSED FUNCTION CWnd::OnCompareItem(int,tagCOMPAREITEMSTRUCT *). PRESS KEYPAD "+"	TO EXPAND]
; [00000020 BYTES: COLLAPSED FUNCTION CWnd::OnDeleteItem(int,tagDELETEITEMSTRUCT *). PRESS KEYPAD "+" TO EXPAND]



sub_10011B02 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8
arg_8= dword ptr  0Ch
arg_C= dword ptr  10h

push	esi
push	0Ch		; int
call	?AfxLockGlobals@@YGXH@Z	; AfxLockGlobals(int)
push	offset sub_100161E2
mov	ecx, offset unk_10020704
call	?GetData@CProcessLocalObject@@QAEPAVCNoTrackObject@@P6GPAV2@XZ@Z ; CProcessLocalObject::GetData(CNoTrackObject * (*)(void))
mov	esi, eax
cmp	dword ptr [esi+8], 0
jnz	short loc_10011B57
push	offset aHhctrl_ocx ; "hhctrl.ocx"
call	ds:LoadLibraryA
test	eax, eax
mov	[esi+4], eax
jz	short loc_10011B53
push	offset aHtmlhelpa ; "HtmlHelpA"
push	eax		; hModule
call	ds:GetProcAddress
test	eax, eax
mov	[esi+8], eax
jnz	short loc_10011B57
push	dword ptr [esi+4] ; hLibModule
call	ds:FreeLibrary
and	dword ptr [esi+4], 0

loc_10011B53:
xor	eax, eax
jmp	short loc_10011B71

loc_10011B57:		; int
push	0Ch
call	?AfxUnlockGlobals@@YGXH@Z ; AfxUnlockGlobals(int)
push	[esp+4+arg_C]
push	[esp+8+arg_8]
push	[esp+0Ch+arg_4]
push	[esp+10h+arg_0]
call	dword ptr [esi+8]

loc_10011B71:
pop	esi
retn	10h
sub_10011B02 endp

; [0000008C BYTES: COLLAPSED FUNCTION CWnd::OnCommand(uint,long). PRESS	KEYPAD "+" TO EXPAND]
; [0000007A BYTES: COLLAPSED FUNCTION CWnd::OnNotify(uint,long,long *).	PRESS KEYPAD "+" TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION AfxGetParentOwner(HWND__ *). PRESS KEYPAD	"+" TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION CWnd::GetTopLevelParent(void). PRESS KEYPAD "+" TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION CWnd::OnSysColorChange(void). PRESS KEYPAD "+" TO	EXPAND]



; int __stdcall	sub_10011D2E(LPCSTR pPrinterName)
sub_10011D2E proc near

pPrinterName= dword ptr	 4

push	esi
mov	esi, ecx
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	eax, [eax+4]
test	eax, eax
jz	short loc_10011D4D
cmp	[eax+1Ch], esi
jnz	short loc_10011D4D
push	[esp+4+pPrinterName] ; pPrinterName
mov	ecx, eax
call	?DevModeChange@CWinApp@@QAEXPAD@Z ; CWinApp::DevModeChange(char	*)

loc_10011D4D:
mov	ecx, esi
call	?GetStyle@CWnd@@QBEKXZ ; CWnd::GetStyle(void)
test	eax, 40000000h
jnz	short loc_10011D75
call	?GetCurrentMessage@CWnd@@KGPBUtagMSG@@XZ ; CWnd::GetCurrentMessage(void)
push	1		; int
push	1		; int
push	dword ptr [eax+0Ch] ; lParam
push	dword ptr [eax+8] ; wParam
push	dword ptr [eax+4] ; Msg
push	dword ptr [esi+1Ch] ; hWnd
call	?SendMessageToDescendants@CWnd@@SGXPAUHWND__@@IIJHH@Z ;	CWnd::SendMessageToDescendants(HWND__ *,uint,uint,long,int,int)

loc_10011D75:
pop	esi
retn	4
sub_10011D2E endp

; [00000049 BYTES: COLLAPSED FUNCTION CWnd::OnDisplayChange(uint,long).	PRESS KEYPAD "+" TO EXPAND]
; [00000061 BYTES: COLLAPSED FUNCTION _AfxHandleActivate(CWnd *,uint,CWnd *). PRESS KEYPAD "+" TO EXPAND]
; [00000076 BYTES: COLLAPSED FUNCTION _AfxHandleSetCursor(CWnd *,uint,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000123 BYTES: COLLAPSED FUNCTION _AfxActivationWndProc(HWND__ *,uint,uint,long). PRESS KEYPAD "+" TO EXPAND]



sub_10011FBC proc near
mov	eax, [ebp+8]
mov	[ebp-4Ch], eax
mov	eax, [ebp+0Ch]
mov	[ebp-48h], eax
mov	eax, [ebp+10h]
mov	[ebp-44h], eax
mov	eax, [ebp+14h]
mov	[ebp-40h], eax
lea	eax, [ebp-4Ch]
push	eax
push	dword ptr [ebp-20h]
call	?AfxProcessWndProcException@@YGJPAVCException@@PBUtagMSG@@@Z ; AfxProcessWndProcException(CException *,tagMSG const *)
mov	ecx, [ebp-20h]
mov	[ebp-14h], eax
call	?Delete@CException@@QAEXXZ ; CException::Delete(void)
mov	eax, offset loc_10011F2A
retn
sub_10011FBC endp

; [0000021F BYTES: COLLAPSED FUNCTION _AfxCbtFilterHook(int,uint,long).	PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION AfxHookWindowCreate(CWnd *). PRESS KEYPAD	"+" TO EXPAND]
; [000000C6 BYTES: COLLAPSED FUNCTION CWnd::CreateEx(ulong,char	const *,char const *,ulong,int,int,int,int,HWND__ *,HMENU__ *,void *). PRESS KEYPAD "+"	TO EXPAND]
; [00000073 BYTES: COLLAPSED FUNCTION CWnd::PrepareForHelp(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000507 BYTES: COLLAPSED FUNCTION CWnd::OnWndMsg(uint,uint,long,long *). PRESS KEYPAD "+" TO EXPAND]
off_1001289C dd	offset loc_10012593, offset loc_100125A1 ; jump	table for switch statement
dd offset loc_100125A1,	offset loc_100125A1
dd offset loc_100125B5,	offset loc_100125CC
dd offset loc_100126A0,	offset loc_100125DA
dd offset loc_10012649,	offset loc_10012681
dd offset loc_10012690,	offset loc_100125B5
dd offset loc_100126A0,	offset loc_100126AA
dd offset loc_100126B3,	offset loc_100126CF
dd offset loc_100126D8,	offset loc_100127EC
dd offset loc_100126E0,	offset loc_100126F1
dd offset loc_100126FF,	offset loc_100126FF
dd offset loc_100125A9,	offset loc_100125A1
dd offset loc_100125A1,	offset loc_100127E3
dd offset loc_100127EC,	offset loc_1001270D
dd offset loc_1001272B,	offset loc_10012739
dd offset loc_10012743,	offset loc_10012757
dd offset loc_1001275C,	offset loc_10012764
dd offset loc_1001276F,	offset loc_10012784
dd offset loc_100127E3,	offset loc_10012792
dd offset loc_100127A1,	offset loc_100127A1
dd offset loc_100127F9,	offset loc_100127EC
dd offset loc_10012828,	offset loc_100126AA
dd offset loc_100127CF,	offset loc_100127E3
dd offset loc_100127EC,	offset loc_100127F9
dd offset loc_10012803,	offset loc_10012814
dd offset loc_10012828,	offset loc_10012839
dd offset loc_10012888,	offset loc_10012888
dd offset loc_10012888,	offset loc_10012888
dd offset loc_10012888,	offset loc_10012888
dd offset loc_10012888,	offset loc_10012888
dd offset loc_10012888,	offset loc_10012888
dd offset loc_10012888,	offset loc_10012888
dd offset loc_1001285D
; [000000E8 BYTES: COLLAPSED FUNCTION CWnd::ReflectChildNotify(uint,uint,long,long *). PRESS KEYPAD "+"	TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION CWnd::OnSettingChange(uint,char const *).	PRESS KEYPAD "+" TO EXPAND]
; [000000C8 BYTES: COLLAPSED FUNCTION CWnd::CreateAccessibleProxy(uint,long,long *). PRESS KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

; int __stdcall	sub_10012B7C(ULONG_PTR dwData, UINT uCommand)
sub_10012B7C proc near

var_C= dword ptr -0Ch
var_4= dword ptr -4
dwData=	dword ptr  8
uCommand= dword	ptr  0Ch

mov	eax, offset sub_100169C1
call	__EH_prolog
push	ecx
push	esi
push	edi
mov	edi, ecx
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	esi, [eax+4]
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	ecx, [eax+4]
call	?BeginWaitCursor@CCmdTarget@@QAEXXZ ; CCmdTarget::BeginWaitCursor(void)
and	[ebp+var_4], 0
mov	ecx, edi
call	?PrepareForHelp@CWnd@@QAEXXZ ; CWnd::PrepareForHelp(void)
mov	ecx, edi
call	?GetTopLevelParent@CWnd@@QBEPAV1@XZ ; CWnd::GetTopLevelParent(void)
push	[ebp+dwData]	; dwData
push	[ebp+uCommand]	; uCommand
push	dword ptr [esi+60h] ; lpszHelp
push	dword ptr [eax+1Ch] ; hWndMain
call	ds:WinHelpA
test	eax, eax
pop	edi
pop	esi
jnz	short loc_10012BD7
push	0FFFFFFFFh	; unsigned int
push	eax		; unsigned int
push	0F107h		; unsigned int
call	?AfxMessageBox@@YGHIII@Z ; AfxMessageBox(uint,uint,uint)

loc_10012BD7:
or	[ebp+var_4], 0FFFFFFFFh
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	ecx, [eax+4]
call	?EndWaitCursor@CCmdTarget@@QAEXXZ ; CCmdTarget::EndWaitCursor(void)
mov	ecx, [ebp+var_C]
mov	large fs:0, ecx
leave
retn	8
sub_10012B7C endp



; Attributes: bp-based frame

sub_10012BF6 proc near

var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

mov	eax, offset sub_100169C1
call	__EH_prolog
push	ecx
push	esi
push	edi
mov	edi, ecx
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	esi, [eax+4]
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	ecx, [eax+4]
call	?BeginWaitCursor@CCmdTarget@@QAEXXZ ; CCmdTarget::BeginWaitCursor(void)
and	[ebp+var_4], 0
mov	ecx, edi
call	?PrepareForHelp@CWnd@@QAEXXZ ; CWnd::PrepareForHelp(void)
mov	ecx, edi
call	?GetTopLevelParent@CWnd@@QBEPAV1@XZ ; CWnd::GetTopLevelParent(void)
push	[ebp+arg_0]
push	[ebp+arg_4]
push	dword ptr [esi+60h]
push	dword ptr [eax+1Ch]
call	sub_10011B02
test	eax, eax
pop	edi
pop	esi
jnz	short loc_10012C50
push	0FFFFFFFFh	; unsigned int
push	eax		; unsigned int
push	0F107h		; unsigned int
call	?AfxMessageBox@@YGHIII@Z ; AfxMessageBox(uint,uint,uint)

loc_10012C50:
or	[ebp+var_4], 0FFFFFFFFh
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	ecx, [eax+4]
call	?EndWaitCursor@CCmdTarget@@QAEXXZ ; CCmdTarget::EndWaitCursor(void)
mov	ecx, [ebp+var_C]
mov	large fs:0, ecx
leave
retn	8
sub_10012BF6 endp

; [00000051 BYTES: COLLAPSED FUNCTION CWnd::OnChildNotify(uint,uint,long,long *). PRESS	KEYPAD "+" TO EXPAND]



sub_10012CC0 proc near
push	offset sub_10012D3D ; void (__cdecl *)()
call	_atexit
pop	ecx
retn
sub_10012CC0 endp




sub_10012CCC proc near
push	offset aCommctrl_dragl ; "commctrl_DragListMsg"
call	ds:RegisterWindowMessageA
mov	dword_100205B8,	eax
retn
sub_10012CCC endp

; [00000018 BYTES: COLLAPSED FUNCTION `dynamic initializer for 'CWnd const CWnd::wndTop''(void). PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION `dynamic initializer for 'CWnd const CWnd::wndBottom''(void). PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION `dynamic initializer for 'CWnd const CWnd::wndTopMost''(void). PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION `dynamic initializer for 'CWnd const CWnd::wndNoTopMost''(void). PRESS KEYPAD "+" TO EXPAND]



; void __cdecl sub_10012D3D()
sub_10012D3D proc near
mov	ecx, offset unk_10020704
jmp	j_??1CProcessLocalObject@@QAE@XZ ; CProcessLocalObject::~CProcessLocalObject(void)
sub_10012D3D endp




; void __cdecl sub_10012D47()
sub_10012D47 proc near
mov	ecx, offset unk_100205C0
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_10012D47 endp




; void __cdecl sub_10012D51()
sub_10012D51 proc near
mov	ecx, offset unk_10020610
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_10012D51 endp




; void __cdecl sub_10012D5B()
sub_10012D5B proc near
mov	ecx, offset unk_10020660
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_10012D5B endp




; void __cdecl sub_10012D65()
sub_10012D65 proc near
mov	ecx, offset unk_100206B0
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_10012D65 endp

; [0000004B BYTES: COLLAPSED FUNCTION AfxLoadString(uint,char *,uint). PRESS KEYPAD "+"	TO EXPAND]
; [0000000B BYTES: COLLAPSED FUNCTION AfxFindStringResourceHandle(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000003 BYTES: COLLAPSED FUNCTION nullsub_5. PRESS KEYPAD "+" TO EXPAND]
; [0000007C BYTES: COLLAPSED FUNCTION afxMapHMENU(int).	PRESS KEYPAD "+" TO EXPAND]
; [0000000E BYTES: COLLAPSED FUNCTION CMenu::FromHandle(HMENU__	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CMenu::FromHandlePermanent(HMENU__ *). PRESS KEYPAD "+" TO EXPAND]



sub_10012E6C proc near
push	esi
mov	esi, ecx
push	edi
mov	edi, [esi+4]
test	edi, edi
jz	short loc_10012E8D
push	0
call	?afxMapHMENU@@YGPAVCHandleMap@@H@Z ; afxMapHMENU(int)
test	eax, eax
jz	short loc_10012E8D
push	dword ptr [esi+4]
lea	ecx, [eax+1Ch]
call	sub_1000E8E5

loc_10012E8D:
and	dword ptr [esi+4], 0
mov	eax, edi
pop	edi
pop	esi
retn
sub_10012E6C endp

; START	OF FUNCTION CHUNK FOR sub_10003B6D

loc_10012E96:
cmp	dword ptr [ecx+4], 0
jnz	short loc_10012E9F
xor	eax, eax
retn

loc_10012E9F:
call	sub_10012E6C
push	eax		; hMenu
call	ds:DestroyMenu
retn
; END OF FUNCTION CHUNK	FOR sub_10003B6D
; [00000013 BYTES: COLLAPSED FUNCTION CWinApp::OnAppExit(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000068 BYTES: COLLAPSED FUNCTION AfxSetWindowText(HWND__ *,char const *). PRESS KEYPAD "+"	TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION AfxDeleteObject(void * *). PRESS KEYPAD "+" TO EXPAND]
; [00000030 BYTES: COLLAPSED FUNCTION AfxGlobalFree(void *). PRESS KEYPAD "+" TO EXPAND]
; [0000004D BYTES: COLLAPSED FUNCTION AfxCriticalNewHandler(uint). PRESS KEYPAD	"+" TO EXPAND]
; [00000072 BYTES: COLLAPSED FUNCTION _AfxChildWindowFromPoint(HWND__ *,tagPOINT). PRESS KEYPAD	"+" TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_34. PRESS	KEYPAD "+" TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_35. PRESS	KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION CDC::ReleaseAttribDC(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION Concurrency::details::TaskStack::Clear(void). PRESS KEYPAD "+" TO	EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION CDC::SaveDC(void). PRESS KEYPAD "+" TO EXPAND]
; [0000003E BYTES: COLLAPSED FUNCTION CDC::RestoreDC(int). PRESS KEYPAD	"+" TO EXPAND]



; int __stdcall	sub_100130BC(COLORREF color)
sub_100130BC proc near

color= dword ptr  4

push	esi
mov	esi, ecx
mov	ecx, [esi+4]
or	eax, 0FFFFFFFFh
cmp	ecx, [esi+8]
push	edi
mov	edi, ds:SetBkColor
jz	short loc_100130D8
push	[esp+8+color]	; color
push	ecx		; hdc
call	edi ; SetBkColor

loc_100130D8:
mov	esi, [esi+8]
test	esi, esi
jz	short loc_100130E6
push	[esp+8+color]	; color
push	esi		; hdc
call	edi ; SetBkColor

loc_100130E6:
pop	edi
pop	esi
retn	4
sub_100130BC endp




; int __stdcall	sub_100130EB(COLORREF color)
sub_100130EB proc near

color= dword ptr  4

push	esi
mov	esi, ecx
mov	ecx, [esi+4]
or	eax, 0FFFFFFFFh
cmp	ecx, [esi+8]
push	edi
mov	edi, ds:SetTextColor
jz	short loc_10013107
push	[esp+8+color]	; color
push	ecx		; hdc
call	edi ; SetTextColor

loc_10013107:
mov	esi, [esi+8]
test	esi, esi
jz	short loc_10013115
push	[esp+8+color]	; color
push	esi		; hdc
call	edi ; SetTextColor

loc_10013115:
pop	edi
pop	esi
retn	4
sub_100130EB endp




; int __stdcall	sub_1001311A(int iMode)
sub_1001311A proc near

iMode= dword ptr  4

push	esi
mov	esi, ecx
mov	ecx, [esi+4]
xor	eax, eax
cmp	ecx, [esi+8]
push	edi
mov	edi, ds:SetMapMode
jz	short loc_10013135
push	[esp+8+iMode]	; iMode
push	ecx		; hdc
call	edi ; SetMapMode

loc_10013135:
mov	esi, [esi+8]
test	esi, esi
jz	short loc_10013143
push	[esp+8+iMode]	; iMode
push	esi		; hdc
call	edi ; SetMapMode

loc_10013143:
pop	edi
pop	esi
retn	4
sub_1001311A endp




; int __stdcall	sub_10013148(LPRECT lprect)
sub_10013148 proc near

lprect=	dword ptr  4

push	[esp+lprect]	; lprect
push	dword ptr [ecx+4] ; hdc
call	ds:GetClipBox
retn	4
sub_10013148 endp

; [00000019 BYTES: COLLAPSED FUNCTION unknown_libname_36. PRESS	KEYPAD "+" TO EXPAND]
align 2
; [00000014 BYTES: COLLAPSED FUNCTION CDC::CDC(void). PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION CDC::SetViewportOrg(int,int). PRESS KEYPAD "+" TO	EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION CDC::OffsetViewportOrg(int,int). PRESS KEYPAD "+"	TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION CDC::SetViewportExt(int,int). PRESS KEYPAD "+" TO	EXPAND]
; [00000058 BYTES: COLLAPSED FUNCTION CDC::ScaleViewportExt(int,int,int,int). PRESS KEYPAD "+" TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION CDC::SetWindowExt(int,int). PRESS	KEYPAD "+" TO EXPAND]
; [00000058 BYTES: COLLAPSED FUNCTION CDC::ScaleWindowExt(int,int,int,int). PRESS KEYPAD "+" TO	EXPAND]
; [0000007C BYTES: COLLAPSED FUNCTION afxMapHDC(int). PRESS KEYPAD "+" TO EXPAND]
; [0000000E BYTES: COLLAPSED FUNCTION CDC::FromHandle(HDC__ *).	PRESS KEYPAD "+" TO EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION CDC::Detach(void). PRESS KEYPAD "+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION CDC::~CDC(void). PRESS KEYPAD "+"	TO EXPAND]
; [0000007C BYTES: COLLAPSED FUNCTION afxMapHGDIOBJ(int). PRESS	KEYPAD "+" TO EXPAND]

; public: static class CGdiObject * __stdcall CGdiObject::FromHandle(void *)
?FromHandle@CGdiObject@@SGPAV1@PAX@Z:
push	1
call	?afxMapHGDIOBJ@@YGPAVCHandleMap@@H@Z ; afxMapHGDIOBJ(int)
mov	ecx, eax
jmp	?FromHandle@CHandleMap@@QAEPAVCObject@@PAX@Z ; CHandleMap::FromHandle(void *)



sub_100134C4 proc near
push	esi
mov	esi, ecx
push	edi
mov	edi, [esi+4]
test	edi, edi
jz	short loc_100134E5
push	0
call	?afxMapHGDIOBJ@@YGPAVCHandleMap@@H@Z ; afxMapHGDIOBJ(int)
test	eax, eax
jz	short loc_100134E5
push	dword ptr [esi+4]
lea	ecx, [eax+1Ch]
call	sub_1000E8E5

loc_100134E5:
and	dword ptr [esi+4], 0
mov	eax, edi
pop	edi
pop	esi
retn
sub_100134C4 endp

; START	OF FUNCTION CHUNK FOR sub_1000303E

loc_100134EE:
cmp	dword ptr [ecx+4], 0
jnz	short loc_100134F7
xor	eax, eax
retn

loc_100134F7:
call	sub_100134C4
push	eax		; ho
call	ds:DeleteObject
retn
; END OF FUNCTION CHUNK	FOR sub_1000303E



; int __thiscall sub_10013504(void *, char)
sub_10013504 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1CDC@@UAE@XZ	; CDC::~CDC(void)
test	[esp+4+arg_0], 1
jz	short loc_1001351A
push	esi		; void *
call	j__free
pop	ecx

loc_1001351A:
mov	eax, esi
pop	esi
retn	4
sub_10013504 endp

; [0000003C BYTES: COLLAPSED FUNCTION CDC::SelectStockObject(int). PRESS KEYPAD	"+" TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION unknown_libname_37. PRESS	KEYPAD "+" TO EXPAND]
; [0000012D BYTES: COLLAPSED FUNCTION CArchive::Read(void *,uint). PRESS KEYPAD	"+" TO EXPAND]
; [00000077 BYTES: COLLAPSED FUNCTION CArchive::Flush(void). PRESS KEYPAD "+" TO EXPAND]
; [000000E8 BYTES: COLLAPSED FUNCTION CArchive::FillBuffer(uint). PRESS	KEYPAD "+" TO EXPAND]
; [000000B1 BYTES: COLLAPSED FUNCTION CArchive::Write(void const *,uint). PRESS	KEYPAD "+" TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION CArchive::WriteCount(ulong). PRESS KEYPAD	"+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION CArchive::ReadCount(void). PRESS KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

; int __cdecl sub_1001393A(LPSTR lpString1, int	iMaxLength, int)
sub_1001393A proc near

lpString2= dword ptr -14h
var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4
lpString1= dword ptr  8
iMaxLength= dword ptr  0Ch
arg_8= dword ptr  10h

mov	eax, offset sub_100169EF
call	__EH_prolog
sub	esp, 0Ch
cmp	[ebp+lpString1], 0
push	ebx
push	esi
push	edi
mov	[ebp+var_10], esp
mov	edi, ecx
jz	loc_100139EE
mov	eax, [ebp+arg_8]
test	eax, eax
jz	short loc_1001396B
mov	ecx, [edi+8]
add	ecx, 0F1B0h
mov	[eax], ecx

loc_1001396B:
and	[ebp+var_4], 0
call	sub_1000FB8F
mov	edx, [eax]
mov	ecx, eax
call	dword ptr [edx+0Ch]
add	eax, 10h
mov	[ebp+lpString2], eax
lea	eax, [edi+0Ch]
push	eax
lea	ecx, [ebp+arg_8]
mov	byte ptr [ebp+var_4], 1
call	??0?$CSimpleStringT@D$0A@@ATL@@QAE@ABV01@@Z ; ATL::CSimpleStringT<char,0>::CSimpleStringT<char,0>(CSimpleStringT<char,0>::CSimpleStringT<char,0> const &)
mov	esi, [ebp+arg_8]
cmp	dword ptr [esi-0Ch], 0
mov	byte ptr [ebp+var_4], 2
jnz	short loc_100139AE
push	0F006h
lea	ecx, [ebp+arg_8]
call	sub_10002B30
mov	esi, [ebp+arg_8]

loc_100139AE:
mov	eax, [edi+8]
push	esi
add	eax, 0F1B0h
push	eax
lea	eax, [ebp+lpString2]
push	eax
call	sub_1001409F
push	[ebp+iMaxLength] ; iMaxLength
push	[ebp+lpString2]	; lpString2
push	[ebp+lpString1]	; lpString1
call	ds:lstrcpynA
lea	ecx, [esi-10h]
call	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
mov	ecx, [ebp+lpString2]
add	ecx, 0FFFFFFF0h
call	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
xor	eax, eax
inc	eax
jmp	short loc_100139F0

loc_100139E8:
mov	eax, offset loc_100139EE
retn

loc_100139EE:
xor	eax, eax

loc_100139F0:
mov	ecx, [ebp+var_C]
pop	edi
pop	esi
mov	large fs:0, ecx
pop	ebx
leave
retn	0Ch
sub_1001393A endp



; Attributes: noreturn bp-based	frame

sub_10013A01 proc near

var_14=	dword ptr -14h
var_10=	dword ptr -10h
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch

mov	eax, offset sub_10016A17
call	__EH_prolog
push	ecx
push	ecx
push	10h		; size_t
call	??2@YAPAXI@Z	; operator new(uint)
pop	ecx
mov	ecx, eax
mov	[ebp+var_14], ecx
xor	eax, eax
cmp	ecx, eax
mov	[ebp+var_4], eax
jz	short loc_10013A2E
push	[ebp+arg_4]	; char *
push	[ebp+arg_0]	; int
call	sub_10003C90

loc_10013A2E:
or	[ebp+var_4], 0FFFFFFFFh
mov	[ebp+var_10], eax
push	offset unk_1001AD94
lea	eax, [ebp+var_10]
push	eax
call	__CxxThrowException@8 ;	_CxxThrowException(x,x)
sub_10013A01 endp

align 4
; [00000053 BYTES: COLLAPSED FUNCTION CWinApp::DoWaitCursor(int). PRESS	KEYPAD "+" TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION CWinApp::SaveAllModified(void). PRESS KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION unknown_libname_38. PRESS	KEYPAD "+" TO EXPAND]



sub_10013AC0 proc near
mov	ecx, [ecx+54h]
mov	eax, [ecx]
jmp	dword ptr [eax+1Ch]
sub_10013AC0 endp

; [00000021 BYTES: COLLAPSED FUNCTION CWinApp::OnUpdateRecentFileMenu(CCmdUI *). PRESS KEYPAD "+" TO EXPAND]
; [00000013 BYTES: COLLAPSED FUNCTION unknown_libname_39. PRESS	KEYPAD "+" TO EXPAND]
; [00000036 BYTES: COLLAPSED FUNCTION CWinApp::OnOpenRecentFile(uint). PRESS KEYPAD "+"	TO EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION CCmdTarget::GetRoutingFrame_(void). PRESS	KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION CWinApp::EnableModeless(int). PRESS KEYPAD "+" TO	EXPAND]
; [0000009E BYTES: COLLAPSED FUNCTION CWnd::GetSafeOwner_(HWND__ *,HWND__ * *).	PRESS KEYPAD "+" TO EXPAND]
; [00000133 BYTES: COLLAPSED FUNCTION CWinApp::DoMessageBox(char const *,uint,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000022 BYTES: COLLAPSED FUNCTION AfxMessageBox(char const *,uint,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000062 BYTES: COLLAPSED FUNCTION AfxMessageBox(uint,uint,uint). PRESS KEYPAD "+" TO EXPAND]
; [00000011 BYTES: COLLAPSED FUNCTION CWinApp::GetFirstDocTemplatePosition(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000043 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::Concatenate(ATL::CSimpleStringT<char,0> &,char const	*,int,char const *,int). PRESS KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

; int __cdecl sub_10013E14(int,	int, char *)
sub_10013E14 proc near

var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h

mov	eax, offset sub_100167CF
call	__EH_prolog
push	ecx
and	[ebp+var_10], 0
push	esi
mov	esi, [ebp+arg_4]
mov	eax, [esi]
mov	ecx, [eax-10h]
mov	eax, [ecx]
call	dword ptr [eax+10h]
mov	edx, [eax]
mov	ecx, eax
call	dword ptr [edx+0Ch]
add	eax, 10h
mov	[ebp+arg_4], eax
and	[ebp+var_4], 0
cmp	[ebp+arg_8], 0
jnz	short loc_10013E4C
xor	eax, eax
jmp	short loc_10013E55

loc_10013E4C:		; char *
push	[ebp+arg_8]
call	_strlen
pop	ecx

loc_10013E55:
mov	ecx, [esi]
push	eax		; size_t
push	[ebp+arg_8]	; void *
lea	eax, [ebp+arg_4]
push	dword ptr [ecx-0Ch] ; size_t
push	ecx		; void *
push	eax		; int
call	?Concatenate@?$CSimpleStringT@D$0A@@ATL@@KAXAAV12@PBDH1H@Z ; ATL::CSimpleStringT<char,0>::Concatenate(ATL::CSimpleStringT<char,0> &,char const *,int,char const	*,int)
mov	ecx, [ebp+arg_0]
add	esp, 14h
lea	eax, [ebp+arg_4]
push	eax
call	??0?$CSimpleStringT@D$0A@@ATL@@QAE@ABV01@@Z ; ATL::CSimpleStringT<char,0>::CSimpleStringT<char,0>(CSimpleStringT<char,0>::CSimpleStringT<char,0> const &)
mov	ecx, [ebp+arg_4]
add	ecx, 0FFFFFFF0h
call	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
mov	ecx, [ebp+var_C]
mov	eax, [ebp+arg_0]
pop	esi
mov	large fs:0, ecx
leave
retn
sub_10013E14 endp

; [00000025 BYTES: COLLAPSED FUNCTION ATL::CSimpleStringT<char,0>::Append(char const *). PRESS KEYPAD "+" TO EXPAND]
; [00000082 BYTES: COLLAPSED FUNCTION CWinApp::WriteProfileInt(char const *,char const *,int). PRESS KEYPAD "+"	TO EXPAND]
; [000000FF BYTES: COLLAPSED FUNCTION AfxFormatStrings(ATL::CStringT<char,StrTraitMFC<char,ATL::ChTraitsCRT<char>>> &,char const *,char	const *	const *,int). PRESS KEYPAD "+" TO EXPAND]


; Attributes: bp-based frame

sub_10014038 proc near

var_10=	dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h
arg_C= dword ptr  14h

mov	eax, offset sub_10016A29
call	__EH_prolog
push	ecx
call	sub_1000FB8F
mov	edx, [eax]
mov	ecx, eax
call	dword ptr [edx+0Ch]
add	eax, 10h
mov	[ebp+var_10], eax
push	[ebp+arg_4]
and	[ebp+var_4], 0
lea	ecx, [ebp+var_10]
call	sub_10002B30
test	eax, eax
jnz	short loc_10014075
mov	ecx, [ebp+var_10]
add	ecx, 0FFFFFFF0h
call	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
jmp	short loc_10014091

loc_10014075:
push	esi
push	[ebp+arg_C]
mov	esi, [ebp+var_10]
push	[ebp+arg_8]
push	esi
push	[ebp+arg_0]
call	?AfxFormatStrings@@YGXAAV?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@PBDPBQBDH@Z ; AfxFormatStrings(ATL::CStringT<char,StrTraitMFC<char,ATL::ChTraitsCRT<char>>> &,char const *,char const * const *,int)
lea	ecx, [esi-10h]
call	?Release@CStringData@ATL@@QAEXXZ ; ATL::CStringData::Release(void)
pop	esi

loc_10014091:
mov	ecx, [ebp+var_C]
mov	large fs:0, ecx
leave
retn	10h
sub_10014038 endp




sub_1001409F proc near

arg_0= dword ptr  4
arg_4= dword ptr  8
arg_8= byte ptr	 0Ch

push	1
lea	eax, [esp+4+arg_8]
push	eax
push	[esp+8+arg_4]
push	[esp+0Ch+arg_0]
call	sub_10014038
retn	0Ch
sub_1001409F endp

; [00000010 BYTES: COLLAPSED FUNCTION AfxOleCanExitApp(void). PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION AfxOleLockApp(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000000F BYTES: COLLAPSED FUNCTION AfxOleSetUserCtrl(int). PRESS KEYPAD "+" TO EXPAND]
; [00000009 BYTES: COLLAPSED FUNCTION AfxOleGetUserCtrl(void). PRESS KEYPAD "+"	TO EXPAND]
; [0000004C BYTES: COLLAPSED FUNCTION AfxOleOnReleaseAllObjects(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION AfxOleUnlockApp(void). PRESS KEYPAD "+" TO EXPAND]
; [0000007F BYTES: COLLAPSED FUNCTION _AfxLoadLangDLL(char const *,ulong). PRESS KEYPAD	"+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION unknown_libname_40. PRESS	KEYPAD "+" TO EXPAND]
; [000001DC BYTES: COLLAPSED FUNCTION AfxLoadLangResourceDLL(char const	*). PRESS KEYPAD "+" TO	EXPAND]
; [000000CA BYTES: COLLAPSED FUNCTION CWinApp::LoadSysPolicies(void). PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION CWinApp::InitApplication(void). PRESS KEYPAD "+" TO EXPAND]
; [00000084 BYTES: COLLAPSED FUNCTION CWinApp::LoadAppLangResourceDLL(void). PRESS KEYPAD "+" TO EXPAND]
; [00000128 BYTES: COLLAPSED FUNCTION CWinApp::~CWinApp(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION CWinApp::SaveStdProfileSettings(void). PRESS KEYPAD "+" TO EXPAND]
; [00000054 BYTES: COLLAPSED FUNCTION CWinApp::ExitInstance(void). PRESS KEYPAD	"+" TO EXPAND]



sub_10014703 proc near
mov	eax, offset off_10017524
retn
sub_10014703 endp

; [00000034 BYTES: COLLAPSED FUNCTION CThreadLocal<AFX_MODULE_THREAD_STATE>::CreateObject(void). PRESS KEYPAD "+" TO EXPAND]



; int __thiscall sub_1001473D(void *, char)
sub_1001473D proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1CWinApp@@UAE@XZ ; CWinApp::~CWinApp(void)
test	[esp+4+arg_0], 1
jz	short loc_10014753
push	esi		; void *
call	j__free
pop	ecx

loc_10014753:
mov	eax, esi
pop	esi
retn	4
sub_1001473D endp

; [00000038 BYTES: COLLAPSED FUNCTION CWinApp::InitInstance(void). PRESS KEYPAD	"+" TO EXPAND]
; [000000D8 BYTES: COLLAPSED FUNCTION CWinApp::CWinApp(char const *). PRESS KEYPAD "+" TO EXPAND]



sub_10014869 proc near
xor	eax, eax
inc	eax
retn
sub_10014869 endp

; [00000114 BYTES: COLLAPSED FUNCTION AfxDelRegTreeHelper(HKEY__ *,ATL::CStringT<char,StrTraitMFC<char,ATL::ChTraitsCRT<char>>>	const &). PRESS	KEYPAD "+" TO EXPAND]
; [00000173 BYTES: COLLAPSED FUNCTION CWinApp::Unregister(void). PRESS KEYPAD "+" TO EXPAND]
; [00000037 BYTES: COLLAPSED FUNCTION CWinThread::CommonConstruct(void). PRESS KEYPAD "+" TO EXPAND]



sub_10014B2B proc near
mov	eax, offset off_10017864
retn
sub_10014B2B endp

; [00000034 BYTES: COLLAPSED FUNCTION CThreadLocal<_AFX_THREAD_STATE>::CreateObject(void). PRESS KEYPAD	"+" TO EXPAND]



; int __thiscall sub_10014B65(void *, char)
sub_10014B65 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1CWinThread@@UAE@XZ ;	CWinThread::~CWinThread(void)
test	[esp+4+arg_0], 1
jz	short loc_10014B7B
push	esi		; void *
call	j__free
pop	ecx

loc_10014B7B:
mov	eax, esi
pop	esi
retn	4
sub_10014B65 endp

; [0000003D BYTES: COLLAPSED FUNCTION CWinThread::CWinThread(void). PRESS KEYPAD "+" TO	EXPAND]
; [000000E8 BYTES: COLLAPSED FUNCTION _AfxLoadDotBitmap(void). PRESS KEYPAD "+"	TO EXPAND]



sub_10014CA6 proc near
mov	eax, offset off_10017A14
retn
sub_10014CA6 endp




sub_10014CAC proc near
mov	eax, offset off_10017AC8
retn
sub_10014CAC endp




sub_10014CB2 proc near
mov	eax, offset off_10017A94
retn
sub_10014CB2 endp




sub_10014CB8 proc near
mov	eax, offset off_10017A60
retn
sub_10014CB8 endp

; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_41. PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_42. PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_43. PRESS	KEYPAD "+" TO EXPAND]



; void __cdecl sub_10014D15()
sub_10014D15 proc near
mov	ecx, offset unk_1001E7D8
jmp	sub_10002D2C
sub_10014D15 endp




; void __cdecl sub_10014D1F()
sub_10014D1F proc near
mov	ecx, offset unk_1001E870
jmp	sub_10002D33
sub_10014D1F endp




; void __cdecl sub_10014D29()
sub_10014D29 proc near
mov	ecx, offset unk_1001E908
jmp	sub_10002D3A
sub_10014D29 endp

; [00000018 BYTES: COLLAPSED FUNCTION unknown_libname_44. PRESS	KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION CNoTrackObject::operator delete(void *). PRESS KEYPAD "+"	TO EXPAND]
; [0000010C BYTES: COLLAPSED FUNCTION CThreadSlotData::AllocSlot(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION CThreadSlotData::GetThreadValue(int). PRESS KEYPAD "+" TO	EXPAND]
; [00000040 BYTES: COLLAPSED CHUNK OF FUNCTION AfxInitLocalData(HINSTANCE__ *).	PRESS KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION CThreadLocalObject::GetDataNA(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000004B BYTES: COLLAPSED FUNCTION CProcessLocalObject::GetData(CNoTrackObject * (*)(void)).	PRESS KEYPAD "+" TO EXPAND]


; Attributes: noreturn

sub_10014F52 proc near
push	10h		; int
call	?AfxUnlockGlobals@@YGXH@Z ; AfxUnlockGlobals(int)
xor	edi, edi
push	edi
push	edi
call	__CxxThrowException@8 ;	_CxxThrowException(x,x)
sub_10014F52 endp

db 0CCh
; [00000025 BYTES: COLLAPSED FUNCTION CProcessLocalObject::~CProcessLocalObject(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION AfxInitLocalData(HINSTANCE__ *). PRESS KEYPAD "+"	TO EXPAND]



sub_10014F9A proc near
inc	dword_1001E9A0
retn
sub_10014F9A endp

; [00000013 BYTES: COLLAPSED FUNCTION unknown_libname_45. PRESS	KEYPAD "+" TO EXPAND]
; [0000003E BYTES: COLLAPSED FUNCTION CSimpleList::Remove(void *). PRESS KEYPAD	"+" TO EXPAND]



sub_10014FF2 proc near
mov	eax, ecx
mov	dword ptr [eax], offset	off_10017B6C
retn
sub_10014FF2 endp

; [00000042 BYTES: COLLAPSED FUNCTION CThreadSlotData::CThreadSlotData(void). PRESS KEYPAD "+" TO EXPAND]
; [00000063 BYTES: COLLAPSED FUNCTION CThreadSlotData::FreeSlot(int). PRESS KEYPAD "+" TO EXPAND]
; [00000107 BYTES: COLLAPSED FUNCTION CThreadSlotData::SetValue(int,void *). PRESS KEYPAD "+" TO EXPAND]



; int __thiscall sub_100151A7(void *, char)
sub_100151A7 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	nullsub_1
test	[esp+4+arg_0], 1
jz	short loc_100151BC
push	esi		; void *
call	??3CNoTrackObject@@SGXPAX@Z ; CNoTrackObject::operator delete(void *)

loc_100151BC:
mov	eax, esi
pop	esi
retn	4
sub_100151A7 endp

; [00000001 BYTES: COLLAPSED FUNCTION nullsub_1. PRESS KEYPAD "+" TO EXPAND]
; [00000095 BYTES: COLLAPSED FUNCTION CThreadSlotData::DeleteValues(CThreadData	*,HINSTANCE__ *). PRESS	KEYPAD "+" TO EXPAND]
; [00000059 BYTES: COLLAPSED FUNCTION CThreadSlotData::DeleteValues(HINSTANCE__	*,int).	PRESS KEYPAD "+" TO EXPAND]
; [0000007A BYTES: COLLAPSED FUNCTION CThreadLocalObject::GetData(CNoTrackObject * (*)(void)). PRESS KEYPAD "+"	TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION CThreadLocalObject::~CThreadLocalObject(void). PRESS KEYPAD "+" TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION AfxTermLocalData(HINSTANCE__ *,int). PRESS KEYPAD	"+" TO EXPAND]
; [00000057 BYTES: COLLAPSED FUNCTION CThreadSlotData::~CThreadSlotData(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION AfxTlsRelease(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000024 BYTES: COLLAPSED FUNCTION AfxCriticalInit(void). PRESS KEYPAD "+" TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION AfxCriticalTerm(void). PRESS KEYPAD "+" TO EXPAND]
; [00000063 BYTES: COLLAPSED FUNCTION AfxLockGlobals(int). PRESS KEYPAD	"+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION AfxUnlockGlobals(int). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION CThreadLocalObject::~CThreadLocalObject(void). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION CProcessLocalObject::~CProcessLocalObject(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION CTypeLibCache::Unlock(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION _AFX_THREAD_STATE::_AFX_THREAD_STATE(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION _AFX_THREAD_STATE::~_AFX_THREAD_STATE(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000006E BYTES: COLLAPSED FUNCTION AFX_MODULE_STATE::~AFX_MODULE_STATE(void). PRESS KEYPAD "+" TO EXPAND]
; [000000A3 BYTES: COLLAPSED FUNCTION AFX_MODULE_THREAD_STATE::~AFX_MODULE_THREAD_STATE(void). PRESS KEYPAD "+"	TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION _AFX_THREAD_STATE::`scalar deleting destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000060 BYTES: COLLAPSED FUNCTION AFX_MODULE_STATE::AFX_MODULE_STATE(int). PRESS KEYPAD "+"	TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION AFX_MODULE_STATE::`scalar	deleting destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION AFX_MODULE_THREAD_STATE::AFX_MODULE_THREAD_STATE(void). PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION AFX_MODULE_THREAD_STATE::`scalar deleting	destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION _AFX_BASE_MODULE_STATE::_AFX_BASE_MODULE_STATE(void). PRESS KEYPAD "+" TO	EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION AFX_MODULE_STATE::`scalar	deleting destructor'(uint). PRESS KEYPAD "+" TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION AFX_MODULE_STATE::~AFX_MODULE_STATE(void). PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION CProcessLocal<_AFX_BASE_MODULE_STATE>::CreateObject(void). PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION AfxGetThreadState(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000026 BYTES: COLLAPSED FUNCTION AfxGetModuleState(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION AfxGetModuleThreadState(void). PRESS KEYPAD "+" TO EXPAND]



sub_100157CD proc near
push	offset sub_100157E5 ; void (__cdecl *)()
call	_atexit
pop	ecx
retn
sub_100157CD endp




sub_100157D9 proc near
push	offset sub_100157EF ; void (__cdecl *)()
call	_atexit
pop	ecx
retn
sub_100157D9 endp




; void __cdecl sub_100157E5()
sub_100157E5 proc near
mov	ecx, offset unk_1001EBDC
jmp	j_??1CThreadLocalObject@@QAE@XZ	; CThreadLocalObject::~CThreadLocalObject(void)
sub_100157E5 endp




; void __cdecl sub_100157EF()
sub_100157EF proc near
mov	ecx, offset unk_1001EBE0
jmp	j_??1CProcessLocalObject@@QAE@XZ_0 ; CProcessLocalObject::~CProcessLocalObject(void)
sub_100157EF endp

; [0000002F BYTES: COLLAPSED FUNCTION AfxGetFileName(char const	*,char *,uint).	PRESS KEYPAD "+" TO EXPAND]
; [0000014E BYTES: COLLAPSED FUNCTION CWinApp::SetCurrentHandles(void).	PRESS KEYPAD "+" TO EXPAND]



sub_10015976 proc near

arg_0= dword ptr  4
arg_8= dword ptr  0Ch
arg_C= dword ptr  10h

push	esi
mov	esi, ds:SetErrorMode
push	0		; uMode
call	esi ; SetErrorMode
or	eax, 8001h
push	eax		; uMode
call	esi ; SetErrorMode
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	esi, [esp+4+arg_0]
mov	[eax+8], esi
mov	[eax+0Ch], esi
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ ;	AfxGetModuleState(void)
mov	eax, [eax+4]
test	eax, eax
jz	short loc_100159BC
mov	ecx, [esp+4+arg_8]
mov	[eax+44h], ecx
mov	ecx, [esp+4+arg_C]
mov	[eax+48h], ecx
mov	ecx, eax
mov	[eax+40h], esi
call	?SetCurrentHandles@CWinApp@@QAEXXZ ; CWinApp::SetCurrentHandles(void)

loc_100159BC:		; AfxGetModuleState(void)
call	?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ
cmp	byte ptr [eax+14h], 0
pop	esi
jnz	short loc_100159CD
call	?AfxInitThread@@YGXXZ ;	AfxInitThread(void)

loc_100159CD:		; "user32.dll"
push	offset LibFileName
call	ds:GetModuleHandleA
test	eax, eax
jz	short loc_100159ED
push	offset aNotifywinevent ; "NotifyWinEvent"
push	eax		; hModule
call	ds:GetProcAddress
mov	dword_100205B4,	eax

loc_100159ED:
xor	eax, eax
inc	eax
retn	10h
sub_10015976 endp

; [00000091 BYTES: COLLAPSED FUNCTION CWinApp::GetAppRegistryKey(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000046 BYTES: COLLAPSED FUNCTION CWinApp::GetSectionKey(char const	*). PRESS KEYPAD "+" TO	EXPAND]



sub_10015ACA proc near
mov	eax, offset off_10017C50
retn
sub_10015ACA endp




sub_10015AD0 proc near
mov	eax, offset off_10017C24
retn
sub_10015AD0 endp




sub_10015AD6 proc near
mov	eax, offset off_10017C04
retn
sub_10015AD6 endp




sub_10015ADC proc near
mov	eax, offset off_10017BDC
retn
sub_10015ADC endp

; [00000021 BYTES: COLLAPSED FUNCTION CDC::CreateObject(void). PRESS KEYPAD "+"	TO EXPAND]



sub_10015B03 proc near
push	8		; size_t
call	??2@YAPAXI@Z	; operator new(uint)
test	eax, eax
pop	ecx
jz	short loc_10015B1A
mov	dword ptr [eax], offset	off_10017CB4
and	dword ptr [eax+4], 0
retn

loc_10015B1A:
xor	eax, eax
retn
sub_10015B03 endp

; [0000001C BYTES: COLLAPSED FUNCTION ConstructDestruct<CDC>::Construct(CObject	*). PRESS KEYPAD "+" TO	EXPAND]



sub_10015B39 proc near

arg_0= dword ptr  4

mov	eax, [esp+arg_0]
test	eax, eax
jz	short locret_10015B4B
and	dword ptr [eax+4], 0
mov	dword ptr [eax], offset	off_10017CB4

locret_10015B4B:
retn	4
sub_10015B39 endp

; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_46. PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_47. PRESS	KEYPAD "+" TO EXPAND]



; void __cdecl sub_10015B88()
sub_10015B88 proc near
mov	ecx, offset unk_1001EBE8
jmp	sub_10002EB2
sub_10015B88 endp




; void __cdecl sub_10015B92()
sub_10015B92 proc near
mov	ecx, offset unk_1001EC80
jmp	sub_10002EDB
sub_10015B92 endp

; [00000055 BYTES: COLLAPSED FUNCTION AUX_DATA::AUX_DATA(void).	PRESS KEYPAD "+" TO EXPAND]



sub_10015BF1 proc near
mov	ecx, offset dword_1001ED30
call	??0AUX_DATA@@QAE@XZ ; AUX_DATA::AUX_DATA(void)
push	offset loc_10015C07 ; void (__cdecl *)()
call	_atexit
pop	ecx
retn

; void __cdecl loc_10015C07()
loc_10015C07:		; void **
push	offset hBitmapChecked
call	?AfxDeleteObject@@YGXPAPAX@Z ; AfxDeleteObject(void * *)
retn
sub_10015BF1 endp




sub_10015C12 proc near
mov	eax, offset off_10017DDC
retn
sub_10015C12 endp

; [0000000E BYTES: COLLAPSED FUNCTION unknown_libname_48. PRESS	KEYPAD "+" TO EXPAND]
; [00000032 BYTES: COLLAPSED FUNCTION CWnd::CreateObject(void).	PRESS KEYPAD "+" TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION ConstructDestruct<CWnd>::Construct(CObject *). PRESS KEYPAD "+" TO EXPAND]
; START	OF FUNCTION CHUNK FOR sub_100161E2

loc_10015C84:
mov	eax, ecx
mov	dword ptr [eax], offset	off_10018580
retn
; END OF FUNCTION CHUNK	FOR sub_100161E2
; [0000002F BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accParent(IDispatch	* *). PRESS KEYPAD "+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accChildCount(long *). PRESS KEYPAD	"+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accChild(tagVARIANT,IDispatch * *).	PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accName(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accValue(tagVARIANT,wchar_t	* *). PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accDescription(tagVARIANT,wchar_t *	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accRole(tagVARIANT,tagVARIANT *). PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accState(tagVARIANT,tagVARIANT *). PRESS KEYPAD "+"	TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accHelp(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [00000048 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accHelpTopic(wchar_t * *,tagVARIANT,long *). PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accKeyboardShortcut(tagVARIANT,wchar_t * *). PRESS KEYPAD "+" TO EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accFocus(tagVARIANT	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accSelection(tagVARIANT *).	PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accDefaultAction(tagVARIANT,wchar_t	* *). PRESS KEYPAD "+" TO EXPAND]
; [00000032 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accSelect(long,tagVARIANT). PRESS KEYPAD "+" TO	EXPAND]
; [00000058 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accLocation(long *,long	*,long *,long *,tagVARIANT). PRESS KEYPAD "+" TO EXPAND]
; [00000043 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accNavigate(long,tagVARIANT,tagVARIANT *). PRESS KEYPAD	"+" TO EXPAND]
; [00000036 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accHitTest(long,long,tagVARIANT	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000002E BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accDoDefaultAction(tagVARIANT).	PRESS KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION unknown_libname_49. PRESS	KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::SetServer(IAccessible *,IAccessibleServer *). PRESS KEYPAD "+" TO EXPAND]
; [00000038 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::Invoke(long,_GUID const	&,ulong,ushort,tagDISPPARAMS *,tagVARIANT *,tagEXCEPINFO *,uint	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000002F BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetIDsOfNames(_GUID const &,wchar_t * *,uint,ulong,long	*). PRESS KEYPAD "+" TO	EXPAND]
; [00000021 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetTypeInfoCount(uint *). PRESS	KEYPAD "+" TO EXPAND]
; [00000029 BYTES: COLLAPSED FUNCTION ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetTypeInfo(uint,ulong,ITypeInfo * *). PRESS KEYPAD "+"	TO EXPAND]



sub_100161E2 proc near

; FUNCTION CHUNK AT 10015C84 SIZE 00000009 BYTES

push	0Ch		; uBytes
call	unknown_libname_44 ; MFC 3.1-10.0 32bit
test	eax, eax
jz	short loc_100161F4
mov	ecx, eax
jmp	loc_10015C84

loc_100161F4:
xor	eax, eax
retn
sub_100161E2 endp

; [0000002D BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::CMFCComObject<ATL::CAccessibleProxy>(void *). PRESS	KEYPAD "+" TO EXPAND]



; int __thiscall sub_10016224(void *, char)
sub_10016224 proc near

arg_0= byte ptr	 4

push	esi
mov	esi, ecx
call	??1?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAE@XZ ; CMFCComObject<ATL::CAccessibleProxy>::~CMFCComObject<ATL::CAccessibleProxy>(void)
test	[esp+4+arg_0], 1
jz	short loc_1001623A
push	esi		; void *
call	j__free
pop	ecx

loc_1001623A:
mov	eax, esi
pop	esi
retn	4
sub_10016224 endp

; [00000025 BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::~CMFCComObject<ATL::CAccessibleProxy>(void). PRESS KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::AddRef(void). PRESS	KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::Release(void). PRESS KEYPAD	"+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::QueryInterface(_GUID const &,void *	*). PRESS KEYPAD "+" TO	EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION [thunk]:CMFCComObject<ATL::CAccessibleProxy>::QueryInterface`adjustor{4}' (_GUID const &,void * *). PRESS KEYPAD "+" TO EXPAND]



sub_100162B3 proc near

arg_0= dword ptr  4

sub	[esp+arg_0], 4
jmp	?AddRef@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ	; CMFCComObject<ATL::CAccessibleProxy>::AddRef(void)
sub_100162B3 endp




sub_100162BD proc near

arg_0= dword ptr  4

sub	[esp+arg_0], 4
jmp	?Release@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ ; CMFCComObject<ATL::CAccessibleProxy>::Release(void)
sub_100162BD endp

; [0000000A BYTES: COLLAPSED FUNCTION [thunk]:CMFCComObject<ATL::CAccessibleProxy>::QueryInterface`adjustor{16}' (_GUID const &,void * *). PRESS KEYPAD "+" TO EXPAND]



sub_100162D1 proc near

arg_0= dword ptr  4

sub	[esp+arg_0], 10h
jmp	?AddRef@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ	; CMFCComObject<ATL::CAccessibleProxy>::AddRef(void)
sub_100162D1 endp




sub_100162DB proc near

arg_0= dword ptr  4

sub	[esp+arg_0], 10h
jmp	?Release@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ ; CMFCComObject<ATL::CAccessibleProxy>::Release(void)
sub_100162DB endp

; [00000086 BYTES: COLLAPSED FUNCTION CMFCComObject<ATL::CAccessibleProxy>::CreateInstance(CMFCComObject<ATL::CAccessibleProxy>	* *). PRESS KEYPAD "+" TO EXPAND]



sub_1001636B proc near
mov	eax, offset off_10018724
retn
sub_1001636B endp




sub_10016371 proc near
mov	eax, offset off_10018760
retn
sub_10016371 endp




sub_10016377 proc near
push	8		; size_t
call	??2@YAPAXI@Z	; operator new(uint)
test	eax, eax
pop	ecx
jz	short loc_1001638E
mov	dword ptr [eax], offset	off_10018788
and	dword ptr [eax+4], 0
retn

loc_1001638E:
xor	eax, eax
retn
sub_10016377 endp




sub_10016391 proc near

arg_0= dword ptr  4

mov	eax, [esp+arg_0]
test	eax, eax
jz	short locret_100163A3
and	dword ptr [eax+4], 0
mov	dword ptr [eax], offset	off_10018788

locret_100163A3:
retn	4
sub_10016391 endp




sub_100163A6 proc near
mov	eax, offset off_1001879C
retn
sub_100163A6 endp

; [00000033 BYTES: COLLAPSED FUNCTION _AfxInitDBCS(void). PRESS	KEYPAD "+" TO EXPAND]



sub_100163DF proc near
call	?_AfxInitDBCS@@YGHXZ ; _AfxInitDBCS(void)
mov	dword_1002070C,	eax
retn
sub_100163DF endp




sub_100163EA proc near
mov	eax, offset off_1001D838
retn
sub_100163EA endp




sub_100163F0 proc near

; FUNCTION CHUNK AT 1000E726 SIZE 00000017 BYTES

push	14h		; size_t
call	??2@YAPAXI@Z	; operator new(uint)
test	eax, eax
pop	ecx
jz	short loc_10016403
mov	ecx, eax
jmp	loc_1000E726

loc_10016403:
xor	eax, eax
retn
sub_100163F0 endp




sub_10016406 proc near
push	offset off_1001D838 ; struct CRuntimeClass *
call	?AfxClassInit@@YGXPAUCRuntimeClass@@@Z ; AfxClassInit(CRuntimeClass *)
retn
sub_10016406 endp

; [00000056 BYTES: COLLAPSED FUNCTION COleException::GetErrorMessage(char *,uint,uint *). PRESS	KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION AfxThrowOleException(long). PRESS	KEYPAD "+" TO EXPAND]
db 0CCh
; [00000029 BYTES: COLLAPSED FUNCTION CCmdTarget::InternalRelease(void). PRESS KEYPAD "+" TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION CCmdTarget::ExternalRelease(void). PRESS KEYPAD "+" TO EXPAND]
; [000000AE BYTES: COLLAPSED FUNCTION CCmdTarget::GetInterface(void const *). PRESS KEYPAD "+" TO EXPAND]
; [00000060 BYTES: COLLAPSED FUNCTION CCmdTarget::QueryAggregates(void const *). PRESS KEYPAD "+" TO EXPAND]
; [0000001B BYTES: COLLAPSED FUNCTION CCmdTarget::ExternalAddRef(void).	PRESS KEYPAD "+" TO EXPAND]
; [00000040 BYTES: COLLAPSED CHUNK OF FUNCTION CCmdTarget::ExternalQueryInterface(void const *,void * *). PRESS	KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION CCmdTarget::ExternalQueryInterface(void const *,void * *). PRESS KEYPAD "+" TO EXPAND]
; [0000001C BYTES: COLLAPSED FUNCTION AfxPostQuitMessage(int). PRESS KEYPAD "+"	TO EXPAND]
; [0000004F BYTES: COLLAPSED FUNCTION CWinThread::~CWinThread(void). PRESS KEYPAD "+" TO EXPAND]
; [000000B4 BYTES: COLLAPSED FUNCTION AfxWinTerm(void).	PRESS KEYPAD "+" TO EXPAND]
align 10h



sub_10016790 proc near
push	dword ptr [ebp-10h] ; void *
call	??3CNoTrackObject@@SGXPAX@Z ; CNoTrackObject::operator delete(void *)
retn
sub_10016790 endp




sub_10016799 proc near
mov	eax, offset stru_1001A524
jmp	___CxxFrameHandler
sub_10016799 endp




sub_100167A3 proc near
mov	ecx, [ebp-10h]
jmp	??1CWinThread@@UAE@XZ ;	CWinThread::~CWinThread(void)
sub_100167A3 endp




sub_100167AB proc near
mov	eax, offset stru_1001A548
jmp	___CxxFrameHandler
sub_100167AB endp




sub_100167B5 proc near

; FUNCTION CHUNK AT 1000294C SIZE 0000000A BYTES

lea	ecx, [ebp-10h]
jmp	loc_1000294C
sub_100167B5 endp




sub_100167BD proc near
mov	eax, offset stru_1001A56C
jmp	___CxxFrameHandler
sub_100167BD endp




sub_100167C7 proc near
lea	ecx, [ebp+0Ch]
jmp	loc_1000294C
sub_100167C7 endp




sub_100167CF proc near
mov	eax, offset stru_1001A590
jmp	___CxxFrameHandler
sub_100167CF endp




sub_100167D9 proc near
mov	ecx, [ebp-10h]
jmp	loc_1000294C
sub_100167D9 endp




sub_100167E1 proc near
mov	eax, offset stru_1001A5B4
jmp	___CxxFrameHandler
sub_100167E1 endp




sub_100167EB proc near
lea	ecx, [ebp-120h]
jmp	loc_1000294C
sub_100167EB endp




sub_100167F6 proc near
mov	eax, offset unk_1001A60C
jmp	___CxxFrameHandler
sub_100167F6 endp




sub_10016800 proc near
lea	ecx, [ebp-11Ch]
jmp	loc_1000294C
sub_10016800 endp




sub_1001680B proc near
lea	ecx, [ebp-12Ch]
jmp	loc_1000294C
sub_1001680B endp




sub_10016816 proc near
lea	ecx, [ebp-124h]
jmp	loc_1000294C
sub_10016816 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?Unregister@CWinApp@@UAEHXZ. PRESS KEYPAD "+"	TO EXPAND]

loc_1001682B:
mov	eax, offset stru_1001A700
jmp	___CxxFrameHandler



sub_10016835 proc near
mov	ecx, [ebp-10h]
jmp	??1CCmdTarget@@UAE@XZ ;	CCmdTarget::~CCmdTarget(void)
sub_10016835 endp




sub_1001683D proc near
mov	eax, offset stru_1001A748
jmp	___CxxFrameHandler
sub_1001683D endp




sub_10016847 proc near
push	dword ptr [ebp-10h] ; void *
call	??3CNoTrackObject@@SGXPAX@Z ; CNoTrackObject::operator delete(void *)
retn
sub_10016847 endp




sub_10016850 proc near
mov	eax, offset stru_1001A724
jmp	___CxxFrameHandler
sub_10016850 endp




sub_1001685A proc near
push	dword ptr [ebp-10h] ; void *
call	sub_10002520
retn
sub_1001685A endp




sub_10016863 proc near
mov	eax, offset stru_1001A800
jmp	___CxxFrameHandler
sub_10016863 endp


loc_1001686D:
mov	eax, offset stru_1001A8F4
jmp	___CxxFrameHandler



sub_10016877 proc near
push	offset unk_1001E9A8
push	dword ptr [ebp-10h]
call	nullsub_2
pop	ecx
pop	ecx
retn
sub_10016877 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?GetData@CThreadLocalObject@@QAEPAVCNoTrackObject@@P6GPAV2@XZ@Z. PRESS KEYPAD	"+" TO EXPAND]



sub_10016891 proc near
mov	ecx, [ebp-10h]
add	ecx, 1070h
jmp	j_??1CThreadLocalObject@@QAE@XZ	; CThreadLocalObject::~CThreadLocalObject(void)
sub_10016891 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$??1AFX_MODULE_STATE@@UAE@XZ. PRESS KEYPAD "+"	TO EXPAND]

__ehhandler$?AfxUnlockTempMaps@@YGHH@Z:
mov	eax, offset stru_1001A98C
jmp	___CxxFrameHandler



sub_100168B3 proc near
mov	ecx, [ebp-10h]
add	ecx, 4
jmp	j_?FreeAll@CFixedAllocNoSync@@QAEXXZ ; CFixedAllocNoSync::FreeAll(void)
sub_100168B3 endp




sub_100168BE proc near
mov	ecx, [ebp-10h]
add	ecx, 1Ch
jmp	sub_1000E9D0
sub_100168BE endp




sub_100168C9 proc near
mov	ecx, [ebp-10h]
add	ecx, 38h
jmp	sub_1000E9D0
sub_100168C9 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$??0CHandleMap@@QAE@PAUCRuntimeClass@@P6GXPAVCObject@@@Z2IH@Z.	PRESS KEYPAD "+" TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?FromHandle@CHandleMap@@QAEPAVCObject@@PAX@Z.	PRESS KEYPAD "+" TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_8. PRESS KEYPAD "+" TO EXPAND]

loc_100168F2:
mov	eax, offset stru_1001AA78
jmp	___CxxFrameHandler



sub_100168FC proc near
push	dword ptr [ebp-10h] ; void *
call	sub_10002520
retn
sub_100168FC endp




sub_10016905 proc near
mov	eax, offset stru_1001AA9C
jmp	___CxxFrameHandler
sub_10016905 endp




sub_1001690F proc near
push	dword ptr [ebp+8] ; int
push	dword ptr [ebp-10h] ; void *
call	??3CObject@@SGXPAX0@Z ;	CObject::operator delete(void *,void *)
retn
sub_1001690F endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?Construct@?$ConstructDestruct@VCWnd@@@@SGXPAVCObject@@@Z. PRESS KEYPAD "+" TO EXPAND]



sub_10016925 proc near
push	dword ptr [ebp+8] ; void *
call	j__free
pop	ecx
retn
sub_10016925 endp

; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_50. PRESS	KEYPAD "+" TO EXPAND]



sub_10016939 proc near
mov	eax, offset stru_1001AB34
jmp	___CxxFrameHandler
sub_10016939 endp




sub_10016943 proc near
mov	ecx, [ebp-10h]
jmp	??1CCmdTarget@@UAE@XZ ;	CCmdTarget::~CCmdTarget(void)
sub_10016943 endp




sub_1001694B proc near
mov	eax, offset stru_1001AB58
jmp	___CxxFrameHandler
sub_1001694B endp




sub_10016955 proc near
lea	ecx, [ebp-5Ch]
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_10016955 endp




sub_1001695D proc near
mov	eax, offset stru_1001AB7C
jmp	___CxxFrameHandler
sub_1001695D endp




sub_10016967 proc near
push	dword ptr [ebp-1Ch] ; void *
call	j__free
pop	ecx
retn
sub_10016967 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?CreateInstance@?$CMFCComObject@VCAccessibleProxy@ATL@@@@SGJPAPAV1@@Z. PRESS KEYPAD "+" TO EXPAND]

loc_1001697B:
mov	eax, offset stru_1001AC24
jmp	___CxxFrameHandler



sub_10016985 proc near
lea	ecx, [ebp-24h]
jmp	??1CDC@@UAE@XZ	; CDC::~CDC(void)
sub_10016985 endp




sub_1001698D proc near
lea	ecx, [ebp-74h]
jmp	??1CWnd@@UAE@XZ	; CWnd::~CWnd(void)
sub_1001698D endp




sub_10016995 proc near
lea	ecx, [ebp-24h]
jmp	??1CDC@@UAE@XZ	; CDC::~CDC(void)
sub_10016995 endp

; [0000000A BYTES: COLLAPSED FUNCTION __ehhandler$?OnWndMsg@CWnd@@MAEHIIJPAJ@Z.	PRESS KEYPAD "+" TO EXPAND]



sub_100169A7 proc near

; FUNCTION CHUNK AT 10010A98 SIZE 0000000D BYTES

lea	ecx, [ebp+0Ch]
jmp	unknown_libname_32 ; MFC 3.1-10.0 32bit
sub_100169A7 endp




sub_100169AF proc near
mov	eax, offset stru_1001AC7C
jmp	___CxxFrameHandler
sub_100169AF endp




sub_100169B9 proc near

; FUNCTION CHUNK AT 100039D4 SIZE 0000000D BYTES

lea	ecx, [ebp-10h]
jmp	loc_100039D4
sub_100169B9 endp




sub_100169C1 proc near
mov	eax, offset stru_1001ACA0
jmp	___CxxFrameHandler
sub_100169C1 endp




sub_100169CB proc near
push	dword ptr [ebp+8] ; void *
call	j__free
pop	ecx
retn
sub_100169CB endp

; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_51. PRESS	KEYPAD "+" TO EXPAND]



sub_100169DF proc near
lea	ecx, [ebp-14h]
jmp	loc_1000294C
sub_100169DF endp




sub_100169E7 proc near
lea	ecx, [ebp+10h]
jmp	loc_1000294C
sub_100169E7 endp




sub_100169EF proc near
mov	eax, offset unk_1001AD24
jmp	___CxxFrameHandler
sub_100169EF endp




sub_100169F9 proc near
mov	ecx, [ebp-10h]
add	ecx, 0Ch
jmp	loc_1000294C
sub_100169F9 endp




sub_10016A04 proc near
mov	eax, offset stru_1001AD48
jmp	___CxxFrameHandler
sub_10016A04 endp




sub_10016A0E proc near
push	dword ptr [ebp-14h] ; void *
call	sub_10002520
retn
sub_10016A0E endp




sub_10016A17 proc near
mov	eax, offset stru_1001ADAC
jmp	___CxxFrameHandler
sub_10016A17 endp




sub_10016A21 proc near
lea	ecx, [ebp-10h]
jmp	loc_1000294C
sub_10016A21 endp




sub_10016A29 proc near
mov	eax, offset stru_1001ADD0
jmp	___CxxFrameHandler
sub_10016A29 endp

align 10h


; Attributes: bp-based frame

sub_10016A40 proc near
push	ebp
mov	ebp, esp
mov	ecx, offset unk_1001E720
call	sub_10001010
push	offset sub_10016A90 ; void (__cdecl *)()
call	_atexit
add	esp, 4
pop	ebp
retn
sub_10016A40 endp




sub_10016A5C proc near
call	sub_10014F9A
push	offset sub_100026CE ; void (__cdecl *)()
call	_atexit
pop	ecx
mov	byte_1001E7CC, al
retn
sub_10016A5C endp




sub_10016A72 proc near
mov	ecx, offset unk_10020C18
call	sub_1000E1A1
push	offset sub_10016A9F ; void (__cdecl *)()
call	_atexit
pop	ecx
retn
sub_10016A72 endp

align 10h


; Attributes: bp-based frame

; void __cdecl sub_10016A90()
sub_10016A90 proc near
push	ebp
mov	ebp, esp
mov	ecx, offset unk_1001E720
call	sub_100024C0
pop	ebp
retn
sub_10016A90 endp




; void __cdecl sub_10016A9F()
sub_10016A9F proc near

; FUNCTION CHUNK AT 1000E154 SIZE 0000001D BYTES
; FUNCTION CHUNK AT 1000E18B SIZE 00000016 BYTES

mov	ecx, offset unk_10020C18
jmp	loc_1000E18B
sub_10016A9F endp

align 800h
_text ends

; Section 2. (virtual address 00017000)
; Virtual size			: 000056D5 (  22229.)
; Section size in file		: 00006000 (  24576.)
; Offset to raw	data for section: 00017000
; Flags	40000040: Data Readable
; Alignment	: default
;
; Imports from ADVAPI32.dll
;

; Segment type:	Externs
; _idata
; LSTATUS __stdcall RegQueryValueExA(HKEY hKey,	LPCSTR lpValueName, LPDWORD lpReserved,	LPDWORD	lpType,	LPBYTE lpData, LPDWORD lpcbData)
extrn RegQueryValueExA:dword
; LSTATUS __stdcall RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY	phkResult)
extrn RegOpenKeyExA:dword
; LSTATUS __stdcall RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
extrn RegDeleteKeyA:dword
; LSTATUS __stdcall RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR	lpName,	DWORD cchName)
extrn RegEnumKeyA:dword
; LSTATUS __stdcall RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
extrn RegOpenKeyA:dword
; LSTATUS __stdcall RegQueryValueA(HKEY	hKey, LPCSTR lpSubKey, LPSTR lpData, PLONG lpcbData)
extrn RegQueryValueA:dword
; LSTATUS __stdcall RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey,	DWORD Reserved,	LPSTR lpClass, DWORD dwOptions,	REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
extrn RegCreateKeyExA:dword
; LSTATUS __stdcall RegSetValueExA(HKEY	hKey, LPCSTR lpValueName, DWORD	Reserved, DWORD	dwType,	const BYTE *lpData, DWORD cbData)
extrn RegSetValueExA:dword
; LSTATUS __stdcall RegCloseKey(HKEY hKey)
extrn RegCloseKey:dword

;
; Imports from COMCTL32.dll
;
; void __stdcall InitCommonControls()
extrn InitCommonControls:dword

;
; Imports from GDI32.dll
;
; COLORREF __stdcall SetBkColor(HDC hdc, COLORREF color)
extrn SetBkColor:dword
; BOOL __stdcall RestoreDC(HDC hdc, int	nSavedDC)
extrn RestoreDC:dword
; int __stdcall	SaveDC(HDC hdc)
extrn SaveDC:dword
; BOOL __stdcall DeleteObject(HGDIOBJ ho)
extrn DeleteObject:dword
; int __stdcall	GetDeviceCaps(HDC hdc, int index)
extrn GetDeviceCaps:dword
; HGDIOBJ __stdcall GetStockObject(int i)
extrn GetStockObject:dword
; BOOL __stdcall DeleteDC(HDC hdc)
extrn DeleteDC:dword
; BOOL __stdcall ScaleWindowExtEx(HDC hdc, int xn, int xd, int yn, int yd, LPSIZE lpsz)
extrn ScaleWindowExtEx:dword
; BOOL __stdcall SetWindowExtEx(HDC hdc, int x,	int y, LPSIZE lpsz)
extrn SetWindowExtEx:dword
; BOOL __stdcall ScaleViewportExtEx(HDC	hdc, int xn, int dx, int yn, int yd, LPSIZE lpsz)
extrn ScaleViewportExtEx:dword
; BOOL __stdcall SetViewportExtEx(HDC hdc, int x, int y, LPSIZE	lpsz)
extrn SetViewportExtEx:dword
; BOOL __stdcall OffsetViewportOrgEx(HDC hdc, int x, int y, LPPOINT lppt)
extrn OffsetViewportOrgEx:dword
; BOOL __stdcall SetViewportOrgEx(HDC hdc, int x, int y, LPPOINT lppt)
extrn SetViewportOrgEx:dword
; HGDIOBJ __stdcall SelectObject(HDC hdc, HGDIOBJ h)
extrn SelectObject:dword
; int __stdcall	Escape(HDC hdc,	int iEscape, int cjIn, LPCSTR pvIn, LPVOID pvOut)
extrn Escape:dword
; BOOL __stdcall ExtTextOutA(HDC hdc, int x, int y, UINT options, const	RECT *lprect, LPCSTR lpString, UINT c, const INT *lpDx)
extrn ExtTextOutA:dword
; BOOL __stdcall TextOutA(HDC hdc, int x, int y, LPCSTR	lpString, int c)
extrn TextOutA:dword
; BOOL __stdcall RectVisible(HDC hdc, const RECT *lprect)
extrn RectVisible:dword
; BOOL __stdcall PtVisible(HDC hdc, int	x, int y)
extrn PtVisible:dword
; int __stdcall	GetClipBox(HDC hdc, LPRECT lprect)
extrn GetClipBox:dword
; int __stdcall	SetMapMode(HDC hdc, int	iMode)
extrn SetMapMode:dword
; COLORREF __stdcall SetTextColor(HDC hdc, COLORREF color)
extrn SetTextColor:dword
; HBITMAP __stdcall CreateBitmap(int nWidth, int nHeight, UINT nPlanes,	UINT nBitCount,	const void *lpBits)
extrn CreateBitmap:dword

;
; Imports from HID.DLL
;
extrn __imp_HidD_GetFeature:dword
extrn __imp_HidD_SetFeature:dword
extrn __imp_HidD_GetAttributes:dword
extrn __imp_HidD_GetPreparsedData:dword
extrn __imp_HidP_GetCaps:dword
extrn __imp_HidD_FreePreparsedData:dword
extrn __imp_HidD_GetHidGuid:dword

;
; Imports from KERNEL32.dll
;
; BOOL __stdcall SetStdHandle(DWORD nStdHandle,	HANDLE hHandle)
extrn SetStdHandle:dword
; BOOL __stdcall IsBadCodePtr(FARPROC lpfn)
extrn IsBadCodePtr:dword
; BOOL __stdcall IsBadReadPtr(const void *lp, UINT_PTR ucb)
extrn IsBadReadPtr:dword
; BOOL __stdcall GetStringTypeW(DWORD dwInfoType, LPCWSTR lpSrcStr, int	cchSrc,	LPWORD lpCharType)
extrn GetStringTypeW:dword
; BOOL __stdcall GetStringTypeA(LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr,	int cchSrc, LPWORD lpCharType)
extrn GetStringTypeA:dword
; int __stdcall	LCMapStringW(LCID Locale, DWORD	dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int	cchDest)
extrn LCMapStringW:dword
; int __stdcall	LCMapStringA(LCID Locale, DWORD	dwMapFlags, LPCSTR lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest)
extrn LCMapStringA:dword
; LPTOP_LEVEL_EXCEPTION_FILTER __stdcall SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
extrn SetUnhandledExceptionFilter:dword
; LONG __stdcall UnhandledExceptionFilter(struct _EXCEPTION_POINTERS *ExceptionInfo)
extrn UnhandledExceptionFilter:dword
; LPWCH	__stdcall GetEnvironmentStringsW()
extrn GetEnvironmentStringsW:dword
; BOOL __stdcall FreeEnvironmentStringsW(LPWCH)
extrn FreeEnvironmentStringsW:dword
; LPCH __stdcall GetEnvironmentStrings()
extrn GetEnvironmentStrings:dword
; BOOL __stdcall FreeEnvironmentStringsA(LPCH)
extrn FreeEnvironmentStringsA:dword
; void __stdcall GetStartupInfoA(LPSTARTUPINFOA	lpStartupInfo)
extrn GetStartupInfoA:dword
; DWORD	__stdcall GetFileType(HANDLE hFile)
extrn GetFileType:dword
; HANDLE __stdcall GetStdHandle(DWORD nStdHandle)
extrn GetStdHandle:dword
; UINT __stdcall SetHandleCount(UINT uNumber)
extrn SetHandleCount:dword
; void __stdcall GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
extrn GetSystemTimeAsFileTime:dword
; DWORD	__stdcall GetCurrentProcessId()
extrn GetCurrentProcessId:dword
; DWORD	__stdcall GetTickCount()
extrn GetTickCount:dword
; BOOL __stdcall QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
extrn QueryPerformanceCounter:dword
; BOOL __stdcall IsBadWritePtr(LPVOID lp, UINT_PTR ucb)
extrn IsBadWritePtr:dword
; BOOL __stdcall VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
extrn VirtualFree:dword
; HANDLE __stdcall HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
extrn HeapCreate:dword
; BOOL __stdcall HeapDestroy(HANDLE hHeap)
extrn HeapDestroy:dword
; LPVOID __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
extrn HeapReAlloc:dword
; SIZE_T __stdcall HeapSize(HANDLE hHeap, DWORD	dwFlags, LPCVOID lpMem)
extrn HeapSize:dword
; BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT	uExitCode)
extrn TerminateProcess:dword
; LPSTR	__stdcall GetCommandLineA()
extrn GetCommandLineA:dword
; SIZE_T __stdcall VirtualQuery(LPCVOID	lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
extrn VirtualQuery:dword
; void __stdcall GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
extrn GetSystemInfo:dword
; LPVOID __stdcall VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
extrn VirtualAlloc:dword
; BOOL __stdcall VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
extrn VirtualProtect:dword
; void __stdcall RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD	ExceptionRecord, PVOID ReturnValue)
extrn __imp_RtlUnwind:dword
; void __stdcall ExitProcess(UINT uExitCode)
extrn ExitProcess:dword
; LPVOID __stdcall HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
extrn HeapAlloc:dword
; BOOL __stdcall HeapFree(HANDLE hHeap,	DWORD dwFlags, LPVOID lpMem)
extrn HeapFree:dword
; UINT __stdcall GetOEMCP()
extrn GetOEMCP:dword
; BOOL __stdcall GetCPInfo(UINT	CodePage, LPCPINFO lpCPInfo)
extrn GetCPInfo:dword
; HANDLE __stdcall GetCurrentProcess()
extrn GetCurrentProcess:dword
; BOOL __stdcall FlushFileBuffers(HANDLE hFile)
extrn FlushFileBuffers:dword
; DWORD	__stdcall SetFilePointer(HANDLE	hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
extrn SetFilePointer:dword
; BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,	LPDWORD	lpNumberOfBytesWritten,	LPOVERLAPPED lpOverlapped)
extrn WriteFile:dword
; UINT __stdcall GlobalGetAtomNameA(ATOM nAtom,	LPSTR lpBuffer,	int nSize)
extrn GlobalGetAtomNameA:dword
; ATOM __stdcall GlobalFindAtomA(LPCSTR	lpString)
extrn GlobalFindAtomA:dword
; int __stdcall	lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2)
extrn lstrcmpW:dword
; void __stdcall RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
extrn RaiseException:dword
; UINT __stdcall GlobalFlags(HGLOBAL hMem)
extrn GlobalFlags:dword
; LONG __stdcall InterlockedIncrement(volatile LONG *lpAddend)
extrn InterlockedIncrement:dword
; BOOL __stdcall WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,	LPCSTR lpString, LPCSTR	lpFileName)
extrn WritePrivateProfileStringA:dword
; UINT __stdcall SetErrorMode(UINT uMode)
extrn SetErrorMode:dword
; LPSTR	__stdcall lstrcatA(LPSTR lpString1, LPCSTR lpString2)
extrn lstrcatA:dword
; LONG __stdcall InterlockedDecrement(volatile LONG *lpAddend)
extrn InterlockedDecrement:dword
; BOOL __stdcall TlsFree(DWORD dwTlsIndex)
extrn TlsFree:dword
; void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
extrn DeleteCriticalSection:dword
; HLOCAL __stdcall LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags)
extrn LocalReAlloc:dword
; BOOL __stdcall TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
extrn TlsSetValue:dword
; DWORD	__stdcall TlsAlloc()
extrn TlsAlloc:dword
; void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
extrn InitializeCriticalSection:dword
; LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)
extrn TlsGetValue:dword
; void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
extrn EnterCriticalSection:dword
; HGLOBAL __stdcall GlobalHandle(LPCVOID pMem)
extrn GlobalHandle:dword
; HGLOBAL __stdcall GlobalReAlloc(HGLOBAL hMem,	SIZE_T dwBytes,	UINT uFlags)
extrn GlobalReAlloc:dword
; void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
extrn LeaveCriticalSection:dword
; HLOCAL __stdcall LocalAlloc(UINT uFlags, SIZE_T uBytes)
extrn LocalAlloc:dword
; void __stdcall SetLastError(DWORD dwErrCode)
extrn SetLastError:dword
; HGLOBAL __stdcall GlobalFree(HGLOBAL hMem)
extrn GlobalFree:dword
; BOOL __stdcall GlobalUnlock(HGLOBAL hMem)
extrn GlobalUnlock:dword
; DWORD	__stdcall FormatMessageA(DWORD dwFlags,	LPCVOID	lpSource, DWORD	dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments)
extrn FormatMessageA:dword
; LPSTR	__stdcall lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength)
extrn lstrcpynA:dword
; HLOCAL __stdcall LocalFree(HLOCAL hMem)
extrn LocalFree:dword
; ATOM __stdcall GlobalAddAtomA(LPCSTR lpString)
extrn GlobalAddAtomA:dword
; HRSRC	__stdcall FindResourceA(HMODULE	hModule, LPCSTR	lpName,	LPCSTR lpType)
extrn FindResourceA:dword
; HGLOBAL __stdcall LoadResource(HMODULE hModule, HRSRC	hResInfo)
extrn LoadResource:dword
; LPVOID __stdcall LockResource(HGLOBAL	hResData)
extrn LockResource:dword
; DWORD	__stdcall SizeofResource(HMODULE hModule, HRSRC	hResInfo)
extrn SizeofResource:dword
; HANDLE __stdcall GetCurrentThread()
extrn GetCurrentThread:dword
; DWORD	__stdcall GetCurrentThreadId()
extrn GetCurrentThreadId:dword
; LPVOID __stdcall GlobalLock(HGLOBAL hMem)
extrn GlobalLock:dword
; HGLOBAL __stdcall GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
extrn GlobalAlloc:dword
; BOOL __stdcall FreeLibrary(HMODULE hLibModule)
extrn FreeLibrary:dword
; ATOM __stdcall GlobalDeleteAtom(ATOM nAtom)
extrn GlobalDeleteAtom:dword
; int __stdcall	lstrcmpA(LPCSTR	lpString1, LPCSTR lpString2)
extrn lstrcmpA:dword
; DWORD	__stdcall GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename,	DWORD nSize)
extrn GetModuleFileNameA:dword
; HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)
extrn GetModuleHandleA:dword
; FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
extrn GetProcAddress:dword
; LCID __stdcall ConvertDefaultLocale(LCID Locale)
extrn ConvertDefaultLocale:dword
; BOOL __stdcall EnumResourceLanguagesA(HMODULE	hModule, LPCSTR	lpType,	LPCSTR lpName, ENUMRESLANGPROCA	lpEnumFunc, LONG_PTR lParam)
extrn EnumResourceLanguagesA:dword
; LPSTR	__stdcall lstrcpyA(LPSTR lpString1, LPCSTR lpString2)
extrn lstrcpyA:dword
; HMODULE __stdcall LoadLibraryA(LPCSTR	lpLibFileName)
extrn LoadLibraryA:dword
; BOOL __stdcall CloseHandle(HANDLE hObject)
extrn CloseHandle:dword
; HANDLE __stdcall CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,	LPCSTR lpName)
extrn CreateEventA:dword
; HANDLE __stdcall CreateFileA(LPCSTR lpFileName, DWORD	dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE	hTemplateFile)
extrn CreateFileA:dword
; DWORD	__stdcall GetLastError()
extrn GetLastError:dword
; BOOL __stdcall CancelIo(HANDLE hFile)
extrn CancelIo:dword
; DWORD	__stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
extrn WaitForSingleObject:dword
; BOOL __stdcall ReadFile(HANDLE hFile,	LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
extrn ReadFile:dword
; BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA	lpVersionInformation)
extrn GetVersionExA:dword
; LONG __stdcall InterlockedExchange(volatile LONG *Target, LONG Value)
extrn InterlockedExchange:dword
; UINT __stdcall GetACP()
extrn GetACP:dword
; int __stdcall	lstrlenA(LPCSTR	lpString)
extrn lstrlenA:dword
; int __stdcall	lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)
extrn lstrcmpiA:dword
; int __stdcall	WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR	lpMultiByteStr,	int cbMultiByte, LPCSTR	lpDefaultChar, LPBOOL lpUsedDefaultChar)
extrn WideCharToMultiByte:dword
; int __stdcall	MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr,	int cchWideChar)
extrn MultiByteToWideChar:dword
; DWORD	__stdcall GetVersion()
extrn GetVersion:dword
; LCID __stdcall GetThreadLocale()
extrn GetThreadLocale:dword
; int __stdcall	GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData)
extrn GetLocaleInfoA:dword

;
; Imports from OLEAUT32.dll
;
; HRESULT __stdcall VariantClear(VARIANTARG *pvarg)
extrn VariantClear:dword
; HRESULT __stdcall VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc,	USHORT wFlags, VARTYPE vt)
extrn VariantChangeType:dword
; void __stdcall VariantInit(VARIANTARG	*pvarg)
extrn VariantInit:dword

;
; Imports from SETUPAPI.dll
;
; BOOL __stdcall SetupDiGetDeviceInterfaceDetailA(HDEVINFO DeviceInfoSet, PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData, PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData, DWORD DeviceInterfaceDetailDataSize, PDWORD RequiredSize, PSP_DEVINFO_DATA DeviceInfoData)
extrn SetupDiGetDeviceInterfaceDetailA:dword
; HDEVINFO __stdcall SetupDiGetClassDevsA(const	GUID *ClassGuid, PCSTR Enumerator, HWND	hwndParent, DWORD Flags)
extrn SetupDiGetClassDevsA:dword
; BOOL __stdcall SetupDiEnumDeviceInterfaces(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, const GUID *InterfaceClassGuid, DWORD MemberIndex, PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData)
extrn SetupDiEnumDeviceInterfaces:dword
; BOOL __stdcall SetupDiDestroyDeviceInfoList(HDEVINFO DeviceInfoSet)
extrn SetupDiDestroyDeviceInfoList:dword

;
; Imports from SHLWAPI.dll
;
; LPSTR	__stdcall PathFindFileNameA(LPCSTR pszPath)
extrn PathFindFileNameA:dword
; LPSTR	__stdcall PathFindExtensionA(LPCSTR pszPath)
extrn PathFindExtensionA:dword

;
; Imports from USER32.dll
;
; HBRUSH __stdcall GetSysColorBrush(int	nIndex)
extrn GetSysColorBrush:dword
; int __stdcall	GetSystemMetrics(int nIndex)
extrn GetSystemMetrics:dword
; HCURSOR __stdcall LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)
extrn LoadCursorA:dword
; HWND __stdcall GetDlgItem(HWND hDlg, int nIDDlgItem)
extrn GetDlgItem:dword
; LONG __stdcall SetWindowLongA(HWND hWnd, int nIndex, LONG dwNewLong)
extrn SetWindowLongA:dword
; BOOL __stdcall ShowWindow(HWND hWnd, int nCmdShow)
extrn ShowWindow:dword
; BOOL __stdcall SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)
extrn SetWindowPos:dword
; BOOL __stdcall CopyRect(LPRECT lprcDst, const	RECT *lprcSrc)
extrn CopyRect:dword
; BOOL __stdcall GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT *lpwndpl)
extrn GetWindowPlacement:dword
; BOOL __stdcall IsIconic(HWND hWnd)
extrn IsIconic:dword
; BOOL __stdcall SystemParametersInfoA(UINT uiAction, UINT uiParam, PVOID pvParam, UINT	fWinIni)
extrn SystemParametersInfoA:dword
; void __stdcall PostQuitMessage(int nExitCode)
extrn PostQuitMessage:dword
; BOOL __stdcall PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
extrn PostMessageA:dword
; HCURSOR __stdcall SetCursor(HCURSOR hCursor)
extrn SetCursor:dword
; LRESULT __stdcall SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
extrn SendMessageA:dword
; BOOL __stdcall EnableWindow(HWND hWnd, BOOL bEnable)
extrn EnableWindow:dword
; BOOL __stdcall IsWindowEnabled(HWND hWnd)
extrn IsWindowEnabled:dword
; HWND __stdcall GetLastActivePopup(HWND hWnd)
extrn GetLastActivePopup:dword
; LONG __stdcall GetWindowLongA(HWND hWnd, int nIndex)
extrn GetWindowLongA:dword
; HWND __stdcall GetParent(HWND	hWnd)
extrn GetParent:dword
; int __stdcall	MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,	UINT uType)
extrn MessageBoxA:dword
; BOOL __stdcall ValidateRect(HWND hWnd, const RECT *lpRect)
extrn ValidateRect:dword
; BOOL __stdcall GetCursorPos(LPPOINT lpPoint)
extrn GetCursorPos:dword
; BOOL __stdcall PeekMessageA(LPMSG lpMsg, HWND	hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
extrn PeekMessageA:dword
; SHORT	__stdcall GetKeyState(int nVirtKey)
extrn GetKeyState:dword
; BOOL __stdcall IsWindowVisible(HWND hWnd)
extrn IsWindowVisible:dword
; HWND __stdcall GetActiveWindow()
extrn GetActiveWindow:dword
; LRESULT __stdcall DispatchMessageA(const MSG *lpMsg)
extrn DispatchMessageA:dword
; BOOL __stdcall TranslateMessage(const	MSG *lpMsg)
extrn TranslateMessage:dword
; BOOL __stdcall GetMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
extrn GetMessageA:dword
; LRESULT __stdcall CallNextHookEx(HHOOK hhk, int nCode, WPARAM	wParam,	LPARAM lParam)
extrn CallNextHookEx:dword
; HHOOK	__stdcall SetWindowsHookExA(int	idHook,	HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
extrn SetWindowsHookExA:dword
; HBITMAP __stdcall LoadBitmapA(HINSTANCE hInstance, LPCSTR lpBitmapName)
extrn LoadBitmapA:dword
; LONG __stdcall GetMenuCheckMarkDimensions()
extrn GetMenuCheckMarkDimensions:dword
; DWORD	__stdcall CheckMenuItem(HMENU hMenu, UINT uIDCheckItem,	UINT uCheck)
extrn CheckMenuItem:dword
; BOOL __stdcall EnableMenuItem(HMENU hMenu, UINT uIDEnableItem, UINT uEnable)
extrn EnableMenuItem:dword
; UINT __stdcall GetMenuState(HMENU hMenu, UINT	uId, UINT uFlags)
extrn GetMenuState:dword
; BOOL __stdcall ModifyMenuA(HMENU hMnu, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem)
extrn ModifyMenuA:dword
; HWND __stdcall GetFocus()
extrn GetFocus:dword
; BOOL __stdcall SetMenuItemBitmaps(HMENU hMenu, UINT uPosition, UINT uFlags, HBITMAP hBitmapUnchecked,	HBITMAP	hBitmapChecked)
extrn SetMenuItemBitmaps:dword
; HMENU	__stdcall GetSubMenu(HMENU hMenu, int nPos)
extrn GetSubMenu:dword
; int __stdcall	GetMenuItemCount(HMENU hMenu)
extrn GetMenuItemCount:dword
; UINT __stdcall GetMenuItemID(HMENU hMenu, int	nPos)
extrn GetMenuItemID:dword
; BOOL __stdcall UnhookWindowsHookEx(HHOOK hhk)
extrn UnhookWindowsHookEx:dword
; BOOL __stdcall UnregisterClassA(LPCSTR lpClassName, HINSTANCE	hInstance)
extrn UnregisterClassA:dword
; int wsprintfA(LPSTR, LPCSTR, ...)
extrn wsprintfA:dword
; int __stdcall	GetClassNameA(HWND hWnd, LPSTR lpClassName, int	nMaxCount)
extrn GetClassNameA:dword
; BOOL __stdcall SetWindowTextA(HWND hWnd, LPCSTR lpString)
extrn SetWindowTextA:dword
; int __stdcall	GetWindowTextA(HWND hWnd, LPSTR	lpString, int nMaxCount)
extrn GetWindowTextA:dword
; BOOL __stdcall PtInRect(const	RECT *lprc, POINT pt)
extrn PtInRect:dword
; BOOL __stdcall GetWindowRect(HWND hWnd, LPRECT lpRect)
extrn GetWindowRect:dword
; int __stdcall	GetDlgCtrlID(HWND hWnd)
extrn GetDlgCtrlID:dword
; HWND __stdcall GetWindow(HWND	hWnd, UINT uCmd)
extrn GetWindow:dword
; BOOL __stdcall ClientToScreen(HWND hWnd, LPPOINT lpPoint)
extrn ClientToScreen:dword
; LONG __stdcall TabbedTextOutA(HDC hdc, int x,	int y, LPCSTR lpString,	int chCount, int nTabPositions,	const INT *lpnTabStopPositions,	int nTabOrigin)
extrn TabbedTextOutA:dword
; int __stdcall	DrawTextA(HDC hdc, LPCSTR lpchText, int	cchText, LPRECT	lprc, UINT format)
extrn DrawTextA:dword
; int __stdcall	DrawTextExA(HDC	hdc, LPSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp)
extrn DrawTextExA:dword
; BOOL __stdcall GrayStringA(HDC hDC, HBRUSH hBrush, GRAYSTRINGPROC lpOutputFunc, LPARAM lpData, int nCount, int X, int	Y, int nWidth, int nHeight)
extrn GrayStringA:dword
; DWORD	__stdcall GetSysColor(int nIndex)
extrn GetSysColor:dword
; HDC __stdcall	GetDC(HWND hWnd)
extrn GetDC:dword
; int __stdcall	ReleaseDC(HWND hWnd, HDC hDC)
extrn ReleaseDC:dword
; BOOL __stdcall DestroyMenu(HMENU hMenu)
extrn DestroyMenu:dword
; UINT __stdcall RegisterWindowMessageA(LPCSTR lpString)
extrn RegisterWindowMessageA:dword
; BOOL __stdcall WinHelpA(HWND hWndMain, LPCSTR	lpszHelp, UINT uCommand, ULONG_PTR dwData)
extrn WinHelpA:dword
; HWND __stdcall GetCapture()
extrn GetCapture:dword
; HWND __stdcall CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y,	int nWidth, int	nHeight, HWND hWndParent, HMENU	hMenu, HINSTANCE hInstance, LPVOID lpParam)
extrn CreateWindowExA:dword
; DWORD	__stdcall GetClassLongA(HWND hWnd, int nIndex)
extrn GetClassLongA:dword
; BOOL __stdcall GetClassInfoExA(HINSTANCE hInstance, LPCSTR lpszClass,	LPWNDCLASSEXA lpwcx)
extrn GetClassInfoExA:dword
; BOOL __stdcall SetPropA(HWND hWnd, LPCSTR lpString, HANDLE hData)
extrn SetPropA:dword
; HANDLE __stdcall GetPropA(HWND hWnd, LPCSTR lpString)
extrn GetPropA:dword
; HANDLE __stdcall RemovePropA(HWND hWnd, LPCSTR lpString)
extrn RemovePropA:dword
; HWND __stdcall GetForegroundWindow()
extrn GetForegroundWindow:dword
; HWND __stdcall GetTopWindow(HWND hWnd)
extrn GetTopWindow:dword
; BOOL __stdcall DestroyWindow(HWND hWnd)
extrn DestroyWindow:dword
; LONG __stdcall GetMessageTime()
extrn GetMessageTime:dword
; DWORD	__stdcall GetMessagePos()
extrn GetMessagePos:dword
; HICON	__stdcall LoadIconA(HINSTANCE hInstance, LPCSTR	lpIconName)
extrn LoadIconA:dword
; int __stdcall	MapWindowPoints(HWND hWndFrom, HWND hWndTo, LPPOINT lpPoints, UINT cPoints)
extrn MapWindowPoints:dword
; BOOL __stdcall SetForegroundWindow(HWND hWnd)
extrn SetForegroundWindow:dword
; BOOL __stdcall GetClientRect(HWND hWnd, LPRECT lpRect)
extrn GetClientRect:dword
; HMENU	__stdcall GetMenu(HWND hWnd)
extrn GetMenu:dword
; BOOL __stdcall AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)
extrn AdjustWindowRectEx:dword
; BOOL __stdcall GetClassInfoA(HINSTANCE hInstance, LPCSTR lpClassName,	LPWNDCLASSA lpWndClass)
extrn GetClassInfoA:dword
; ATOM __stdcall RegisterClassA(const WNDCLASSA	*lpWndClass)
extrn RegisterClassA:dword
; LRESULT __stdcall DefWindowProcA(HWND	hWnd, UINT Msg,	WPARAM wParam, LPARAM lParam)
extrn DefWindowProcA:dword
; LRESULT __stdcall CallWindowProcA(WNDPROC lpPrevWndFunc, HWND	hWnd, UINT Msg,	WPARAM wParam, LPARAM lParam)
extrn CallWindowProcA:dword

;
; Imports from WINSPOOL.DRV
;
; BOOL __stdcall OpenPrinterA(LPSTR pPrinterName, LPHANDLE phPrinter, LPPRINTER_DEFAULTSA pDefault)
extrn __imp_OpenPrinterA:dword
; LONG __stdcall DocumentPropertiesA(HWND hWnd,	HANDLE hPrinter, LPSTR pDeviceName, PDEVMODEA pDevModeOutput, PDEVMODEA	pDevModeInput, DWORD fMode)
extrn __imp_DocumentPropertiesA:dword
; BOOL __stdcall ClosePrinter(HANDLE hPrinter)
extrn __imp_ClosePrinter:dword



; Segment type:	Pure data
; Segment permissions: Read
_rdata segment para public 'DATA' use32
assume cs:_rdata
;org 100173FCh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  8Eh	; Ž
db 0F8h	; ø
db  93h	; “
db  4Ah	; J
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db  50h	; P
db    0
db    0
db    0
db  7Ch	; |
db  9Ah	; š
db    1
db    0
db  7Ch	; |
db  9Ah	; š
db    1
db    0
; char Name[4]
Name db	4 dup(0)
off_10017420 dd	offset off_10017548
dd offset unk_10017428
unk_10017428 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10017440 dd	offset sub_10014703
dd offset sub_10002490
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?OnCmdMsg@CCmdTarget@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z ; CCmdTarget::OnCmdMsg(uint,int,void	*,AFX_CMDHANDLERINFO *)
dd offset ?OnFinalRelease@CCmdTarget@@UAEXXZ ; CCmdTarget::OnFinalRelease(void)
dd offset sub_1000F571
dd offset sub_1000F5CF
dd offset sub_10010843
dd offset sub_10010843
dd offset ?GetTypeLib@CCmdTarget@@UAEJKPAPAUITypeLib@@@Z ; CCmdTarget::GetTypeLib(ulong,ITypeLib * *)
dd offset sub_10001000
dd offset sub_1000F5D4
dd offset sub_1000F585
dd offset sub_1000F5C9
dd offset sub_1000F591
dd offset sub_1000F58B
dd offset sub_1000F5C5
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_10001040
dd offset ?Run@CWinApp@@UAEHXZ ; CWinApp::Run(void)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z_0 ; std::allocator<char>::allocate(uint)
dd offset j_?AfxInternalPumpMessage@@YGHXZ ; AfxInternalPumpMessage(void)
dd offset ?OnIdle@CWinApp@@UAEHJ@Z ; CWinApp::OnIdle(long)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z ; std::allocator<char>::allocate(uint)
dd offset ?ExitInstance@CWinApp@@UAEHXZ	; CWinApp::ExitInstance(void)
dd offset ?ProcessWndProcException@CWinApp@@UAEJPAVCException@@PBUtagMSG@@@Z ; CWinApp::ProcessWndProcException(CException *,tagMSG const *)
dd offset ?ProcessMessageFilter@CWinThread@@UAEHHPAUtagMSG@@@Z ; CWinThread::ProcessMessageFilter(int,tagMSG *)
dd offset ?GetMainWnd@CWinThread@@UAEPAVCWnd@@XZ ; CWinThread::GetMainWnd(void)
dd offset ?Delete@CWinThread@@UAEXXZ ; CWinThread::Delete(void)
dd offset nullsub_1
dd offset sub_10014869
dd offset ?Unregister@CWinApp@@UAEHXZ ;	CWinApp::Unregister(void)
dd offset sub_10013AC0
dd offset unknown_libname_38 ; MFC 3.1-10.0 32bit
dd offset ?InitApplication@CWinApp@@UAEHXZ ; CWinApp::InitApplication(void)
dd offset ?SaveAllModified@CWinApp@@UAEHXZ ; CWinApp::SaveAllModified(void)
dd offset ?DoMessageBox@CWinApp@@UAEHPBDII@Z ; CWinApp::DoMessageBox(char const	*,uint,uint)
dd offset ?DoWaitCursor@CWinApp@@UAEXH@Z ; CWinApp::DoWaitCursor(int)
dd offset unknown_libname_39 ; MFC 3.1-10.0 32bit
dd offset sub_1000EC37
dd offset sub_1000EC6B
dd offset ?WinHelpInternal@CWinApp@@UAEXKI@Z ; CWinApp::WinHelpInternal(ulong,uint)
dd offset ?LoadAppLangResourceDLL@CWinApp@@UAEPAUHINSTANCE__@@XZ ; CWinApp::LoadAppLangResourceDLL(void)
dd offset ?LoadSysPolicies@CWinApp@@UAEHXZ ; CWinApp::LoadSysPolicies(void)
aInvalidDatetim	db 'Invalid DateTime',0
align 4
aInvalidDatet_0	db 'Invalid DateTimeSpan',0
unk_10017521 db	   0
db    0
db    0
off_10017524 dd	offset aCwinapp	; "CWinApp"
db 0A0h	;  
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017864
align 10h
aCwinapp db 'CWinApp',0
off_10017548 dd	offset unk_10017958
dd offset unk_10017550
unk_10017550 db	 11h
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db  41h	; A
db 0E1h	; á
db    0
db    0
db  41h	; A
db 0E1h	; á
db    0
db    0
db  35h	; 5
db    0
db    0
db    0
dd offset ?OnAppExit@CWinApp@@IAEXXZ ; CWinApp::OnAppExit(void)
db  11h
db    1
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db  10h
db 0E1h	; á
db    0
db    0
db  10h
db 0E1h	; á
db    0
db    0
db  3Dh	; =
db    0
db    0
db    0
dd offset ?OnUpdateRecentFileMenu@CWinApp@@IAEXPAVCCmdUI@@@Z ; CWinApp::OnUpdateRecentFileMenu(CCmdUI *)
db  11h
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db  10h
db 0E1h	; á
db    0
db    0
db  1Fh
db 0E1h	; á
db    0
db    0
db  38h	; 8
db    0
db    0
db    0
dd offset ?OnOpenRecentFile@CWinApp@@IAEHI@Z ; CWinApp::OnOpenRecentFile(uint)
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; char KeyName[]
KeyName	db 'PreviewPages',0
align 10h
; char aSettings[]
aSettings db 'Settings',0
align 4
; char aLoc[4]
aLoc db	'LOC',0
; char aNtdll_dll[]
aNtdll_dll db 'ntdll.dll',0
align 4
; char asc_100175DC[]
asc_100175DC db	'%x',0
align 10h
; char SubKey[]
SubKey db 'Control Panel\Desktop\ResourceLocal'
db 'e',0
align 4
; char aGetsystemdefau[]
aGetsystemdefau	db 'GetSystemDefaultUILanguage',0
align 4
; char aGetuserdefault[]
aGetuserdefault	db 'GetUserDefaultUILanguage',0
align 10h
; char aKernel32_dll_0[]
aKernel32_dll_0	db 'kernel32.dll',0
align 10h
aNofilemru db 'NoFileMru',0
align 4
aNobackbutton db 'NoBackButton',0
align 4
aNoplacesbar db	'NoPlacesBar',0
aSoftwareMicr_0	db 'Software\Microsoft\Windows\CurrentV'
db 'ersion\Policies\Comdlg32',0
aNoentirenetwor	db 'NoEntireNetwork',0
aSoftwareMicr_1	db 'Software\Microsoft\Windows\CurrentV'
db 'ersion\Policies\Network',0
align 10h
aNoclose db 'NoClose',0
aNorecentdocshi	db 'NoRecentDocsHistory',0
aNonetconnectdi	db 'NoNetConnectDisconnect',0
align 4
aRestrictrun db	'RestrictRun',0
aNodrives db 'NoDrives',0
align 4
aNorun db 'NoRun',0
align 4
aSoftwareMicros	db 'Software\Microsoft\Windows\CurrentV'
db 'ersion\Policies\Explorer',0
aS_dll db '%s.dll',0
align 4
dd offset unk_10019B50
off_1001779C dd	offset sub_10014703
dd offset sub_1001473D
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?OnCmdMsg@CCmdTarget@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z ; CCmdTarget::OnCmdMsg(uint,int,void	*,AFX_CMDHANDLERINFO *)
dd offset ?OnFinalRelease@CCmdTarget@@UAEXXZ ; CCmdTarget::OnFinalRelease(void)
dd offset sub_1000F571
dd offset sub_1000F5CF
dd offset sub_10010843
dd offset sub_10010843
dd offset ?GetTypeLib@CCmdTarget@@UAEJKPAPAUITypeLib@@@Z ; CCmdTarget::GetTypeLib(ulong,ITypeLib * *)
dd offset sub_1000EA97
dd offset sub_1000F5D4
dd offset sub_1000F585
dd offset sub_1000F5C9
dd offset sub_1000F591
dd offset sub_1000F58B
dd offset sub_1000F5C5
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset ?InitInstance@CWinApp@@UAEHXZ	; CWinApp::InitInstance(void)
dd offset ?Run@CWinApp@@UAEHXZ ; CWinApp::Run(void)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z_0 ; std::allocator<char>::allocate(uint)
dd offset j_?AfxInternalPumpMessage@@YGHXZ ; AfxInternalPumpMessage(void)
dd offset ?OnIdle@CWinApp@@UAEHJ@Z ; CWinApp::OnIdle(long)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z ; std::allocator<char>::allocate(uint)
dd offset ?ExitInstance@CWinApp@@UAEHXZ	; CWinApp::ExitInstance(void)
dd offset ?ProcessWndProcException@CWinApp@@UAEJPAVCException@@PBUtagMSG@@@Z ; CWinApp::ProcessWndProcException(CException *,tagMSG const *)
dd offset ?ProcessMessageFilter@CWinThread@@UAEHHPAUtagMSG@@@Z ; CWinThread::ProcessMessageFilter(int,tagMSG *)
dd offset ?GetMainWnd@CWinThread@@UAEPAVCWnd@@XZ ; CWinThread::GetMainWnd(void)
dd offset ?Delete@CWinThread@@UAEXXZ ; CWinThread::Delete(void)
dd offset nullsub_1
dd offset sub_10014869
dd offset ?Unregister@CWinApp@@UAEHXZ ;	CWinApp::Unregister(void)
dd offset sub_10013AC0
dd offset unknown_libname_38 ; MFC 3.1-10.0 32bit
dd offset ?InitApplication@CWinApp@@UAEHXZ ; CWinApp::InitApplication(void)
dd offset ?SaveAllModified@CWinApp@@UAEHXZ ; CWinApp::SaveAllModified(void)
dd offset ?DoMessageBox@CWinApp@@UAEHPBDII@Z ; CWinApp::DoMessageBox(char const	*,uint,uint)
dd offset ?DoWaitCursor@CWinApp@@UAEXH@Z ; CWinApp::DoWaitCursor(int)
dd offset unknown_libname_39 ; MFC 3.1-10.0 32bit
dd offset sub_1000EC37
dd offset sub_1000EC6B
dd offset ?WinHelpInternal@CWinApp@@UAEXKI@Z ; CWinApp::WinHelpInternal(ulong,uint)
dd offset ?LoadAppLangResourceDLL@CWinApp@@UAEPAUHINSTANCE__@@XZ ; CWinApp::LoadAppLangResourceDLL(void)
dd offset ?LoadSysPolicies@CWinApp@@UAEHXZ ; CWinApp::LoadSysPolicies(void)
; char asc_10017854[2]
asc_10017854 db	'\',0
db    0
db    0
; char aSoftware_0[]
aSoftware_0 db 'Software\',0
align 4
off_10017864 dd	offset aCwinthread ; "CWinThread"
db  40h	; @
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017910
align 10h
aCwinthread db 'CWinThread',0
align 10h
dd offset unk_10019B84
off_10017894 dd	offset sub_10014B2B
dd offset sub_10014B65
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?OnCmdMsg@CCmdTarget@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z ; CCmdTarget::OnCmdMsg(uint,int,void	*,AFX_CMDHANDLERINFO *)
dd offset ?OnFinalRelease@CCmdTarget@@UAEXXZ ; CCmdTarget::OnFinalRelease(void)
dd offset sub_1000F571
dd offset sub_1000F5CF
dd offset sub_10010843
dd offset sub_10010843
dd offset ?GetTypeLib@CCmdTarget@@UAEJKPAPAUITypeLib@@@Z ; CCmdTarget::GetTypeLib(ulong,ITypeLib * *)
dd offset sub_1000F57F
dd offset sub_1000F5D4
dd offset sub_1000F585
dd offset sub_1000F5C9
dd offset sub_1000F591
dd offset sub_1000F58B
dd offset sub_1000F5C5
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_10010843
dd offset ?Run@CWinThread@@UAEHXZ ; CWinThread::Run(void)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z_0 ; std::allocator<char>::allocate(uint)
dd offset j_?AfxInternalPumpMessage@@YGHXZ ; AfxInternalPumpMessage(void)
dd offset ?OnIdle@CWinThread@@UAEHJ@Z ;	CWinThread::OnIdle(long)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z ; std::allocator<char>::allocate(uint)
dd offset sub_1000EE69
dd offset j_unknown_libname_26
dd offset ?ProcessMessageFilter@CWinThread@@UAEHHPAUtagMSG@@@Z ; CWinThread::ProcessMessageFilter(int,tagMSG *)
dd offset ?GetMainWnd@CWinThread@@UAEPAVCWnd@@XZ ; CWinThread::GetMainWnd(void)
dd offset ?Delete@CWinThread@@UAEXXZ ; CWinThread::Delete(void)
off_10017910 dd	offset aCcmdtarget ; "CCmdTarget"
db  1Ch
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017D5C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCcmdtarget db 'CCmdTarget',0
align 4
unk_10017938 db	   6
db  0Fh
db  0Fh
db  0Fh
db    6
db    0
db    0
db    0
unk_10017940 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_10017958 db	   0
db    0
db    0
db    0
dd offset unk_10017940
unk_10017960 db	   0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
unk_10017980 db	   0
db    0
db    0
db    0
dd offset unk_10017960
dd offset unk_1001D1C8
dd offset unk_1001D1CC
unk_10017990 db	   0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db 0FFh
unk_100179B8 db	   0
db    0
db    0
db    0
dd offset unk_10017990
dd offset unk_1001D1D0
off_100179C4 dd	offset unk_10019A30
db  10h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
unk_100179D4 db	   0
db    0
db    0
db    0
dd offset off_100179C4
unk_100179DC db	   0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
unk_100179E4 db	   0
db    0
db    0
db    0
dd offset unk_100179DC
unk_100179EC db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_100179F8 db	   0
db    0
db    0
db    0
dd offset unk_100179EC
dd offset unk_10019BC8
off_10017A04 dd	offset ?Enable@CCmdUI@@UAEXH@Z ; CCmdUI::Enable(int)
dd offset ?SetCheck@CCmdUI@@UAEXH@Z ; CCmdUI::SetCheck(int)
dd offset ?SetRadio@CCmdUI@@UAEXH@Z ; CCmdUI::SetRadio(int)
dd offset sub_1000F764
off_10017A14 dd	offset aColeexception ;	"COleException"
db  0Ch
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
align 10h
aColeexception db 'COleException',0
align 10h
dd offset unk_10019C2C
off_10017A44 dd	offset sub_10014CA6
dd offset sub_10002D09
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@COleException@@UAEHPADIPAI@Z	; COleException::GetErrorMessage(char *,uint,uint *)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
; char String2[]
String2	db 'DISPLAY',0
off_10017A60 dd	offset aCinvalidargexc ; "CInvalidArgException"
db  98h	; ˜
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCinvalidargexc	db 'CInvalidArgException',0
align 4
off_10017A94 dd	offset aCnotsupportede ; "CNotSupportedException"
db  98h	; ˜
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
align 10h
aCnotsupportede	db 'CNotSupportedException',0
align 4
off_10017AC8 dd	offset aCmemoryexcepti ; "CMemoryException"
db  98h	; ˜
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCmemoryexcepti	db 'CMemoryException',0
align 4
off_10017AF8 dd	offset aCexception ; "CException"
db    8
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017D5C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCexception db 'CException',0
align 10h
dd offset unk_10019C94
off_10017B24 dd	offset sub_10014CAC
dd offset sub_10002D59
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z ; CSimpleException::GetErrorMessage(char *,uint,uint	*)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
dd offset unk_10019CE4
off_10017B3C dd	offset sub_10014CB2
dd offset sub_10002D97
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z ; CSimpleException::GetErrorMessage(char *,uint,uint	*)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
dd offset unk_10019D34
off_10017B54 dd	offset sub_10014CB8
dd offset sub_10002DD5
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z ; CSimpleException::GetErrorMessage(char *,uint,uint	*)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
dd offset unk_10019D94
off_10017B6C dd	offset sub_100151A7
dd offset unk_10019DDC
off_10017B74 dd	offset ??_G_AFX_THREAD_STATE@@UAEPAXI@Z	; _AFX_THREAD_STATE::`scalar deleting destructor'(uint)
dd offset unk_10019E24
off_10017B7C dd	offset ??_GAFX_MODULE_STATE@@UAEPAXI@Z ; AFX_MODULE_STATE::`scalar deleting destructor'(uint)
dd offset unk_10019E6C
off_10017B84 dd	offset ??_GAFX_MODULE_THREAD_STATE@@UAEPAXI@Z ;	AFX_MODULE_THREAD_STATE::`scalar deleting destructor'(uint)
dd offset unk_10019EB8
off_10017B8C dd	offset ??_GAFX_MODULE_STATE@@UAEPAXI@Z_0 ; AFX_MODULE_STATE::`scalar deleting destructor'(uint)
dd offset unk_10019EFC
off_10017B94 dd	offset ??_GCHandleMap@@UAEPAXI@Z ; CHandleMap::`scalar deleting	destructor'(uint)
; char a_ini[]
a_ini db '.INI',0
align 10h
; char a_hlp[]
a_hlp db '.HLP',0
align 4
a_chm db '.CHM',0
align 10h
; char aNotifywinevent[]
aNotifywinevent	db 'NotifyWinEvent',0
align 10h
; char LibFileName[]
LibFileName db 'user32.dll',0
align 4
; char aSoftware[]
aSoftware db 'software',0
align 4
; char aD[]
aD db '%d',0
align 4
off_10017BDC dd	offset aCgdiobject ; "CGdiObject"
db    8
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
dd offset sub_10015B03
dd offset off_10017D5C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCgdiobject db 'CGdiObject',0
align 4
off_10017C04 dd	offset unk_10017C20
db  10h
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
dd offset ?CreateObject@CDC@@SGPAVCObject@@XZ ;	CDC::CreateObject(void)
dd offset off_10017D5C
align 10h
unk_10017C20 db	 43h ; C
db  44h	; D
db  43h	; C
db    0
off_10017C24 dd	offset aCuserexception ; "CUserException"
db  98h	; ˜
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
align 10h
aCuserexception	db 'CUserException',0
align 10h
off_10017C50 dd	offset aCresourceexcep ; "CResourceException"
db  98h	; ˜
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCresourceexcep	db 'CResourceException',0
align 10h
dd offset unk_10019F4C
off_10017C84 dd	offset sub_10015ACA
dd offset sub_10003006
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z ; CSimpleException::GetErrorMessage(char *,uint,uint	*)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
dd offset unk_10019F9C
off_10017C9C dd	offset sub_10015AD0
dd offset sub_10003022
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z ; CSimpleException::GetErrorMessage(char *,uint,uint	*)
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
dd offset unk_10019FE4
off_10017CB4 dd	offset sub_10015ADC
dd offset sub_10003049
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset unk_1001A02C
off_10017CC4 dd	offset sub_10015AD6
dd offset sub_10013504
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset unknown_libname_34 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_35 ; MFC 3.1-10.0 32bit
dd offset ?ReleaseAttribDC@CDC@@UAEXXZ ; CDC::ReleaseAttribDC(void)
dd offset ?Clear@TaskStack@details@Concurrency@@QAEXXZ ; Concurrency::details::TaskStack::Clear(void)
dd offset ?SaveDC@CDC@@UAEHXZ ;	CDC::SaveDC(void)
dd offset ?RestoreDC@CDC@@UAEHH@Z ; CDC::RestoreDC(int)
dd offset ?SelectStockObject@CDC@@UAEPAVCGdiObject@@H@Z	; CDC::SelectStockObject(int)
dd offset unknown_libname_37 ; MFC 3.1-10.0 32bit
dd offset sub_100130BC
dd offset sub_100130EB
dd offset sub_1001311A
dd offset ?SetViewportOrg@CDC@@UAE?AVCPoint@@HH@Z ; CDC::SetViewportOrg(int,int)
dd offset ?OffsetViewportOrg@CDC@@UAE?AVCPoint@@HH@Z ; CDC::OffsetViewportOrg(int,int)
dd offset ?SetViewportExt@CDC@@UAE?AVCSize@@HH@Z ; CDC::SetViewportExt(int,int)
dd offset ?ScaleViewportExt@CDC@@UAE?AVCSize@@HHHH@Z ; CDC::ScaleViewportExt(int,int,int,int)
dd offset ?SetWindowExt@CDC@@UAE?AVCSize@@HH@Z ; CDC::SetWindowExt(int,int)
dd offset ?ScaleWindowExt@CDC@@UAE?AVCSize@@HHHH@Z ; CDC::ScaleWindowExt(int,int,int,int)
dd offset sub_10013148
dd offset sub_10002EE2
dd offset sub_10002EF6
dd offset sub_10002F06
dd offset ?ExtTextOutA@CDC@@UAEHHHIPBUtagRECT@@PBDIPAH@Z ; CDC::ExtTextOutA(int,int,uint,tagRECT const *,char const *,uint,int *)
dd offset ?TabbedTextOutA@CDC@@UAE?AVCSize@@HHPBDHHPAHH@Z ; CDC::TabbedTextOutA(int,int,char const *,int,int,int *,int)
dd offset sub_10002F7F
dd offset ?DrawTextExA@CDC@@UAEHPADHPAUtagRECT@@IPAUtagDRAWTEXTPARAMS@@@Z ; CDC::DrawTextExA(char *,int,tagRECT	*,uint,tagDRAWTEXTPARAMS *)
dd offset ?GrayStringA@CDC@@UAEHPAVCBrush@@P6GHPAUHDC__@@JH@ZJHHHHH@Z ;	CDC::GrayStringA(CBrush	*,int (*)(HDC__	*,long,int),long,int,int,int,int,int)
dd offset sub_10002FEA
dd offset aS		; "S"
dd offset aM		; "M"
dd offset aD_0		; "D"
dd offset aB		; "B"
dd offset aVal		; "Val"
dd offset aForceremove	; "ForceRemove"
dd offset aNoremove	; "NoRemove"
dd offset aDelete	; "Delete"
off_10017D5C dd	offset aCobject	; "CObject"
db    4
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCobject db 'CObject',0
aDelete	db 'Delete',0
align 4
aNoremove db 'NoRemove',0
align 4
aForceremove db	'ForceRemove',0
aVal db	'Val',0
aB db 'B',0
align 4
aD_0 db	'D',0
align 4
aM db 'M',0
align 10h
aS db 'S',0
align 8
stru_10017DB8 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10003079
		   offset loc_10003093,	\
		   offset loc_100030A1>
dd offset unk_1001A08C
off_10017DC8 dd	offset ?Allocate@CAfxStringMgr@@UAEPAUCStringData@ATL@@HH@Z ; CAfxStringMgr::Allocate(int,int)
dd offset ?allocate@?$allocator@D@std@@QAEPADI@Z_1 ; std::allocator<char>::allocate(uint)
dd offset ?Reallocate@CAfxStringMgr@@UAEPAUCStringData@ATL@@PAU23@HH@Z ; CAfxStringMgr::Reallocate(ATL::CStringData *,int,int)
dd offset ?GetNilString@CAfxStringMgr@@UAEPAUCStringData@ATL@@XZ ; CAfxStringMgr::GetNilString(void)
dd offset sub_1000FC0C
off_10017DDC dd	offset aCwnd ; "CWnd"
db  50h	; P
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
dd offset ?CreateObject@CWnd@@SGPAVCObject@@XZ ; CWnd::CreateObject(void)
dd offset off_10017910
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCwnd db 'CWnd',0
align 10h
off_10017E00 dd	offset unk_100179D4
dd offset unk_10017E08
unk_10017E08 db	   0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
off_10017E10 dd	offset unk_10017958
dd offset unk_10017E18
unk_10017E18 db	 38h ; 8
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  33h	; 3
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  35h	; 5
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  34h	; 4
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  36h	; 6
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  32h	; 2
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db  37h	; 7
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnNTCtlColor@CWnd@@IAEJIJ@Z ; CWnd::OnNTCtlColor(uint,long)
db    7
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  20h
db    0
db    0
db    0
dd offset ?OnSetFocus@CWnd@@IAEXPAV1@@Z	; CWnd::OnSetFocus(CWnd	*)
db  2Bh	; +
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  2Bh	; +
db    0
db    0
db    0
dd offset ?OnDrawItem@CWnd@@IAEXHPAUtagDRAWITEMSTRUCT@@@Z ; CWnd::OnDrawItem(int,tagDRAWITEMSTRUCT *)
db  2Ch	; ,
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  2Bh	; +
db    0
db    0
db    0
dd offset ?OnMeasureItem@CWnd@@IAEXHPAUtagMEASUREITEMSTRUCT@@@Z	; CWnd::OnMeasureItem(int,tagMEASUREITEMSTRUCT *)
db  19h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    8
db    0
db    0
db    0
dd offset ?OnCtlColor@CWnd@@IAEPAUHBRUSH__@@PAVCDC@@PAV1@I@Z ; CWnd::OnCtlColor(CDC *,CWnd *,uint)
db  39h	; 9
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  2Ch	; ,
db    0
db    0
db    0
dd offset ?OnCompareItem@CWnd@@IAEHHPAUtagCOMPAREITEMSTRUCT@@@Z	; CWnd::OnCompareItem(int,tagCOMPAREITEMSTRUCT *)
db  21h	; !
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  17h
db    0
db    0
db    0
dd offset ?OnEnterIdle@CWnd@@IAEXIPAV1@@Z ; CWnd::OnEnterIdle(uint,CWnd	*)
db  14h
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  27h	; '
db    0
db    0
db    0
dd offset sub_10011504	; ?OnVScroll@CWnd@@IAEXIIPAVCScrollBar@@@Z
			; doubtful name
db  15h
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  27h	; '
db    0
db    0
db    0
dd offset sub_10011504	; ?OnVScroll@CWnd@@IAEXIIPAVCScrollBar@@@Z
			; doubtful name
db  2Dh	; -
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  2Bh	; +
db    0
db    0
db    0
dd offset ?OnDeleteItem@CWnd@@IAEXHPAUtagDELETEITEMSTRUCT@@@Z ;	CWnd::OnDeleteItem(int,tagDELETEITEMSTRUCT *)
db  2Fh	; /
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Ah
db    0
db    0
db    0
dd offset sub_100117B9	; ?OnVKeyToItem@CWnd@@IAEHIPAVCListBox@@I@Z
			; doubtful name
db  2Eh	; .
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Ah
db    0
db    0
db    0
dd offset sub_100117B9	; ?OnVKeyToItem@CWnd@@IAEHIPAVCListBox@@I@Z
			; doubtful name
db  82h	; ‚
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
dd offset ?OnNcDestroy@CWnd@@IAEXXZ ; CWnd::OnNcDestroy(void)
db  10h
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  1Bh
db    0
db    0
db    0
dd offset ?OnParentNotify@CWnd@@IAEXIJ@Z ; CWnd::OnParentNotify(uint,long)
db  15h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
dd offset ?OnSysColorChange@CWnd@@IAEXXZ ; CWnd::OnSysColorChange(void)
db  1Bh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  29h	; )
db    0
db    0
db    0
dd offset sub_10011D2E
db  53h	; S
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    7
db    0
db    0
db    0
dd offset ?OnHelpInfo@CWnd@@IAEHPAUtagHELPINFO@@@Z ; CWnd::OnHelpInfo(tagHELPINFO *)
db  1Ah
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  2Ah	; *
db    0
db    0
db    0
dd offset ?OnSettingChange@CWnd@@IAEXIPBD@Z ; CWnd::OnSettingChange(uint,char const *)
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
dd offset ?OnDestroy@CWnd@@IAEXXZ ; CWnd::OnDestroy(void)
db  6Eh	; n
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnActivateTopLevel@CWnd@@IAEJIJ@Z ; CWnd::OnActivateTopLevel(uint,long)
db  7Eh	; ~
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnDisplayChange@CWnd@@IAEJIJ@Z ; CWnd::OnDisplayChange(uint,long)
db    0
db 0C0h	; À
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset dword_100205B8
dd offset ?OnDragList@CWnd@@IAEJIJ@Z ; CWnd::OnDragList(uint,long)
db  3Dh	; =
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  0Eh
db    0
db    0
db    0
dd offset ?OnGetObject@CWnd@@IAEJIJ@Z ;	CWnd::OnGetObject(uint,long)
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; char String[]
String db 'AfxOldWndProc423',0
align 4
aAfxwnd70s db 'AfxWnd70s',0
align 4
aAfxcontrolbar7	db 'AfxControlBar70s',0
align 4
aAfxmdiframe70s	db 'AfxMDIFrame70s',0
align 4
aAfxframeorview	db 'AfxFrameOrView70s',0
align 10h
aAfxolecontrol7	db 'AfxOleControl70s',0
align 4
; char aEnumdisplaydev[]
aEnumdisplaydev	db 'EnumDisplayDevicesA',0
; char aGetmonitorinfo[]
aGetmonitorinfo	db 'GetMonitorInfoA',0
; char aEnumdisplaymon[]
aEnumdisplaymon	db 'EnumDisplayMonitors',0
; char aMonitorfrompoi[]
aMonitorfrompoi	db 'MonitorFromPoint',0
align 10h
; char aMonitorfromrec[]
aMonitorfromrec	db 'MonitorFromRect',0
; char aMonitorfromwin[]
aMonitorfromwin	db 'MonitorFromWindow',0
align 4
; char ProcName[]
ProcName db 'GetSystemMetrics',0
align 4
; char ModuleName[]
ModuleName db 'USER32',0
align 10h
aAccdodefaultac:
unicode	0, <accDoDefaultAction>,0
align 4
aAcchittest:
unicode	0, <accHitTest>,0
align 10h
aAccnavigate:
unicode	0, <accNavigate>,0
aAcclocation:
unicode	0, <accLocation>,0
aAccselect:
unicode	0, <accSelect>,0
aAccdefaultacti:
unicode	0, <accDefaultAction>,0
align 4
aAccselection:
unicode	0, <accSelection>,0
align 4
aAccfocus:
unicode	0, <accFocus>,0
align 4
aAcckeyboardsho:
unicode	0, <accKeyboardShortcut>,0
aAcchelptopic:
unicode	0, <accHelpTopic>,0
align 4
aAcchelp:
unicode	0, <accHelp>,0
aAccstate:
unicode	0, <accState>,0
align 10h
aAccrole:
unicode	0, <accRole>,0
aAccdescription:
unicode	0, <accDescription>,0
align 10h
aAccvalue:
unicode	0, <accValue>,0
align 4
aAccname:
unicode	0, <accName>,0
aAccchild:
unicode	0, <accChild>,0
align 4
aAccchildcount:
unicode	0, <accChildCount>,0
aAccparent:
unicode	0, <accParent>,0
dd offset unk_1001A0D0
off_100183BC dd	offset unknown_libname_27 ; MFC	3.1-10.0 32bit
dd offset unknown_libname_28 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_29 ; MFC 3.1-10.0 32bit
dd offset ?Invoke@XAccessible@CWnd@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z ; CWnd::XAccessible::Invoke(long,_GUID const &,ulong,ushort,tagDISPPARAMS *,tagVARIANT *,tagEXCEPINFO *,uint *)
dd offset ?GetIDsOfNames@XAccessible@CWnd@@UAGJABU_GUID@@PAPA_WIKPAJ@Z ; CWnd::XAccessible::GetIDsOfNames(_GUID	const &,wchar_t	* *,uint,ulong,long *)
dd offset ?GetTypeInfoCount@XAccessible@CWnd@@UAGJPAI@Z	; CWnd::XAccessible::GetTypeInfoCount(uint *)
dd offset sub_100101C5
dd offset ?get_accParent@XAccessible@CWnd@@UAGJPAPAUIDispatch@@@Z ; CWnd::XAccessible::get_accParent(IDispatch * *)
dd offset ?get_accChildCount@XAccessible@CWnd@@UAGJPAJ@Z ; CWnd::XAccessible::get_accChildCount(long *)
dd offset ?get_accChild@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPAUIDispatch@@@Z ;	CWnd::XAccessible::get_accChild(tagVARIANT,IDispatch * *)
dd offset ?get_accName@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accName(tagVARIANT,wchar_t * *)
dd offset ?get_accValue@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accValue(tagVARIANT,wchar_t * *)
dd offset ?get_accDescription@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accDescription(tagVARIANT,wchar_t * *)
dd offset ?get_accRole@XAccessible@CWnd@@UAGJUtagVARIANT@@PAU3@@Z ; CWnd::XAccessible::get_accRole(tagVARIANT,tagVARIANT *)
dd offset ?get_accState@XAccessible@CWnd@@UAGJUtagVARIANT@@PAU3@@Z ; CWnd::XAccessible::get_accState(tagVARIANT,tagVARIANT *)
dd offset ?get_accHelp@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accHelp(tagVARIANT,wchar_t * *)
dd offset ?get_accHelpTopic@XAccessible@CWnd@@UAGJPAPA_WUtagVARIANT@@PAJ@Z ; CWnd::XAccessible::get_accHelpTopic(wchar_t * *,tagVARIANT,long *)
dd offset ?get_accKeyboardShortcut@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accKeyboardShortcut(tagVARIANT,wchar_t * *)
dd offset ?get_accFocus@XAccessible@CWnd@@UAGJPAUtagVARIANT@@@Z	; CWnd::XAccessible::get_accFocus(tagVARIANT *)
dd offset ?get_accSelection@XAccessible@CWnd@@UAGJPAUtagVARIANT@@@Z ; CWnd::XAccessible::get_accSelection(tagVARIANT *)
dd offset ?get_accDefaultAction@XAccessible@CWnd@@UAGJUtagVARIANT@@PAPA_W@Z ; CWnd::XAccessible::get_accDefaultAction(tagVARIANT,wchar_t * *)
dd offset ?accSelect@XAccessible@CWnd@@UAGJJUtagVARIANT@@@Z ; CWnd::XAccessible::accSelect(long,tagVARIANT)
dd offset ?accLocation@XAccessible@CWnd@@UAGJPAJ000UtagVARIANT@@@Z ; CWnd::XAccessible::accLocation(long *,long	*,long *,long *,tagVARIANT)
dd offset ?accNavigate@XAccessible@CWnd@@UAGJJUtagVARIANT@@PAU3@@Z ; CWnd::XAccessible::accNavigate(long,tagVARIANT,tagVARIANT *)
dd offset ?accHitTest@XAccessible@CWnd@@UAGJJJPAUtagVARIANT@@@Z	; CWnd::XAccessible::accHitTest(long,long,tagVARIANT *)
dd offset ?accDoDefaultAction@XAccessible@CWnd@@UAGJUtagVARIANT@@@Z ; CWnd::XAccessible::accDoDefaultAction(tagVARIANT)
dd offset ?put_accName@XAccessible@CWnd@@UAGJUtagVARIANT@@PA_W@Z ; CWnd::XAccessible::put_accName(tagVARIANT,wchar_t *)
dd offset ?put_accValue@XAccessible@CWnd@@UAGJUtagVARIANT@@PA_W@Z ; CWnd::XAccessible::put_accValue(tagVARIANT,wchar_t *)
dd offset unk_1001A114
off_10018430 dd	offset ?AddRef@XDataObject@COleDataSource@@UAGKXZ ; COleDataSource::XDataObject::AddRef(void)
dd offset sub_100104D0
dd offset ?QueryInterface@XDataObject@COleDataSource@@UAGJABU_GUID@@PAPAX@Z ; COleDataSource::XDataObject::QueryInterface(_GUID	const &,void * *)
dd offset ?SetProxy@XAccessibleServer@CWnd@@UAGJPAUIAccessibleProxy@@@Z	; CWnd::XAccessibleServer::SetProxy(IAccessibleProxy *)
dd offset ?GetHWND@XAccessibleServer@CWnd@@UAGJPAPAUHWND__@@@Z ; CWnd::XAccessibleServer::GetHWND(HWND__ * *)
dd offset ?GetEnumVariant@XAccessibleServer@CWnd@@UAGJPAPAUIEnumVARIANT@@@Z ; CWnd::XAccessibleServer::GetEnumVariant(IEnumVARIANT * *)
dd offset unk_1001A160
off_1001844C dd	offset sub_10015C12
dd offset sub_10011A5F
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset ?OnCmdMsg@CCmdTarget@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z ; CCmdTarget::OnCmdMsg(uint,int,void	*,AFX_CMDHANDLERINFO *)
dd offset ?OnFinalRelease@CWnd@@UAEXXZ ; CWnd::OnFinalRelease(void)
dd offset sub_1000F571
dd offset sub_1000F5CF
dd offset sub_10010843
dd offset sub_10010843
dd offset ?GetTypeLib@CCmdTarget@@UAEJKPAPAUITypeLib@@@Z ; CCmdTarget::GetTypeLib(ulong,ITypeLib * *)
dd offset sub_1001006B
dd offset sub_1000F5D4
dd offset sub_1000F585
dd offset sub_1000F5C9
dd offset sub_1001014C
dd offset sub_1000F58B
dd offset sub_1000F5C5
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset sub_1000F5CF
dd offset nullsub_3
dd offset unknown_libname_31 ; MFC 3.1-10.0 32bit
dd offset ?CreateEx@CWnd@@UAEHKPBD0KABUtagRECT@@PAV1@IPAX@Z ; CWnd::CreateEx(ulong,char	const *,char const *,ulong,tagRECT const &,CWnd	*,uint,void *)
dd offset ?CreateEx@CWnd@@UAEHKPBD0KHHHHPAUHWND__@@PAUHMENU__@@PAX@Z ; CWnd::CreateEx(ulong,char const *,char const *,ulong,int,int,int,int,HWND__ *,HMENU__ *,void *)
dd offset ?DestroyWindow@CWnd@@UAEHXZ ;	CWnd::DestroyWindow(void)
dd offset sub_10011151
dd offset ?CalcWindowRect@CWnd@@UAEXPAUtagRECT@@I@Z ; CWnd::CalcWindowRect(tagRECT *,uint)
dd offset ?OnToolHitTest@CWnd@@UBEHVCPoint@@PAUtagTOOLINFOA@@@Z	; CWnd::OnToolHitTest(CPoint,tagTOOLINFOA *)
dd offset sub_1000F5CF
dd offset sub_10012B7C
dd offset sub_10012BF6
dd offset ?WinHelpInternal@CWnd@@UAEXKI@Z ; CWnd::WinHelpInternal(ulong,uint)
dd offset ?ContinueModal@CWnd@@UAEHXZ ;	CWnd::ContinueModal(void)
dd offset ?EndModalLoop@CWnd@@UAEXH@Z ;	CWnd::EndModalLoop(int)
dd offset ?EnsureStdObj@CWnd@@UAEJXZ ; CWnd::EnsureStdObj(void)
dd offset ?get_accParent@CWnd@@UAEJPAPAUIDispatch@@@Z ;	CWnd::get_accParent(IDispatch *	*)
dd offset ?get_accChildCount@CWnd@@UAEJPAJ@Z ; CWnd::get_accChildCount(long *)
dd offset ?get_accChild@CWnd@@UAEJUtagVARIANT@@PAPAUIDispatch@@@Z ; CWnd::get_accChild(tagVARIANT,IDispatch * *)
dd offset ?get_accName@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z ; CWnd::get_accName(tagVARIANT,wchar_t *	*)
dd offset ?get_accValue@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z	; CWnd::get_accValue(tagVARIANT,wchar_t	* *)
dd offset ?get_accDescription@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z ;	CWnd::get_accDescription(tagVARIANT,wchar_t * *)
dd offset ?get_accRole@CWnd@@UAEJUtagVARIANT@@PAU2@@Z ;	CWnd::get_accRole(tagVARIANT,tagVARIANT	*)
dd offset ?get_accState@CWnd@@UAEJUtagVARIANT@@PAU2@@Z ; CWnd::get_accState(tagVARIANT,tagVARIANT *)
dd offset ?get_accHelp@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z ; CWnd::get_accHelp(tagVARIANT,wchar_t *	*)
dd offset ?get_accHelpTopic@CWnd@@UAEJPAPA_WUtagVARIANT@@PAJ@Z ; CWnd::get_accHelpTopic(wchar_t	* *,tagVARIANT,long *)
dd offset ?get_accKeyboardShortcut@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z ; CWnd::get_accKeyboardShortcut(tagVARIANT,wchar_t *	*)
dd offset ?get_accFocus@CWnd@@UAEJPAUtagVARIANT@@@Z ; CWnd::get_accFocus(tagVARIANT *)
dd offset ?get_accSelection@CWnd@@UAEJPAUtagVARIANT@@@Z	; CWnd::get_accSelection(tagVARIANT *)
dd offset ?get_accDefaultAction@CWnd@@UAEJUtagVARIANT@@PAPA_W@Z	; CWnd::get_accDefaultAction(tagVARIANT,wchar_t	* *)
dd offset ?accSelect@CWnd@@UAEJJUtagVARIANT@@@Z	; CWnd::accSelect(long,tagVARIANT)
dd offset ?accLocation@CWnd@@UAEJPAJ000UtagVARIANT@@@Z ; CWnd::accLocation(long	*,long *,long *,long *,tagVARIANT)
dd offset ?accNavigate@CWnd@@UAEJJUtagVARIANT@@PAU2@@Z ; CWnd::accNavigate(long,tagVARIANT,tagVARIANT *)
dd offset ?accHitTest@CWnd@@UAEJJJPAUtagVARIANT@@@Z ; CWnd::accHitTest(long,long,tagVARIANT *)
dd offset ?accDoDefaultAction@CWnd@@UAEJUtagVARIANT@@@Z	; CWnd::accDoDefaultAction(tagVARIANT)
dd offset unknown_libname_30 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_30 ; MFC 3.1-10.0 32bit
dd offset ?SetProxy@CWnd@@UAEJPAUIAccessibleProxy@@@Z ;	CWnd::SetProxy(IAccessibleProxy	*)
dd offset ?CreateAccessibleProxy@CWnd@@UAEJIJPAJ@Z ; CWnd::CreateAccessibleProxy(uint,long,long	*)
dd offset ?OnCommand@CWnd@@MAEHIJ@Z ; CWnd::OnCommand(uint,long)
dd offset ?OnNotify@CWnd@@MAEHIJPAJ@Z ;	CWnd::OnNotify(uint,long,long *)
dd offset sub_1000FEA5
dd offset nullsub_4
dd offset sub_100039BC
dd offset ?EndModalState@CWnd@@UAEXXZ ;	CWnd::EndModalState(void)
dd offset ?PreTranslateMessage@CWnd@@UAEHPAUtagMSG@@@Z ; CWnd::PreTranslateMessage(tagMSG *)
dd offset ?OnAmbientProperty@CWnd@@UAEHPAVCOleControlSite@@JPAUtagVARIANT@@@Z ;	CWnd::OnAmbientProperty(COleControlSite	*,long,tagVARIANT *)
dd offset ?WindowProc@CWnd@@MAEJIIJ@Z ;	CWnd::WindowProc(uint,uint,long)
dd offset ?OnWndMsg@CWnd@@MAEHIIJPAJ@Z ; CWnd::OnWndMsg(uint,uint,long,long *)
dd offset ?DefWindowProcA@CWnd@@MAEJIIJ@Z ; CWnd::DefWindowProcA(uint,uint,long)
dd offset nullsub_3
dd offset ?OnChildNotify@CWnd@@MAEHIIJPAJ@Z ; CWnd::OnChildNotify(uint,uint,long,long *)
dd offset sub_1000F5C5
dd offset sub_10010843
dd offset ?CreateControlContainer@CWnd@@MAEHPAPAVCOleControlContainer@@@Z ; CWnd::CreateControlContainer(COleControlContainer *	*)
dd offset ?CreateControlSite@CWnd@@MAEHPAVCOleControlContainer@@PAPAVCOleControlSite@@IABU_GUID@@@Z ; CWnd::CreateControlSite(COleControlContainer *,COleControlSite * *,uint,_GUID const &)
dd offset sub_1000F5CF
dd offset unk_1001A1A8
off_10018580 dd	offset sub_10010050
dd offset unk_1001A1F0
off_10018588 dd	offset ?Enable@CTestCmdUI@@UAEXH@Z ; CTestCmdUI::Enable(int)
dd offset nullsub_5
dd offset nullsub_5
dd offset nullsub_5
; IID riid
riid dd	618736E0h	     ; Data1
dw 3C3Dh		; Data2
dw 11CFh		; Data3
db 81h,	0Ch, 0,	0AAh, 0, 38h, 9Bh, 71h;	Data4
; char aInitcommoncont[]
aInitcommoncont	db 'InitCommonControlsEx',0
align 10h
; char aComctl32_dll_0[]
aComctl32_dll_0	db 'COMCTL32.DLL',0
align 10h
unk_100185D0 db	0CFh ; Ï
db  9Dh	; 
db  7Dh	; }
db  7Ah	; z
db 0A1h	; ¡
db 0B7h	; ·
db  19h
db  40h	; @
db  90h	; 
db  31h	; 1
db  25h	; %
db  82h	; ‚
db  68h	; h
db  84h	; „
db  69h	; i
db  80h	; €
dd offset unk_1001A294
off_100185E4 dd	offset ?QueryInterface@?$CMFCComObject@VCAccessibleProxy@ATL@@@@WBA@AGJABU_GUID@@PAPAX@Z ; [thunk]:CMFCComObject<ATL::CAccessibleProxy>::QueryInterface`adjustor{16}' (_GUID const &,void * *)
dd offset sub_100162D1
dd offset sub_100162DB
dd offset sub_100039E1
dd offset sub_100039E6
dd offset unk_1001A2A8
off_100185FC dd	offset ?QueryInterface@?$CMFCComObject@VCAccessibleProxy@ATL@@@@W3AGJABU_GUID@@PAPAX@Z ; [thunk]:CMFCComObject<ATL::CAccessibleProxy>::QueryInterface`adjustor{4}' (_GUID const &,void * *)
dd offset sub_100162B3
dd offset sub_100162BD
dd offset ?SetServer@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAUIAccessible@@PAUIAccessibleServer@@@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::SetServer(IAccessible	*,IAccessibleServer *)
align 10h
dd offset unk_1001A390
off_10018614 dd	offset ?QueryInterface@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGJABU_GUID@@PAPAX@Z ;	CMFCComObject<ATL::CAccessibleProxy>::QueryInterface(_GUID const &,void	* *)
dd offset ?AddRef@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ ; CMFCComObject<ATL::CAccessibleProxy>::AddRef(void)
dd offset ?Release@?$CMFCComObject@VCAccessibleProxy@ATL@@@@UAGKXZ ; CMFCComObject<ATL::CAccessibleProxy>::Release(void)
dd offset ?GetTypeInfoCount@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAI@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetTypeInfoCount(uint *)
dd offset ?GetTypeInfo@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJIKPAPAUITypeInfo@@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetTypeInfo(uint,ulong,ITypeInfo * *)
dd offset ?GetIDsOfNames@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJABU_GUID@@PAPA_WIKPAJ@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::GetIDsOfNames(_GUID const &,wchar_t * *,uint,ulong,long *)
dd offset ?Invoke@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::Invoke(long,_GUID const &,ulong,ushort,tagDISPPARAMS	*,tagVARIANT *,tagEXCEPINFO *,uint *)
dd offset ?get_accParent@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAPAUIDispatch@@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accParent(IDispatch	* *)
dd offset ?get_accChildCount@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAJ@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accChildCount(long *)
dd offset ?get_accChild@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPAUIDispatch@@@Z	; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accChild(tagVARIANT,IDispatch *	*)
dd offset ?get_accName@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accName(tagVARIANT,wchar_t	* *)
dd offset ?get_accValue@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accValue(tagVARIANT,wchar_t * *)
dd offset ?get_accDescription@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accDescription(tagVARIANT,wchar_t *	*)
dd offset ?get_accRole@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAU3@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accRole(tagVARIANT,tagVARIANT *)
dd offset ?get_accState@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAU3@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accState(tagVARIANT,tagVARIANT *)
dd offset ?get_accHelp@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accHelp(tagVARIANT,wchar_t	* *)
dd offset ?get_accHelpTopic@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAPA_WUtagVARIANT@@PAJ@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accHelpTopic(wchar_t * *,tagVARIANT,long *)
dd offset ?get_accKeyboardShortcut@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accKeyboardShortcut(tagVARIANT,wchar_t	* *)
dd offset ?get_accFocus@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAUtagVARIANT@@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accFocus(tagVARIANT *)
dd offset ?get_accSelection@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAUtagVARIANT@@@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accSelection(tagVARIANT *)
dd offset ?get_accDefaultAction@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@PAPA_W@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::get_accDefaultAction(tagVARIANT,wchar_t * *)
dd offset ?accSelect@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJJUtagVARIANT@@@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accSelect(long,tagVARIANT)
dd offset ?accLocation@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJPAJ000UtagVARIANT@@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accLocation(long *,long *,long	*,long *,tagVARIANT)
dd offset ?accNavigate@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJJUtagVARIANT@@PAU3@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accNavigate(long,tagVARIANT,tagVARIANT	*)
dd offset ?accHitTest@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJJJPAUtagVARIANT@@@Z ; ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accHitTest(long,long,tagVARIANT *)
dd offset ?accDoDefaultAction@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJUtagVARIANT@@@Z ;	ATL::IAccessibleProxyImpl<ATL::CAccessibleProxy>::accDoDefaultAction(tagVARIANT)
dd offset unknown_libname_49 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_49 ; MFC 3.1-10.0 32bit
dd offset sub_10016224
unk_10018688 db	 14h
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db 0C0h	; À
db    0
db    0
db    0
db    0
db    0
db    0
db  46h	; F
unk_10018698 db	   0
db    4
db    2
db    0
db    0
db    0
db    0
db    0
db 0C0h	; À
db    0
db    0
db    0
db    0
db    0
db    0
db  46h	; F
off_100186A8 dd	offset unk_100185D0
db    4
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset riid
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset unk_10018698
align 8
db    1
db    0
db    0
db    0
dd offset unk_10018688
db  10h
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; char aHtmlhelpa[]
aHtmlhelpa db 'HtmlHelpA',0
align 10h
; char aHhctrl_ocx[]
aHhctrl_ocx db 'hhctrl.ocx',0
align 4
; char szClass[]
szClass	db '#32768',0
align 4
; char aIme[]
aIme db	'ime',0
; char aCommctrl_dragl[]
aCommctrl_dragl	db 'commctrl_DragListMsg',0
align 10h
db 0FFh
db 0FFh
db 0FFh
db 0FFh
off_10018724 dd	offset aCmapptrtoptr ; "CMapPtrToPtr"
db  1Ch
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017D5C
align 10h
aCmapptrtoptr db 'CMapPtrToPtr',0
align 10h
dd offset unk_1001A3D8
off_10018754 dd	offset sub_1001636B
dd offset sub_1000EA7B
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
off_10018760 dd	offset aCmenu ;	"CMenu"
db    8
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
dd offset sub_10016377
dd offset off_10017D5C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCmenu db 'CMenu',0
align 4
dd offset unk_1001A420
off_10018788 dd	offset sub_10016371
dd offset sub_10003B78
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset nullsub_5
dd offset nullsub_5
off_1001879C dd	offset aCarchiveexcept ; "CArchiveException"
db  10h
db    0
db    0
db    0
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_10017AF8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
aCarchiveexcept	db 'CArchiveException',0
align 4
dd offset unk_1001A46C
off_100187D0 dd	offset sub_100163A6
dd offset sub_10003CDD
dd offset unknown_libname_11 ; Microsoft VisualC 2-10/net runtime
			; MFC 3.1-10.0 32bit
dd offset sub_1001393A
dd offset ?ReportError@CException@@UAEHII@Z ; CException::ReportError(uint,uint)
aCbytearray db 'CByteArray',0
align 10h
dd offset unk_1001A4B4
off_100187F4 dd	offset sub_100163EA
dd offset sub_1000E7CA
dd offset ?Serialize@CByteArray@@UAEXAAVCArchive@@@Z ; CByteArray::Serialize(CArchive &)
stru_10018800 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10003D0A
		   offset loc_10003D5D>
align 10h
stru_10018810 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10003D7B
		   offset loc_10003DEA>
align 10h
stru_10018820 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10003E34
		   offset loc_10003E51,	\
		   offset loc_10003E55>
align 10h
stru_10018830 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10003F1B
		   offset loc_10003F4D>
align 10h
stru_10018840 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 100047DA
		   offset loc_1000489C,	\
		   offset loc_100048AD>
; char aCorexitprocess[]
aCorexitprocess	db 'CorExitProcess',0
align 4
; char aMscoree_dll[]
aMscoree_dll db	'mscoree.dll',0
stru_10018868 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10004A5F
		   offset loc_10004B09>
dd offset unk_1001A4F8
off_10018878 dd	offset ??_Gtype_info@@UAEPAXI@Z	; type_info::`scalar deleting destructor'(uint)
align 10h
stru_10018880 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10004B42
		   offset loc_10004B7F>
unk_1001888C db	 63h ; c
db  73h	; s
db  6Dh	; m
db 0E0h	; à
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
db  20h
db    5
db  93h	; “
db  19h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
stru_100188B0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10005442
		   offset loc_100054AC>
align 10h
stru_100188C0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10005717
		   offset loc_1000577A>
align 10h
stru_100188D0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10005916
		   offset loc_10005A5D>
align 10h
stru_100188E0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10005A84
		   offset loc_10005AFF>
align 10h
stru_100188F0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10005C04
		   offset loc_10005D64>
align 10h
stru_10018900 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10006227
		   offset loc_100062BE>
aMicrosoftVisua	db 'Microsoft Visual C++ Runtime Librar'
db 'y',0
align 4
; char aProgram[]
aProgram db 'Program: ',0
align 10h
; char asc_10018940[]
asc_10018940 db	0Ah
db 0Ah,0
align 4
; char a___[]
a___ db	'...',0
; char aProgramNameUnk[]
aProgramNameUnk	db '<program name unknown>',0
align 10h
aABufferOverrun	db 'A buffer overrun has been detected '
db 'which has corrupted the program',27h,'s'
db 0Ah
db 'internal state.  The program cannot'
db ' safely continue execution and must'
db 0Ah
db 'now be terminated.',0Ah,0
aBufferOverrunD	db 'Buffer overrun detected!',0
align 10h
aASecurityError	db 'A security error of unknown cause h'
db 'as been detected which has',0Ah
db 'corrupted the program',27h,'s internal'
db ' state.  The program cannot safely',0Ah
db 'continue execution and must now be '
db 'terminated.',0Ah,0
align 4
; char aUnknownSecurit[]
aUnknownSecurit	db 'Unknown security failure detected!',0
align 4
stru_10018AF8 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10006E9C
		   offset loc_10006ED4,	\
		   offset loc_10006ED8>
align 8
stru_10018B08 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10007051
		   offset loc_100070FE>
_SCOPETABLE_ENTRY <0, \
		   offset loc_100070C4,	\
		   offset loc_100070CD>
stru_10018B20 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 1000711F
		   offset loc_10007153,	\
		   offset loc_1000715C>
align 10h
stru_10018B30 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10007183
		   offset loc_100072D2>
_SCOPETABLE_ENTRY <0, \
		   offset loc_1000720E,	\
		   offset loc_1000725D>
stru_10018B48 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10007347
		   offset loc_100074B7,	\
		   offset loc_100074BB>
align 8
stru_10018B58 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10007938
		   offset loc_10007A65>
_SCOPETABLE_ENTRY <0FFFFFFFFh, 0, \
		   offset loc_10007A73>
; char aFlsfree[]
aFlsfree db 'FlsFree',0
; char aFlssetvalue[]
aFlssetvalue db	'FlsSetValue',0
; char aFlsgetvalue[]
aFlsgetvalue db	'FlsGetValue',0
; char aFlsalloc[]
aFlsalloc db 'FlsAlloc',0
align 10h
stru_10018BA0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10007B9D
		   offset loc_10007BC2,	\
		   offset loc_10007BC6>
align 10h
stru_10018BB0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10007BD2
		   offset loc_10007BEF,	\
		   offset loc_10007BF3>
align 10h
stru_10018BC0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 10007E75
		   offset loc_10007F1C>
align 10h
stru_10018BD0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 10008571
		   offset loc_1000859E,	\
		   offset loc_100085A2>
align 10h
stru_10018BE0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 100085B5
		   offset loc_100085E2,	\
		   offset loc_100085E6>
aRuntimeError db 'runtime error ',0
align 4
asc_10018BFC db	0Dh,0Ah,0
align 10h
aTlossError db 'TLOSS error',0Dh,0Ah,0
align 10h
aSingError db 'SING error',0Dh,0Ah,0
align 10h
aDomainError db	'DOMAIN error',0Dh,0Ah,0
align 10h
aR6029ThisAppli	db 'R6029',0Dh,0Ah
db '- This application cannot run using'
db ' the active version of the Microsof'
db 't .NET Runtime',0Ah
db 'Please contact the application',27h,'s'
db ' support team for more information.'
db 0Dh,0Ah,0
align 4
aR6028UnableToI	db 'R6028',0Dh,0Ah
db '- unable to initialize heap',0Dh,0Ah,0
align 4
aR6027NotEnough	db 'R6027',0Dh,0Ah
db '- not enough space for lowio initia'
db 'lization',0Dh,0Ah,0
align 4
aR6026NotEnough	db 'R6026',0Dh,0Ah
db '- not enough space for stdio initia'
db 'lization',0Dh,0Ah,0
align 4
aR6025PureVirtu	db 'R6025',0Dh,0Ah
db '- pure virtual function call',0Dh,0Ah,0
align 4
aR6024NotEnough	db 'R6024',0Dh,0Ah
db '- not enough space for _onexit/atex'
db 'it table',0Dh,0Ah,0
align 4
aR6019UnableToO	db 'R6019',0Dh,0Ah
db '- unable to open console device',0Dh,0Ah,0
align 4
aR6018Unexpecte	db 'R6018',0Dh,0Ah
db '- unexpected heap error',0Dh,0Ah,0
align 4
aR6017Unexpecte	db 'R6017',0Dh,0Ah
db '- unexpected multithread lock error'
db 0Dh,0Ah,0
align 4
aR6016NotEnough	db 'R6016',0Dh,0Ah
db '- not enough space for thread data',0Dh
db 0Ah,0
aThisApplicatio	db 0Dh,0Ah
db 'This application has requested the '
db 'Runtime to terminate it in an unusu'
db 'al way.',0Ah
db 'Please contact the application',27h,'s'
db ' support team for more information.'
db 0Dh,0Ah,0
align 10h
aR6009NotEnough	db 'R6009',0Dh,0Ah
db '- not enough space for environment',0Dh
db 0Ah,0
aR6008NotEnough	db 'R6008',0Dh,0Ah
db '- not enough space for arguments',0Dh,0Ah
db 0
align 4
aR6002FloatingP	db 'R6002',0Dh,0Ah
db '- floating point not loaded',0Dh,0Ah,0
align 10h
; char aRuntimeErrorPr[]
aRuntimeErrorPr	db 'Runtime Error!',0Ah
db 0Ah
db 'Program: ',0
align 10h
byte_10018FB0 db 6
db    0
db    0
db    6
db    0
db    1
db    0
db    0
db  10h
db    0
db    3
db    6
db    0
db    6
db    2
db  10h
db    4
db  45h	; E
db  45h	; E
db  45h	; E
db    5
db    5
db    5
db    5
db    5
db  35h	; 5
db  30h	; 0
db    0
db  50h	; P
db    0
db    0
db    0
db    0
db  20h
db  28h	; (
db  38h	; 8
db  50h	; P
db  58h	; X
db    7
db    8
db    0
db  37h	; 7
db  30h	; 0
db  30h	; 0
db  57h	; W
db  50h	; P
db    7
db    0
db    0
db  20h
db  20h
db    8
db    0
db    0
db    0
db    0
db    8
db  60h	; `
db  68h	; h
db  60h	; `
db  60h	; `
db  60h	; `
db  60h	; `
db    0
db    0
db  70h	; p
db  70h	; p
db  78h	; x
db  78h	; x
db  78h	; x
db  78h	; x
db    8
db    7
db    8
db    0
db    0
db    7
db    0
db    8
db    8
db    8
db    0
db    0
db    8
db    0
db    8
db    0
db    7
db    8
db    0
db    0
db    0
aNull_0:
unicode	0, <(null)>,0
align 4
aNull db '(null)',0
align 8
stru_10019028 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 100092DF
		   offset loc_10009909,	\
		   offset loc_1000990D>
; const	WCHAR SrcStr
SrcStr dw 0
align 4
stru_10019038 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 1000A32E
		   offset loc_1000A627,	\
		   offset loc_1000A62B>
_SCOPETABLE_ENTRY <0FFFFFFFFh, \
		   offset loc_1000A424,	\
		   offset loc_1000A428>
_SCOPETABLE_ENTRY <0FFFFFFFFh, \
		   offset loc_1000A4F2,	\
		   offset loc_1000A4F6>
align 10h
stru_10019060 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 1000A6EA
		   offset loc_1000A7C3,	\
		   offset loc_1000A7C7>
align 10h
aHH:
unicode	0, <	    h((((	       >
unicode	0, <	H>
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  20h
db    0
db    0
db    0
db    1
db    2
db    3
db    4
db    5
db    6
db    7
db    8
db    9
db  0Ah
db  0Bh
db  0Ch
db  0Dh
db  0Eh
db  0Fh
db  10h
db  11h
db  12h
db  13h
db  14h
db  15h
db  16h
db  17h
db  18h
db  19h
db  1Ah
db  1Bh
db  1Ch
db  1Dh
db  1Eh
db  1Fh
db  20h
db  21h	; !
db  22h	; "
db  23h	; #
db  24h	; $
db  25h	; %
db  26h	; &
db  27h	; '
db  28h	; (
db  29h	; )
db  2Ah	; *
db  2Bh	; +
db  2Ch	; ,
db  2Dh	; -
db  2Eh	; .
db  2Fh	; /
db  30h	; 0
db  31h	; 1
db  32h	; 2
db  33h	; 3
db  34h	; 4
db  35h	; 5
db  36h	; 6
db  37h	; 7
db  38h	; 8
db  39h	; 9
db  3Ah	; :
db  3Bh	; ;
db  3Ch	; <
db  3Dh	; =
db  3Eh	; >
db  3Fh	; ?
db  40h	; @
db  41h	; A
db  42h	; B
db  43h	; C
db  44h	; D
db  45h	; E
db  46h	; F
db  47h	; G
db  48h	; H
db  49h	; I
db  4Ah	; J
db  4Bh	; K
db  4Ch	; L
db  4Dh	; M
db  4Eh	; N
db  4Fh	; O
db  50h	; P
db  51h	; Q
db  52h	; R
db  53h	; S
db  54h	; T
db  55h	; U
db  56h	; V
db  57h	; W
db  58h	; X
db  59h	; Y
db  5Ah	; Z
db  5Bh	; [
db  5Ch	; \
db  5Dh	; ]
db  5Eh	; ^
db  5Fh	; _
db  60h	; `
db  61h	; a
db  62h	; b
db  63h	; c
db  64h	; d
db  65h	; e
db  66h	; f
db  67h	; g
db  68h	; h
db  69h	; i
db  6Ah	; j
db  6Bh	; k
db  6Ch	; l
db  6Dh	; m
db  6Eh	; n
db  6Fh	; o
db  70h	; p
db  71h	; q
db  72h	; r
db  73h	; s
db  74h	; t
db  75h	; u
db  76h	; v
db  77h	; w
db  78h	; x
db  79h	; y
db  7Ah	; z
db  7Bh	; {
db  7Ch	; |
db  7Dh	; }
db  7Eh	; ~
db  7Fh	; 
db    0
stru_100191F0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000AAAC
		   offset loc_1000AADE>
align 10h
dbl_10019200 dq	0.0
; char aE000[]
aE000 db 'e+000',0
align 10h
dbl_10019210 dq	1.0
dbl_10019218 dq	4195835.0
dbl_10019220 dq	3145727.0
; char aIsprocessorfea[]
aIsprocessorfea	db 'IsProcessorFeaturePresent',0
align 4
; char aKernel32[]
aKernel32 db 'KERNEL32',0
align 10h
aSunmontuewedth	db 'SunMonTueWedThuFriSat',0
align 4
aJanfebmaraprma	db 'JanFebMarAprMayJunJulAugSepOctNovDe'
db 'c',0
align 10h
; char aInitializecrit[]
aInitializecrit	db 'InitializeCriticalSectionAndSpinCou'
db 'nt',0
align 4
stru_100192B8 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 1000B0F2
		   offset loc_1000B14F,	\
		   offset loc_1000B15D>
; char aGetprocesswind[]
aGetprocesswind	db 'GetProcessWindowStation',0
; char aGetuserobjecti[]
aGetuserobjecti	db 'GetUserObjectInformationA',0
align 4
; char aGetlastactivep[]
aGetlastactivep	db 'GetLastActivePopup',0
align 4
; char aGetactivewindo[]
aGetactivewindo	db 'GetActiveWindow',0
; char aMessageboxa[]
aMessageboxa db	'MessageBoxA',0
stru_10019328 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000B480
		   offset loc_1000B504>
align 8
stru_10019338 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000B6F9
		   offset loc_1000B77D>
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
asc_10019448:
unicode	0, <	     (((((	       >
unicode	0, <	 H>
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  81h	; 
db    0
db  81h	; 
db    0
db  81h	; 
db    0
db  81h	; 
db    0
db  81h	; 
db    0
db  81h	; 
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db    1
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  82h	; ‚
db    0
db  82h	; ‚
db    0
db  82h	; ‚
db    0
db  82h	; ‚
db    0
db  82h	; ‚
db    0
db  82h	; ‚
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db    2
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  20h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001964A db	 20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  68h	; h
db    0
db  28h	; (
db    0
db  28h	; (
db    0
db  28h	; (
db    0
db  28h	; (
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  48h	; H
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  84h	; „
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db  81h	; 
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db  82h	; ‚
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  20h
db    0
db  48h	; H
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  14h
db    0
db  14h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  14h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db  10h
db    0
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db  10h
db    0
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db  10h
db    0
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    2
db    1
db    1
db    1
db    0
db    0
db    0
db    0
stru_10019850 _SCOPETABLE_ENTRY	<0FFFFFFFFh, \ ; SEH scope table for function 1000BDC3
		   offset loc_1000BE95,	\
		   offset loc_1000BE99>
aHhMmSs	db 'HH:mm:ss',0
align 4
aDdddMmmmDdYyyy	db 'dddd, MMMM dd, yyyy',0
aMmDdYy	db 'MM/dd/yy',0
align 4
aPm db 'PM',0
align 4
aAm db 'AM',0
align 10h
aDecember db 'December',0
align 4
aNovember db 'November',0
align 4
aOctober db 'October',0
aSeptember db 'September',0
align 4
aAugust	db 'August',0
align 4
aJuly db 'July',0
align 4
aJune db 'June',0
align 4
aApril db 'April',0
align 4
aMarch db 'March',0
align 4
aFebruary db 'February',0
align 10h
aJanuary db 'January',0
aDec db	'Dec',0
aNov db	'Nov',0
aOct db	'Oct',0
aSep db	'Sep',0
aAug db	'Aug',0
aJul db	'Jul',0
aJun db	'Jun',0
aMay db	'May',0
aApr db	'Apr',0
aMar db	'Mar',0
aFeb db	'Feb',0
aJan db	'Jan',0
aSaturday db 'Saturday',0
align 4
aFriday	db 'Friday',0
align 4
aThursday db 'Thursday',0
align 4
aWednesday db 'Wednesday',0
align 4
aTuesday db 'Tuesday',0
aMonday	db 'Monday',0
align 4
aSunday	db 'Sunday',0
align 4
aSat db	'Sat',0
aFri db	'Fri',0
aThu db	'Thu',0
aWed db	'Wed',0
aTue db	'Tue',0
aMon db	'Mon',0
aSun db	'Sun',0
stru_10019988 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000CAA4
		   offset loc_1000CBD7>
align 8
stru_10019998 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000CCDD
		   offset loc_1000CD71>
align 8
stru_100199A8 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000CE22
		   offset loc_1000CEB4>
align 8
stru_100199B8 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000CF48
		   offset loc_1000D014>
_SCOPETABLE_ENTRY <0, 0, \
		   offset loc_1000CFE3>
stru_100199D0 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000D201
		   offset loc_1000D285>
; char a1Qnan[]
a1Qnan db '1#QNAN',0
align 4
; char a1Inf[]
a1Inf db '1#INF',0
align 4
a1Ind db '1#IND',0
align 4
a1Snan db '1#SNAN',0
align 10h
stru_10019A00 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000DBC4
		   offset loc_1000DC0A>
align 10h
stru_10019A10 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000DC15
		   offset loc_1000DCB2>
align 10h
stru_10019A20 _SCOPETABLE_ENTRY	<0FFFFFFFFh, 0,	\ ; SEH	scope table for	function 1000E07C
		   offset loc_1000E0F0>
align 10h
unk_10019A30 db	   0
db    4
db    2
db    0
db    0
db    0
db    0
db    0
db 0C0h	; À
db    0
db    0
db    0
db    0
db    0
db    0
db  46h	; F
dword_10019A40 dd 0
dword_10019A44 dd 0
dword_10019A48 dd 0C0h
dword_10019A4C dd 46000000h
db  10h
db  59h	; Y
db  2Fh	; /
db 0B6h	; ¶
db  28h	; (
db  65h	; e
db 0D1h	; Ñ
db  11h
db  96h	; –
db  11h
db    0
db    0
db 0F8h	; ø
db  1Eh
db  0Dh
db  0Dh
unk_10019A60 db	0E0h ; à
db  3Dh	; =
db  4Ch	; L
db  39h	; 9
db  6Fh	; o
db  3Ch	; <
db 0D2h	; Ò
db  11h
db  81h	; 
db  7Bh	; {
db    0
db 0C0h	; À
db  4Fh	; O
db  79h	; y
db  7Ah	; z
db 0B7h	; ·
aOleacc_dll db 'OLEACC.dll',0
align 4
db  52h	; R
db  53h	; S
db  44h	; D
db  53h	; S
db  0Ch
db  96h	; –
db  0Bh
db 0DFh	; ß
db  22h	; "
db    8
db  47h	; G
db  45h	; E
db 0B4h	; ´
db  8Ch	; Œ
db  22h	; "
db 0B5h	; µ
db 0F6h	; ö
db 0EDh	; í
db 0D7h	; ×
db  22h	; "
db    2
db    0
db    0
db    0
db  63h	; c
db  3Ah	; :
db  5Ch	; \
db  55h	; U
db  73h	; s
db  62h	; b
db  20h
db  68h	; h
db  69h	; i
db  64h	; d
db  5Ch	; \
db  44h	; D
db  4Ch	; L
db  4Ch	; L
db  20h
db  56h	; V
db  65h	; e
db  72h	; r
db  73h	; s
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  5Ch	; \
db  32h	; 2
db  30h	; 0
db  30h	; 0
db  39h	; 9
db  2Eh	; .
db  30h	; 0
db  38h	; 8
db  2Eh	; .
db  32h	; 2
db  34h	; 4
db  5Ch	; \
db  73h	; s
db  48h	; H
db  49h	; I
db  44h	; D
db  5Ch	; \
db  52h	; R
db  65h	; e
db  6Ch	; l
db  65h	; e
db  61h	; a
db  73h	; s
db  65h	; e
db  5Ch	; \
db  73h	; s
db  48h	; H
db  49h	; I
db  44h	; D
db  2Eh	; .
db  70h	; p
db  64h	; d
db  62h	; b
db    0
off_10019ACC dd	offset off_1001D124
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019AE4 dd	offset off_1001D13C
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019AFC dd	offset off_1001D158
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019B14 dd	offset off_1001D174
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019B2C dd	offset off_10019B14
dd offset off_10019AFC
dd offset off_10019AE4
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019B40 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019B2C
unk_10019B50 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D174
dd offset unk_10019B40
off_10019B64 dd	offset off_10019AFC
dd offset off_10019AE4
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019B74 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
dd offset off_10019B64
unk_10019B84 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D158
dd offset unk_10019B74
off_10019B98 dd	offset off_1001D1D4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019BB0 dd	offset off_10019B98
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset off_10019BB0
unk_10019BC8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D1D4
dd offset unk_10019BB8
off_10019BDC dd	offset off_1001D1F0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019BF4 dd	offset off_1001D20C
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019C0C dd	offset off_10019BF4
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019C1C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
dd offset off_10019C0C
unk_10019C2C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D20C
dd offset unk_10019C1C
off_10019C40 dd	offset off_1001D2B0
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019C58 dd	offset off_1001D2D0
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019C70 dd	offset off_10019C58
dd offset off_10019C40
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019C84 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019C70
unk_10019C94 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D2D0
dd offset unk_10019C84
off_10019CA8 dd	offset off_1001D2F0
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019CC0 dd	offset off_10019CA8
dd offset off_10019C40
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019CD4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019CC0
unk_10019CE4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D2F0
dd offset unk_10019CD4
off_10019CF8 dd	offset off_1001D318
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019D10 dd	offset off_10019CF8
dd offset off_10019C40
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019D24 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019D10
unk_10019D34 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D318
dd offset unk_10019D24
off_10019D48 dd	offset off_1001D33C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019D60 dd	offset off_1001D35C
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019D78 dd	offset off_10019D60
dd offset off_10019D48
db    0
db    0
db    0
db    0
unk_10019D84 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_10019D78
unk_10019D94 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D35C
dd offset unk_10019D84
off_10019DA8 dd	offset off_1001D378
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019DC0 dd	offset off_10019DA8
dd offset off_10019D48
db    0
db    0
db    0
db    0
unk_10019DCC db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_10019DC0
unk_10019DDC db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D378
dd offset unk_10019DCC
off_10019DF0 dd	offset off_1001D398
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019E08 dd	offset off_10019DF0
dd offset off_10019D48
db    0
db    0
db    0
db    0
unk_10019E14 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_10019E08
unk_10019E24 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D398
dd offset unk_10019E14
off_10019E38 dd	offset off_1001D3B8
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019E50 dd	offset off_10019E38
dd offset off_10019D48
db    0
db    0
db    0
db    0
unk_10019E5C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_10019E50
unk_10019E6C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D3B8
dd offset unk_10019E5C
off_10019E80 dd	offset off_1001D3E0
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019E98 dd	offset off_10019E80
dd offset off_10019DF0
dd offset off_10019D48
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
dd offset off_10019E98
unk_10019EB8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D3E0
dd offset unk_10019EA8
off_10019ECC dd	offset off_1001D408
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019EE4 dd	offset off_10019ECC
db    0
db    0
db    0
db    0
unk_10019EEC db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset off_10019EE4
unk_10019EFC db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D408
dd offset unk_10019EEC
off_10019F10 dd	offset off_1001D444
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019F28 dd	offset off_10019F10
dd offset off_10019C40
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019F3C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019F28
unk_10019F4C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D444
dd offset unk_10019F3C
off_10019F60 dd	offset off_1001D468
db    3
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019F78 dd	offset off_10019F60
dd offset off_10019C40
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019F8C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
dd offset off_10019F78
unk_10019F9C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D468
dd offset unk_10019F8C
off_10019FB0 dd	offset off_1001D488
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_10019FC8 dd	offset off_10019FB0
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_10019FD4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_10019FC8
unk_10019FE4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D488
dd offset unk_10019FD4
off_10019FF8 dd	offset off_1001D4A4
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A010 dd	offset off_10019FF8
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_1001A01C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A010
unk_1001A02C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D4A4
dd offset unk_1001A01C
off_1001A040 dd	offset off_1001D4B8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A058 dd	offset off_1001D4D8
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A070 dd	offset off_1001A058
dd offset off_1001A040
db    0
db    0
db    0
db    0
unk_1001A07C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A070
unk_1001A08C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D4D8
dd offset unk_1001A07C
off_1001A0A0 dd	offset off_1001D594
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A0B8 dd	offset off_1001A0A0
db    0
db    0
db    0
db    0
unk_1001A0C0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset off_1001A0B8
unk_1001A0D0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D594
dd offset unk_1001A0C0
off_1001A0E4 dd	offset off_1001D5B4
align 10h
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A0FC dd	offset off_1001A0E4
db    0
db    0
db    0
db    0
unk_1001A104 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset off_1001A0FC
unk_1001A114 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D5B4
dd offset unk_1001A104
off_1001A128 dd	offset off_1001D5DC
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A140 dd	offset off_1001A128
dd offset off_10019AE4
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_1001A150 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
dd offset off_1001A140
unk_1001A160 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D5DC
dd offset unk_1001A150
off_1001A174 dd	offset off_1001D5F0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A18C dd	offset off_1001A174
dd offset off_10019D48
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A18C
unk_1001A1A8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D5F0
dd offset unk_1001A198
off_1001A1BC dd	offset off_1001D614
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A1D4 dd	offset off_1001A1BC
dd offset off_10019B98
db    0
db    0
db    0
db    0
unk_1001A1E0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A1D4
unk_1001A1F0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D614
dd offset unk_1001A1E0
off_1001A204 dd	offset off_1001D650
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
off_1001A21C dd	offset off_1001D630
db    1
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A234 dd	offset off_1001D650
align 10h
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
off_1001A24C dd	offset off_1001D668
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A264 dd	offset off_1001D680
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A27C dd	offset off_1001D6A0
db    5
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A294 db	   0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D790
dd offset unk_1001A380
unk_1001A2A8 db	   0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D790
dd offset unk_1001A380
off_1001A2BC dd	offset off_1001D650
db    0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
off_1001A2D4 dd	offset off_1001D6E4
db    1
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A2EC dd	offset off_1001D700
db    0
db    0
db    0
db    0
db  14h
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A304 dd	offset off_1001D728
db    1
db    0
db    0
db    0
db  14h
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A31C dd	offset off_1001D76C
db  0Ah
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A334 dd	offset off_1001D790
db  0Bh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A34C dd	offset off_1001A334
dd offset off_1001A31C
dd offset off_1001A304
dd offset off_1001A2EC
dd offset off_1001A27C
dd offset off_1001A264
dd offset off_1001A24C
dd offset off_1001A234
dd offset off_1001A21C
dd offset off_1001A204
dd offset off_1001A2D4
dd offset off_1001A2BC
align 10h
unk_1001A380 db	   0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db  0Ch
db    0
db    0
db    0
dd offset off_1001A34C
unk_1001A390 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D790
dd offset unk_1001A380
off_1001A3A4 dd	offset off_1001D7C8
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A3BC dd	offset off_1001A3A4
dd offset off_10019ACC
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A3BC
unk_1001A3D8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D7C8
dd offset unk_1001A3C8
off_1001A3EC dd	offset off_1001D7E4
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A404 dd	offset off_1001A3EC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_1001A410 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A404
unk_1001A420 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D7E4
dd offset unk_1001A410
off_1001A434 dd	offset off_1001D818
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A44C dd	offset off_1001A434
dd offset off_10019BDC
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_1001A45C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    3
db    0
db    0
db    0
dd offset off_1001A44C
unk_1001A46C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D818
dd offset unk_1001A45C
off_1001A480 dd	offset off_1001D854
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A498 dd	offset off_1001A480
dd offset off_10019ACC
db    0
db    0
db    0
db    0
unk_1001A4A4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
dd offset off_1001A498
unk_1001A4B4 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D854
dd offset unk_1001A4A4
off_1001A4C8 dd	offset off_1001D894
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001A4E0 dd	offset off_1001A4C8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset off_1001A4E0
unk_1001A4F8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001D894
dd offset unk_1001A4E8
align 10h
unk_1001A510 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A518 db	   0
db    0
db    0
db    0
stru_1001A51C _msExcInfo <-1, offset sub_10016790>
stru_1001A524 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A51C, 0, 0,	\
	    0>
stru_1001A540 _msExcInfo <-1, offset sub_100167A3>
stru_1001A548 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A540, 0, 0,	\
	    0>
stru_1001A564 _msExcInfo <-1, offset sub_100167B5>
stru_1001A56C _msExcept7 <19930520h, 1,	\
	    offset stru_1001A564, 0, 0,	\
	    0>
stru_1001A588 _msExcInfo <-1, offset sub_100167C7>
stru_1001A590 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A588, 0, 0,	\
	    0>
stru_1001A5AC _msExcInfo <-1, offset sub_100167D9>
stru_1001A5B4 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A5AC, 0, 0,	\
	    0>
unk_1001A5D0 db	0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset sub_100167EB
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
unk_1001A5E8 db	   0
db    0
db    0
db    0
dd offset off_1001D18C
db 0D8h	; Ø
db 0FEh	; þ
db 0FFh
db 0FFh
dd offset loc_10014919
unk_1001A5F8 db	   0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset unk_1001A5E8
unk_1001A60C db	 20h
db    5
db  93h	; “
db  19h
db    3
db    0
db    0
db    0
dd offset unk_1001A5D0
db    1
db    0
db    0
db    0
dd offset unk_1001A5F8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
stru_1001A628 _msExcInfo <-1, offset sub_10016800>
_msExcInfo <0, offset sub_1001680B>
_msExcInfo <1, offset sub_10016816>
_msExcInfo <0, offset sub_10016816>
stru_1001A648 _msExcept7 <19930520h, 4,	\
	    offset stru_1001A628, 0, 0,	\
	    0>
stru_1001A664 _msExcInfo 6 dup(<-1, 0>)
stru_1001A694 _msRttiDscr <0, offset stru_1001D1AC, \
	     -20, offset sub_1000EDA4>
stru_1001A6A4 _msRttiDscr <0, offset stru_1001D1AC, \
	     -20, offset sub_1000EDB2>
stru_1001A6B4 _msRttiDscr <0, offset stru_1001D1AC, \
	     -20, offset sub_1000EDC0>
stru_1001A6C4 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001A694	; RttiBlkPtr
dd 2, 2, 3		; _unk
dd 1			; Count
dd offset stru_1001A6A4	; RttiBlkPtr
dd 4, 4, 5		; _unk
dd 1			; Count
dd offset stru_1001A6B4	; RttiBlkPtr
stru_1001A700 _msExcept7 <19930520h, 6,	\
	    offset stru_1001A664, 3, \
	    offset stru_1001A6C4, 0>
stru_1001A71C _msExcInfo <-1, offset sub_10016847>
stru_1001A724 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A71C, 0, 0,	\
	    0>
stru_1001A740 _msExcInfo <-1, offset sub_10016835>
stru_1001A748 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A740, 0, 0,	\
	    0>
unk_1001A764 db	   1
db    0
db    0
db    0
dd offset off_1001D228
align 10h
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A780 db	   1
db    0
db    0
db    0
dd offset off_1001D238
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A79C db	   1
db    0
db    0
db    0
dd offset stru_1001D1AC
align 8
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A7B8 db	   1
db    0
db    0
db    0
dd offset off_1001D250
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A7D4 db	   4
db    0
db    0
db    0
dd offset unk_1001A7B8
dd offset unk_1001A79C
dd offset unk_1001A780
dd offset unk_1001A764
unk_1001A7E8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001A7D4
stru_1001A7F8 _msExcInfo <-1, offset sub_1001685A>
stru_1001A800 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A7F8, 0, 0,	\
	    0>
unk_1001A81C db	   1
db    0
db    0
db    0
dd offset off_1001D26C
align 8
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A838 db	   1
db    0
db    0
db    0
dd offset off_1001D18C
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A854 db	   5
db    0
db    0
db    0
dd offset unk_1001A838
dd offset unk_1001A81C
dd offset unk_1001A79C
dd offset unk_1001A780
dd offset unk_1001A764
unk_1001A86C db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001A854
unk_1001A87C db	   1
db    0
db    0
db    0
dd offset off_1001D28C
align 8
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A898 db	   5
db    0
db    0
db    0
dd offset unk_1001A87C
dd offset unk_1001A81C
dd offset unk_1001A79C
dd offset unk_1001A780
dd offset unk_1001A764
unk_1001A8B0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001A898
stru_1001A8C0 _msExcInfo 2 dup(<-1, 0>)
stru_1001A8D0 _msRttiDscr <0, offset stru_1001D1AC, \
	     -20, offset sub_10014F52>
stru_1001A8E0 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001A8D0	; RttiBlkPtr
stru_1001A8F4 _msExcept7 <19930520h, 2,	\
	    offset stru_1001A8C0, 1, \
	    offset stru_1001A8E0, 0>
stru_1001A910 _msExcInfo <-1, offset sub_10016877>
stru_1001A918 _msExcept7 <19930520h, 1,	\
	    offset stru_1001A910, 0, 0,	\
	    0>
stru_1001A934 _msExcInfo <-1, offset sub_10016891>
stru_1001A93C _msExcept7 <19930520h, 1,	\
	    offset stru_1001A934, 0, 0,	\
	    0>
stru_1001A958 _msExcInfo 2 dup(<-1, 0>)
stru_1001A968 _msRttiDscr <0, offset stru_1001D1AC, \
	     -20, offset sub_1000F9CE>
stru_1001A978 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001A968	; RttiBlkPtr
stru_1001A98C _msExcept7 <19930520h, 2,	\
	    offset stru_1001A958, 1, \
	    offset stru_1001A978, 0>
stru_1001A9A8 _msExcInfo <-1, offset sub_100168B3>
_msExcInfo <0, offset sub_100168BE>
_msExcInfo <1, offset sub_100168C9>
stru_1001A9C0 _msExcept7 <19930520h, 3,	\
	    offset stru_1001A9A8, 0, 0,	\
	    0>
unk_1001A9DC db	   1
db    0
db    0
db    0
dd offset off_1001D424
align 8
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001A9F8 db	   5
db    0
db    0
db    0
dd offset unk_1001A9DC
dd offset unk_1001A81C
dd offset unk_1001A79C
dd offset unk_1001A780
dd offset unk_1001A764
unk_1001AA10 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001A9F8
stru_1001AA20 _msExcInfo <-1, \
	    offset __ehhandler$?FromHandle@CHandleMap@@QAEPAVCObject@@PAX@Z>
stru_1001AA28 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AA20, 0, 0,	\
	    0>
stru_1001AA44 _msExcInfo 2 dup(<-1, 0>)
stru_1001AA54 _msRttiDscr <0, offset stru_1001D1AC, \
	     -68, offset sub_1001002A>
stru_1001AA64 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001AA54	; RttiBlkPtr
stru_1001AA78 _msExcept7 <19930520h, 2,	\
	    offset stru_1001AA44, 1, \
	    offset stru_1001AA64, 0>
stru_1001AA94 _msExcInfo <-1, offset sub_100168FC>
stru_1001AA9C _msExcept7 <19930520h, 1,	\
	    offset stru_1001AA94, 0, 0,	\
	    0>
stru_1001AAB8 _msExcInfo <-1, offset sub_1001690F>
stru_1001AAC0 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AAB8, 0, 0,	\
	    0>
stru_1001AADC _msExcInfo <-1, offset sub_10016925>
stru_1001AAE4 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AADC, 0, 0,	\
	    0>
stru_1001AB00 _msExcInfo 2 dup(<-1, 0>)
stru_1001AB10 _msRttiDscr <0, offset stru_1001D1AC, \
	     12, offset	loc_100116B0>
stru_1001AB20 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001AB10	; RttiBlkPtr
stru_1001AB34 _msExcept7 <19930520h, 2,	\
	    offset stru_1001AB00, 1, \
	    offset stru_1001AB20, 0>
stru_1001AB50 _msExcInfo <-1, offset sub_10016943>
stru_1001AB58 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AB50, 0, 0,	\
	    0>
stru_1001AB74 _msExcInfo <-1, offset sub_10016955>
stru_1001AB7C _msExcept7 <19930520h, 1,	\
	    offset stru_1001AB74, 0, 0,	\
	    0>
unk_1001AB98 db	0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset sub_10016967
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
unk_1001ABB0 db	   0
db    0
db    0
db    0
dd offset stru_1001D1AC
db 0E0h	; à
db 0FFh
db 0FFh
db 0FFh
dd offset loc_10016338
unk_1001ABC0 db	   0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset unk_1001ABB0
unk_1001ABD4 db	 20h
db    5
db  93h	; “
db  19h
db    3
db    0
db    0
db    0
dd offset unk_1001AB98
db    1
db    0
db    0
db    0
dd offset unk_1001ABC0
align 10h
stru_1001ABF0 _msExcInfo 2 dup(<-1, 0>)
stru_1001AC00 _msRttiDscr <0, offset stru_1001D1AC, \
	     -32, offset sub_10011FBC>
stru_1001AC10 dd 0, 0, 1	      ;	_unk
dd 1			; Count
dd offset stru_1001AC00	; RttiBlkPtr
stru_1001AC24 _msExcept7 <19930520h, 2,	\
	    offset stru_1001ABF0, 1, \
	    offset stru_1001AC10, 0>
stru_1001AC40 _msExcInfo <-1, offset sub_10016985>
_msExcInfo <0, offset sub_1001698D>
_msExcInfo <-1,	offset sub_10016995>
stru_1001AC58 _msExcept7 <19930520h, 3,	\
	    offset stru_1001AC40, 0, 0,	\
	    0>
stru_1001AC74 _msExcInfo <-1, offset sub_100169A7>
stru_1001AC7C _msExcept7 <19930520h, 1,	\
	    offset stru_1001AC74, 0, 0,	\
	    0>
stru_1001AC98 _msExcInfo <-1, offset sub_100169B9>
stru_1001ACA0 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AC98, 0, 0,	\
	    0>
stru_1001ACBC _msExcInfo <-1, offset sub_100169CB>
stru_1001ACC4 _msExcept7 <19930520h, 1,	\
	    offset stru_1001ACBC, 0, 0,	\
	    0>
unk_1001ACE0 db	0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset sub_100169DF
db    1
db    0
db    0
db    0
dd offset sub_100169E7
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
unk_1001AD00 db	   0
db    0
db    0
db    0
dd offset stru_1001D1AC
db 0E8h	; è
db 0FFh
db 0FFh
db 0FFh
dd offset loc_100139E8
unk_1001AD10 db	   0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    3
db    0
db    0
db    0
db    1
db    0
db    0
db    0
dd offset unk_1001AD00
unk_1001AD24 db	 20h
db    5
db  93h	; “
db  19h
db    4
db    0
db    0
db    0
dd offset unk_1001ACE0
db    1
db    0
db    0
db    0
dd offset unk_1001AD10
align 10h
stru_1001AD40 _msExcInfo <-1, offset sub_100169F9>
stru_1001AD48 _msExcept7 <19930520h, 1,	\
	    offset stru_1001AD40, 0, 0,	\
	    0>
unk_1001AD64 db	   1
db    0
db    0
db    0
dd offset off_1001D7F8
align 10h
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001AD80 db	   4
db    0
db    0
db    0
dd offset unk_1001AD64
dd offset unk_1001A79C
dd offset unk_1001A780
dd offset unk_1001A764
unk_1001AD94 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001AD80
stru_1001ADA4 _msExcInfo <-1, offset sub_10016A0E>
stru_1001ADAC _msExcept7 <19930520h, 1,	\
	    offset stru_1001ADA4, 0, 0,	\
	    0>
stru_1001ADC8 _msExcInfo <-1, offset sub_10016A21>
stru_1001ADD0 _msExcept7 <19930520h, 1,	\
	    offset stru_1001ADC8, 0, 0,	\
	    0>
OLEACC_dll_import_table	dd 1 ; Attributes
dd rva aOleacc_dll	; "OLEACC.dll"
dd rva OLEACC_dll_handle ; Module handle
dd rva __imp_LresultFromObject ; Delayed Import	Address	Table
dd rva OLEACC_dll_dint	; Delayed Import Name Table
dd rva OLEACC_dll_dbiat	; Bound	Delayed	Import Address Table
dd 0			; Unload Delayed Import	Table
dd 0			; Time stamp
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
OLEACC_dll_dint	dd rva word_1001AE54 ; OLEACC.dll delayed import name table
dd rva word_1001AE38
dd 0
word_1001AE38 dw 0
aCreatestdacces	db 'CreateStdAccessibleObject',0
word_1001AE54 dw 0
aLresultfromobj	db 'LresultFromObject',0
OLEACC_dll_dbiat dd 0	; OLEACC.dll bound delayed import address table
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
__IMPORT_DESCRIPTOR_HID	dd rva off_1001AFE0 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aHid_dll		; DLL Name
dd rva __imp_HidD_GetFeature ; Import Address Table
__IMPORT_DESCRIPTOR_SETUPAPI dd	rva off_1001B1C0 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aSetupapi_dll	; DLL Name
dd rva SetupDiGetDeviceInterfaceDetailA	; Import Address Table
__IMPORT_DESCRIPTOR_KERNEL32 dd	rva off_1001B000 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aKernel32_dll	; DLL Name
dd rva SetStdHandle	; Import Address Table
__IMPORT_DESCRIPTOR_USER32 dd rva off_1001B1E0 ; Import	Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aUser32_dll	; DLL Name
dd rva GetSysColorBrush	; Import Address Table
__IMPORT_DESCRIPTOR_GDI32 dd rva off_1001AF80 ;	Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aGdi32_dll	; DLL Name
dd rva SetBkColor	; Import Address Table
__IMPORT_DESCRIPTOR_WINSPOOL_DRV dd rva	off_1001B33C ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aWinspool_drv	; DLL Name
dd rva __imp_OpenPrinterA ; Import Address Table
__IMPORT_DESCRIPTOR_ADVAPI32 dd	rva off_1001AF50 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aAdvapi32_dll	; DLL Name
dd rva RegQueryValueExA	; Import Address Table
__IMPORT_DESCRIPTOR_COMCTL32 dd	rva dword_1001AF78 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aComctl32_dll	; DLL Name
dd rva InitCommonControls ; Import Address Table
__IMPORT_DESCRIPTOR_SHLWAPI dd rva off_1001B1D4	; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aShlwapi_dll	; DLL Name
dd rva PathFindFileNameA ; Import Address Table
__IMPORT_DESCRIPTOR_OLEAUT32 dd	rva dword_1001B1B0 ; Import Name Table
dd 0			; Time stamp
dd 0			; Forwarder Chain
dd rva aOleaut32_dll	; DLL Name
dd rva VariantClear	; Import Address Table
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
;
; Import names for ADVAPI32.dll
;
off_1001AF50 dd	rva word_1001BCEC
dd rva word_1001BD00
dd rva word_1001BD10
dd rva word_1001BD20
dd rva word_1001BD2E
dd rva word_1001BD3C
dd rva word_1001BD4E
dd rva word_1001BD60
dd rva word_1001BCDE
dd 0
;
; Import names for COMCTL32.dll
;
dword_1001AF78 dd 80000011h
dd 0
;
; Import names for GDI32.dll
;
off_1001AF80 dd	rva word_1001BB62
dd rva word_1001BB56
dd rva word_1001BB4C
dd rva word_1001BB3C
dd rva word_1001BB2C
dd rva word_1001BC70
dd rva word_1001BC64
dd rva word_1001BC50
dd rva word_1001BC3E
dd rva word_1001BC28
dd rva word_1001BC14
dd rva word_1001BBFE
dd rva word_1001BBEA
dd rva word_1001BBDA
dd rva word_1001BBD0
dd rva word_1001BBC2
dd rva word_1001BBB6
dd rva word_1001BBA8
dd rva word_1001BB9C
dd rva word_1001BB8E
dd rva word_1001BB80
dd rva word_1001BB70
dd rva word_1001BB1C
dd 0
;
; Import names for HID.DLL
;
off_1001AFE0 dd	rva word_1001B3C8
dd rva word_1001B3B6
dd rva word_1001B3A0
dd rva word_1001B388
dd rva word_1001B378
dd rva word_1001B35E
dd rva word_1001B34C
dd 0
;
; Import names for KERNEL32.dll
;
off_1001B000 dd	rva word_1001C410
dd rva word_1001C400
dd rva word_1001C3F0
dd rva word_1001C3DE
dd rva word_1001C3CC
dd rva word_1001C3BC
dd rva word_1001C3AC
dd rva word_1001C38E
dd rva word_1001C372
dd rva word_1001C358
dd rva word_1001C33E
dd rva word_1001C326
dd rva word_1001C30C
dd rva word_1001C2FA
dd rva word_1001C2EC
dd rva word_1001C2DC
dd rva word_1001C2CA
dd rva word_1001C2B0
dd rva word_1001C29A
dd rva word_1001C28A
dd rva word_1001C270
dd rva word_1001C260
dd rva word_1001C252
dd rva word_1001C244
dd rva word_1001C236
dd rva word_1001C228
dd rva word_1001C21C
dd rva word_1001C208
dd rva word_1001C1F6
dd rva word_1001C1E6
dd rva word_1001C1D6
dd rva word_1001C1C6
dd rva word_1001C1B4
dd rva word_1001C1A8
dd rva word_1001C19A
dd rva word_1001C18E
dd rva word_1001C182
dd rva word_1001C176
dd rva word_1001C16A
dd rva word_1001C156
dd rva word_1001C142
dd rva word_1001C130
dd rva word_1001C124
dd rva word_1001C10E
dd rva word_1001C0FC
dd rva word_1001C0F0
dd rva word_1001C0DE
dd rva word_1001C0D0
dd rva word_1001C0B8
dd rva word_1001C09A
dd rva word_1001C08A
dd rva word_1001C07E
dd rva word_1001C066
dd rva word_1001C05C
dd rva word_1001C044
dd rva word_1001C034
dd rva word_1001C026
dd rva word_1001C01A
dd rva word_1001BFFE
dd rva word_1001BFF0
dd rva word_1001BFD8
dd rva word_1001BFC8
dd rva word_1001BFB8
dd rva word_1001BFA0
dd rva word_1001BF92
dd rva word_1001BF82
dd rva word_1001BF74
dd rva word_1001BF64
dd rva word_1001BF52
dd rva word_1001BF46
dd rva word_1001BF3A
dd rva word_1001BF28
dd rva word_1001BF18
dd rva word_1001BF08
dd rva word_1001BEF8
dd rva word_1001BEE6
dd rva word_1001BED2
dd rva word_1001BEBC
dd rva word_1001BEAE
dd rva word_1001BEA0
dd rva word_1001BE92
dd rva word_1001BE7E
dd rva word_1001BE72
dd rva word_1001BE5C
dd rva word_1001BE48
dd rva word_1001BE36
dd rva word_1001BE1E
dd rva word_1001BE04
dd rva word_1001BDF8
dd rva word_1001BDE8
dd rva word_1001B46A
dd rva word_1001B478
dd rva word_1001B488
dd rva word_1001B496
dd rva word_1001B4A6
dd rva word_1001B4B2
dd rva word_1001B4C8
dd rva word_1001B4D4
dd rva word_1001B4E4
dd rva word_1001B4FA
dd rva word_1001B56E
dd rva word_1001B562
dd rva word_1001B54C
dd rva word_1001B536
dd rva word_1001B528
dd rva word_1001B516
dd rva word_1001B504
dd 0
;
; Import names for OLEAUT32.dll
;
dword_1001B1B0 dd 80000009h
dd 8000000Ch
dd 80000008h
dd 0
;
; Import names for SETUPAPI.dll
;
off_1001B1C0 dd	rva word_1001B402
dd rva word_1001B444
dd rva word_1001B426
dd rva word_1001B3E2
dd 0
;
; Import names for SHLWAPI.dll
;
off_1001B1D4 dd	rva word_1001BDB0
dd rva word_1001BD9A
dd 0
;
; Import names for USER32.dll
;
off_1001B1E0 dd	rva word_1001B8B8
dd rva word_1001B8CC
dd rva word_1001B8E0
dd rva word_1001B8EE
dd rva word_1001B8FC
dd rva word_1001B90E
dd rva word_1001B91C
dd rva word_1001B92C
dd rva word_1001B938
dd rva word_1001B94E
dd rva word_1001B95A
dd rva word_1001B588
dd rva word_1001B59A
dd rva word_1001B5AA
dd rva word_1001B5B6
dd rva word_1001B5C6
dd rva word_1001B5D6
dd rva word_1001B5E8
dd rva word_1001B5FE
dd rva word_1001B610
dd rva word_1001B61C
dd rva word_1001B62A
dd rva word_1001B63A
dd rva word_1001B64A
dd rva word_1001B65A
dd rva word_1001B668
dd rva word_1001B67A
dd rva word_1001B68C
dd rva word_1001B6A0
dd rva word_1001B6B4
dd rva word_1001B6C2
dd rva word_1001B6D4
dd rva word_1001B6E8
dd rva word_1001B6F6
dd rva word_1001B714
dd rva word_1001B724
dd rva word_1001B736
dd rva word_1001B746
dd rva word_1001B754
dd rva word_1001B760
dd rva word_1001B776
dd rva word_1001B784
dd rva word_1001B798
dd rva word_1001B7A8
dd rva word_1001B7BE
dd rva word_1001B7D2
dd rva word_1001B7DE
dd rva word_1001B7EE
dd rva word_1001B800
dd rva word_1001B812
dd rva word_1001B81E
dd rva word_1001B82E
dd rva word_1001B83E
dd rva word_1001B84A
dd rva word_1001B85C
dd rva word_1001B86E
dd rva word_1001B87A
dd rva word_1001B888
dd rva word_1001B8AA
dd rva word_1001B896
dd rva word_1001B89E
dd rva word_1001BB02
dd rva word_1001BAE8
dd rva word_1001BADC
dd rva word_1001BACE
dd rva word_1001BABC
dd rva word_1001BAAC
dd rva word_1001BA9A
dd rva word_1001BA8E
dd rva word_1001BA82
dd rva word_1001BA74
dd rva word_1001BA5E
dd rva word_1001BA4E
dd rva word_1001BA3E
dd rva word_1001BA2C
dd rva word_1001BA1C
dd rva word_1001BA10
dd rva word_1001B9FE
dd rva word_1001B9E8
dd rva word_1001B9D8
dd rva word_1001B9CE
dd rva word_1001B9B8
dd rva word_1001B9A8
dd rva word_1001B996
dd rva word_1001B984
dd rva word_1001B972
dd 0
;
; Import names for WINSPOOL.DRV
;
off_1001B33C dd	rva word_1001BCC0
dd rva word_1001BCAA
dd rva word_1001BC9A
dd 0
word_1001B34C dw 5
db 'HidD_GetHidGuid',0
word_1001B35E dw 1
db 'HidD_FreePreparsedData',0
align 4
word_1001B378 dw 12h
db 'HidP_GetCaps',0
align 4
word_1001B388 dw 0Ah
db 'HidD_GetPreparsedData',0
word_1001B3A0 dw 2
db 'HidD_GetAttributes',0
align 2
word_1001B3B6 dw 0Fh
db 'HidD_SetFeature',0
word_1001B3C8 dw 4
db 'HidD_GetFeature',0
aHid_dll db 'HID.DLL',0
word_1001B3E2 dw 13Ah
db 'SetupDiDestroyDeviceInfoList',0
align 2
word_1001B402 dw 15Ch
db 'SetupDiGetDeviceInterfaceDetailA',0
align 2
word_1001B426 dw 13Eh
db 'SetupDiEnumDeviceInterfaces',0
word_1001B444 dw 14Ah
db 'SetupDiGetClassDevsA',0
align 4
aSetupapi_dll db 'SETUPAPI.dll',0
align 2
word_1001B46A dw 1Eh
db 'CloseHandle',0
word_1001B478 dw 34h
db 'CreateEventA',0
align 4
word_1001B488 dw 38h
db 'CreateFileA',0
word_1001B496 dw 131h
db 'GetLastError',0
align 2
word_1001B4A6 dw 17h
db 'CancelIo',0
align 2
word_1001B4B2 dw 301h
db 'WaitForSingleObject',0
word_1001B4C8 dw 241h
db 'ReadFile',0
align 4
word_1001B4D4 dw 193h
db 'GetVersionExA',0
word_1001B4E4 dw 1CDh
db 'InterlockedExchange',0
word_1001B4FA dw 0CDh
db 'GetACP',0
align 4
word_1001B504 dw 134h
db 'GetLocaleInfoA',0
align 2
word_1001B516 dw 185h
db 'GetThreadLocale',0
word_1001B528 dw 192h
db 'GetVersion',0
align 2
word_1001B536 dw 206h
db 'MultiByteToWideChar',0
word_1001B54C dw 305h
db 'WideCharToMultiByte',0
word_1001B562 dw 330h
db 'lstrcmpiA',0
word_1001B56E dw 339h
db 'lstrlenA',0
align 2
aKernel32_dll db 'KERNEL32.dll',0
align 4
word_1001B588 dw 1E5h
db 'PostQuitMessage',0
word_1001B59A dw 1E3h
db 'PostMessageA',0
align 2
word_1001B5AA dw 22Ah
db 'SetCursor',0
word_1001B5B6 dw 218h
db 'SendMessageA',0
align 2
word_1001B5C6 dw 0B9h
db 'EnableWindow',0
align 2
word_1001B5D6 dw 194h
db 'IsWindowEnabled',0
word_1001B5E8 dw 11Ch
db 'GetLastActivePopup',0
align 2
word_1001B5FE dw 15Ah
db 'GetWindowLongA',0
align 10h
word_1001B610 dw 138h
db 'GetParent',0
word_1001B61C dw 1C3h
db 'MessageBoxA',0
word_1001B62A dw 2A0h
db 'ValidateRect',0
align 2
word_1001B63A dw 0FFh
db 'GetCursorPos',0
align 2
word_1001B64A dw 1E1h
db 'PeekMessageA',0
align 2
word_1001B65A dw 115h
db 'GetKeyState',0
word_1001B668 dw 196h
db 'IsWindowVisible',0
word_1001B67A dw 0DFh
db 'GetActiveWindow',0
word_1001B68C dw 97h
db 'DispatchMessageA',0
align 10h
word_1001B6A0 dw 287h
db 'TranslateMessage',0
align 4
word_1001B6B4 dw 12Dh
db 'GetMessageA',0
word_1001B6C2 dw 15h
db 'CallNextHookEx',0
align 4
word_1001B6D4 dw 267h
db 'SetWindowsHookExA',0
word_1001B6E8 dw 19Ch
db 'LoadBitmapA',0
word_1001B6F6 dw 121h
db 'GetMenuCheckMarkDimensions',0
align 4
word_1001B714 dw 34h
db 'CheckMenuItem',0
word_1001B724 dw 0B7h
db 'EnableMenuItem',0
align 2
word_1001B736 dw 12Ah
db 'GetMenuState',0
align 2
word_1001B746 dw 1C9h
db 'ModifyMenuA',0
word_1001B754 dw 10Ah
db 'GetFocus',0
align 10h
word_1001B760 dw 23Eh
db 'SetMenuItemBitmaps',0
align 2
word_1001B776 dw 145h
db 'GetSubMenu',0
align 4
word_1001B784 dw 125h
db 'GetMenuItemCount',0
align 4
word_1001B798 dw 126h
db 'GetMenuItemID',0
word_1001B7A8 dw 28Bh
db 'UnhookWindowsHookEx',0
word_1001B7BE dw 290h
db 'UnregisterClassA',0
align 2
word_1001B7D2 dw 2B3h
db 'wsprintfA',0
word_1001B7DE dw 0F0h
db 'GetClassNameA',0
word_1001B7EE dw 263h
db 'SetWindowTextA',0
align 10h
word_1001B800 dw 162h
db 'GetWindowTextA',0
align 2
word_1001B812 dw 1EEh
db 'PtInRect',0
align 2
word_1001B81E dw 160h
db 'GetWindowRect',0
word_1001B82E dw 104h
db 'GetDlgCtrlID',0
align 2
word_1001B83E dw 156h
db 'GetWindow',0
word_1001B84A dw 3Bh
db 'ClientToScreen',0
align 4
word_1001B85C dw 278h
db 'TabbedTextOutA',0
align 2
word_1001B86E dw 0B1h
db 'DrawTextA',0
word_1001B87A dw 0B2h
db 'DrawTextExA',0
word_1001B888 dw 168h
db 'GrayStringA',0
word_1001B896 dw 100h
db 'GetDC',0
word_1001B89E dw 207h
db 'ReleaseDC',0
word_1001B8AA dw 146h
db 'GetSysColor',0
word_1001B8B8 dw 147h
db 'GetSysColorBrush',0
align 4
word_1001B8CC dw 149h
db 'GetSystemMetrics',0
align 10h
word_1001B8E0 dw 19Eh
db 'LoadCursorA',0
word_1001B8EE dw 105h
db 'GetDlgItem',0
align 4
word_1001B8FC dw 25Dh
db 'SetWindowLongA',0
align 2
word_1001B90E dw 26Fh
db 'ShowWindow',0
align 4
word_1001B91C dw 260h
db 'SetWindowPos',0
align 4
word_1001B92C dw 45h
db 'CopyRect',0
align 4
word_1001B938 dw 15Fh
db 'GetWindowPlacement',0
align 2
word_1001B94E dw 190h
db 'IsIconic',0
align 2
word_1001B95A dw 276h
db 'SystemParametersInfoA',0
word_1001B972 dw 16h
db 'CallWindowProcA',0
word_1001B984 dw 86h
db 'DefWindowProcA',0
align 2
word_1001B996 dw 1F6h
db 'RegisterClassA',0
align 4
word_1001B9A8 dw 0EAh
db 'GetClassInfoA',0
word_1001B9B8 dw 2
db 'AdjustWindowRectEx',0
align 2
word_1001B9CE dw 11Fh
db 'GetMenu',0
word_1001B9D8 dw 0F3h
db 'GetClientRect',0
word_1001B9E8 dw 234h
db 'SetForegroundWindow',0
word_1001B9FE dw 1BEh
db 'MapWindowPoints',0
word_1001BA10 dw 1A2h
db 'LoadIconA',0
word_1001BA1C dw 12Fh
db 'GetMessagePos',0
word_1001BA2C dw 130h
db 'GetMessageTime',0
align 2
word_1001BA3E dw 90h
db 'DestroyWindow',0
word_1001BA4E dw 14Fh
db 'GetTopWindow',0
align 2
word_1001BA5E dw 10Bh
db 'GetForegroundWindow',0
word_1001BA74 dw 209h
db 'RemovePropA',0
word_1001BA82 dw 13Dh
db 'GetPropA',0
align 2
word_1001BA8E dw 247h
db 'SetPropA',0
align 2
word_1001BA9A dw 0EBh
db 'GetClassInfoExA',0
word_1001BAAC dw 0EEh
db 'GetClassLongA',0
word_1001BABC dw 5Ah
db 'CreateWindowExA',0
word_1001BACE dw 0E7h
db 'GetCapture',0
align 4
word_1001BADC dw 2ADh
db 'WinHelpA',0
align 4
word_1001BAE8 dw 204h
db 'RegisterWindowMessageA',0
align 2
word_1001BB02 dw 8Fh
db 'DestroyMenu',0
aUser32_dll db 'USER32.dll',0
align 4
word_1001BB1C dw 25h
db 'CreateBitmap',0
align 4
word_1001BB2C dw 12Dh
db 'GetDeviceCaps',0
word_1001BB3C dw 54h
db 'DeleteObject',0
align 4
word_1001BB4C dw 1C7h
db 'SaveDC',0
align 2
word_1001BB56 dw 1C0h
db 'RestoreDC',0
word_1001BB62 dw 1D4h
db 'SetBkColor',0
align 10h
word_1001BB70 dw 1FAh
db 'SetTextColor',0
align 10h
word_1001BB80 dw 1E9h
db 'SetMapMode',0
align 2
word_1001BB8E dw 122h
db 'GetClipBox',0
align 4
word_1001BB9C dw 1B1h
db 'PtVisible',0
word_1001BBA8 dw 1B5h
db 'RectVisible',0
word_1001BBB6 dw 20Ch
db 'TextOutA',0
align 2
word_1001BBC2 dw 0A2h
db 'ExtTextOutA',0
word_1001BBD0 dw 99h
db 'Escape',0
align 2
word_1001BBDA dw 1CEh
db 'SelectObject',0
align 2
word_1001BBEA dw 1FDh
db 'SetViewportOrgEx',0
align 2
word_1001BBFE dw 195h
db 'OffsetViewportOrgEx',0
word_1001BC14 dw 1FCh
db 'SetViewportExtEx',0
align 4
word_1001BC28 dw 1C8h
db 'ScaleViewportExtEx',0
align 2
word_1001BC3E dw 200h
db 'SetWindowExtEx',0
align 10h
word_1001BC50 dw 1C9h
db 'ScaleWindowExtEx',0
align 4
word_1001BC64 dw 51h
db 'DeleteDC',0
align 10h
word_1001BC70 dw 167h
db 'GetStockObject',0
align 2
aGdi32_dll db 'GDI32.dll',0
aComdlg32_dll db 'comdlg32.dll',0
align 2
word_1001BC9A dw 1Bh
db 'ClosePrinter',0
align 2
word_1001BCAA dw 46h
db 'DocumentPropertiesA',0
word_1001BCC0 dw 7Ch
db 'OpenPrinterA',0
align 10h
aWinspool_drv db 'WINSPOOL.DRV',0
align 2
word_1001BCDE dw 18Bh
db 'RegCloseKey',0
word_1001BCEC dw 1AEh
db 'RegQueryValueExA',0
align 10h
word_1001BD00 dw 1A4h
db 'RegOpenKeyExA',0
word_1001BD10 dw 192h
db 'RegDeleteKeyA',0
word_1001BD20 dw 197h
db 'RegEnumKeyA',0
word_1001BD2E dw 1A3h
db 'RegOpenKeyA',0
word_1001BD3C dw 1ADh
db 'RegQueryValueA',0
align 2
word_1001BD4E dw 18Fh
db 'RegCreateKeyExA',0
word_1001BD60 dw 1B9h
db 'RegSetValueExA',0
align 2
aAdvapi32_dll db 'ADVAPI32.dll',0
align 10h
aShell32_dll db	'SHELL32.dll',0
aComctl32_dll db 'COMCTL32.dll',0
align 2
word_1001BD9A dw 27h
db 'PathFindExtensionA',0
align 10h
word_1001BDB0 dw 29h
db 'PathFindFileNameA',0
aShlwapi_dll db	'SHLWAPI.dll',0
aOle32_dll db 'ole32.dll',0
aOleaut32_dll db 'OLEAUT32.dll',0
align 4
word_1001BDE8 dw 1E3h
db 'LoadLibraryA',0
align 4
word_1001BDF8 dw 333h
db 'lstrcpyA',0
align 4
word_1001BE04 dw 7Eh
db 'EnumResourceLanguagesA',0
align 2
word_1001BE1E dw 29h
db 'ConvertDefaultLocale',0
align 2
word_1001BE36 dw 157h
db 'GetProcAddress',0
align 4
word_1001BE48 dw 13Eh
db 'GetModuleHandleA',0
align 4
word_1001BE5C dw 13Ch
db 'GetModuleFileNameA',0
align 2
word_1001BE72 dw 32Dh
db 'lstrcmpA',0
align 2
word_1001BE7E dw 1A2h
db 'GlobalDeleteAtom',0
align 2
word_1001BE92 dw 0C7h
db 'FreeLibrary',0
word_1001BEA0 dw 1A0h
db 'GlobalAlloc',0
word_1001BEAE dw 1ABh
db 'GlobalLock',0
align 4
word_1001BEBC dw 110h
db 'GetCurrentThreadId',0
align 2
word_1001BED2 dw 10Fh
db 'GetCurrentThread',0
align 2
word_1001BEE6 dw 2C6h
db 'SizeofResource',0
align 4
word_1001BEF8 dw 1F6h
db 'LockResource',0
align 4
word_1001BF08 dw 1E8h
db 'LoadResource',0
align 4
word_1001BF18 dw 0B6h
db 'FindResourceA',0
word_1001BF28 dw 19Eh
db 'GlobalAddAtomA',0
align 2
word_1001BF3A dw 1EDh
db 'LocalFree',0
word_1001BF46 dw 336h
db 'lstrcpynA',0
word_1001BF52 dw 0C2h
db 'FormatMessageA',0
align 4
word_1001BF64 dw 1B2h
db 'GlobalUnlock',0
align 4
word_1001BF74 dw 1A7h
db 'GlobalFree',0
align 2
word_1001BF82 dw 2A0h
db 'SetLastError',0
align 2
word_1001BF92 dw 1E9h
db 'LocalAlloc',0
align 10h
word_1001BFA0 dw 1E2h
db 'LeaveCriticalSection',0
align 4
word_1001BFB8 dw 1AEh
db 'GlobalReAlloc',0
word_1001BFC8 dw 1AAh
db 'GlobalHandle',0
align 4
word_1001BFD8 dw 73h
db 'EnterCriticalSection',0
align 10h
word_1001BFF0 dw 2D6h
db 'TlsGetValue',0
word_1001BFFE dw 1C9h
db 'InitializeCriticalSection',0
word_1001C01A dw 2D4h
db 'TlsAlloc',0
align 2
word_1001C026 dw 2D7h
db 'TlsSetValue',0
word_1001C034 dw 1F0h
db 'LocalReAlloc',0
align 4
word_1001C044 dw 5Eh
db 'DeleteCriticalSection',0
word_1001C05C dw 2D5h
db 'TlsFree',0
word_1001C066 dw 1CCh
db 'InterlockedDecrement',0
align 2
word_1001C07E dw 32Ah
db 'lstrcatA',0
align 2
word_1001C08A dw 293h
db 'SetErrorMode',0
align 2
word_1001C09A dw 317h
db 'WritePrivateProfileStringA',0
align 4
word_1001C0B8 dw 1CFh
db 'InterlockedIncrement',0
align 10h
word_1001C0D0 dw 1A6h
db 'GlobalFlags',0
word_1001C0DE dw 234h
db 'RaiseException',0
align 10h
word_1001C0F0 dw 32Eh
db 'lstrcmpW',0
align 4
word_1001C0FC dw 1A3h
db 'GlobalFindAtomA',0
word_1001C10E dw 1A8h
db 'GlobalGetAtomNameA',0
align 4
word_1001C124 dw 312h
db 'WriteFile',0
word_1001C130 dw 299h
db 'SetFilePointer',0
align 2
word_1001C142 dw 0BDh
db 'FlushFileBuffers',0
align 2
word_1001C156 dw 10Dh
db 'GetCurrentProcess',0
word_1001C16A dw 0D3h
db 'GetCPInfo',0
word_1001C176 dw 14Ah
db 'GetOEMCP',0
align 2
word_1001C182 dw 1BEh
db 'HeapFree',0
align 2
word_1001C18E dw 1B8h
db 'HeapAlloc',0
word_1001C19A dw 90h
db 'ExitProcess',0
word_1001C1A8 dw 25Bh
db 'RtlUnwind',0
word_1001C1B4 dw 2F8h
db 'VirtualProtect',0
align 2
word_1001C1C6 dw 2F2h
db 'VirtualAlloc',0
align 2
word_1001C1D6 dw 176h
db 'GetSystemInfo',0
word_1001C1E6 dw 2FAh
db 'VirtualQuery',0
align 2
word_1001C1F6 dw 0DEh
db 'GetCommandLineA',0
word_1001C208 dw 2CFh
db 'TerminateProcess',0
align 4
word_1001C21C dw 1C2h
db 'HeapSize',0
align 4
word_1001C228 dw 1C1h
db 'HeapReAlloc',0
word_1001C236 dw 1BCh
db 'HeapDestroy',0
word_1001C244 dw 1BAh
db 'HeapCreate',0
align 2
word_1001C252 dw 2F5h
db 'VirtualFree',0
word_1001C260 dw 1D7h
db 'IsBadWritePtr',0
word_1001C270 dw 22Fh
db 'QueryPerformanceCounter',0
word_1001C28A dw 18Ah
db 'GetTickCount',0
align 2
word_1001C29A dw 10Eh
db 'GetCurrentProcessId',0
word_1001C2B0 dw 17Ah
db 'GetSystemTimeAsFileTime',0
word_1001C2CA dw 29Ch
db 'SetHandleCount',0
align 4
word_1001C2DC dw 16Ch
db 'GetStdHandle',0
align 4
word_1001C2EC dw 12Ch
db 'GetFileType',0
word_1001C2FA dw 16Ah
db 'GetStartupInfoA',0
word_1001C30C dw 0C5h
db 'FreeEnvironmentStringsA',0
word_1001C326 dw 11Dh
db 'GetEnvironmentStrings',0
word_1001C33E dw 0C6h
db 'FreeEnvironmentStringsW',0
word_1001C358 dw 11Fh
db 'GetEnvironmentStringsW',0
align 2
word_1001C372 dw 2DFh
db 'UnhandledExceptionFilter',0
align 2
word_1001C38E dw 2BCh
db 'SetUnhandledExceptionFilter',0
word_1001C3AC dw 1E0h
db 'LCMapStringA',0
align 4
word_1001C3BC dw 1E1h
db 'LCMapStringW',0
align 4
word_1001C3CC dw 16Dh
db 'GetStringTypeA',0
align 2
word_1001C3DE dw 170h
db 'GetStringTypeW',0
align 10h
word_1001C3F0 dw 1D4h
db 'IsBadReadPtr',0
align 10h
word_1001C400 dw 1D1h
db 'IsBadCodePtr',0
align 10h
word_1001C410 dw 2ACh
db 'SetStdHandle',0
align 10h
;
; Export directory for sHID.dll
;
dd 0			; Characteristics
dd 4A93F88Eh		; TimeDateStamp: Tue Aug 25 16:43:26 2009
dw 0			; MajorVersion
dw 0			; MinorVersion
dd rva aShid_dll	; Name
dd 1			; Base
dd 16h			; NumberOfFunctions
dd 16h			; NumberOfNames
dd rva off_1001C448	; AddressOfFunctions
dd rva off_1001C4A0	; AddressOfNames
dd rva word_1001C4F8	; AddressOfNameOrdinals
;
; Export Address Table for sHID.dll
;
off_1001C448 dd	rva _sHID_EraseConfigFlash@4, rva _sHID_EraseDataFlash@4 ; sHID_create()
dd rva _sHID_Execute@8,	rva _sHID_Find@16
dd rva _sHID_GetFrame@12, rva _sHID_GetReport@12
dd rva _sHID_GetRevInfo@8, rva _sHID_GetState@8
dd rva _sHID_ReadConfigFlash@16, rva _sHID_ReadDataFlash@16
dd rva _sHID_ReadReg16@12, rva _sHID_ReadReg@12
dd rva _sHID_SetFrame@12, rva _sHID_SetPreamblePattern@8
dd rva _sHID_SetRX@4, rva _sHID_SetState@8
dd rva _sHID_SetTX@4, rva _sHID_WriteConfigFlash@16
dd rva _sHID_WriteDataFlash@16,	rva _sHID_WriteReg@12
dd rva _sHID_create@0, rva _sHID_destroy@4
;
; Export Names Table for sHID.dll
;
off_1001C4A0 dd	rva a_shid_erasecon, rva a_shid_erasedat ; "_sHID_EraseConfigFlash@4"
dd rva a_shid_execute@,	rva a_shid_find@16
dd rva a_shid_getframe,	rva a_shid_getrepor
dd rva a_shid_getrevin,	rva a_shid_getstate
dd rva a_shid_readconf,	rva a_shid_readdata
dd rva a_shid_readreg1,	rva a_shid_readreg@
dd rva a_shid_setframe,	rva a_shid_setpream
dd rva a_shid_setrx@4, rva a_shid_setstate
dd rva a_shid_settx@4, rva a_shid_writecon
dd rva a_shid_writedat,	rva a_shid_writereg
dd rva a_shid_create@0,	rva a_shid_destroy@
;
; Export Ordinals Table	for sHID.dll
;
word_1001C4F8 dw 0, 1, 2, 3, 4,	5, 6, 7, 8, 9, 0Ah, 0Bh
dw 0Ch,	0Dh, 0Eh, 0Fh, 10h, 11h, 12h, 13h
dw 14h,	15h
aShid_dll db 'sHID.dll',0
a_shid_erasecon	db '_sHID_EraseConfigFlash@4',0
a_shid_erasedat	db '_sHID_EraseDataFlash@4',0
a_shid_execute@	db '_sHID_Execute@8',0
a_shid_find@16 db '_sHID_Find@16',0
a_shid_getframe	db '_sHID_GetFrame@12',0
a_shid_getrepor	db '_sHID_GetReport@12',0
a_shid_getrevin	db '_sHID_GetRevInfo@8',0
a_shid_getstate	db '_sHID_GetState@8',0
a_shid_readconf	db '_sHID_ReadConfigFlash@16',0
a_shid_readdata	db '_sHID_ReadDataFlash@16',0
a_shid_readreg1	db '_sHID_ReadReg16@12',0
a_shid_readreg@	db '_sHID_ReadReg@12',0
a_shid_setframe	db '_sHID_SetFrame@12',0
a_shid_setpream	db '_sHID_SetPreamblePattern@8',0
a_shid_setrx@4 db '_sHID_SetRX@4',0
a_shid_setstate	db '_sHID_SetState@8',0
a_shid_settx@4 db '_sHID_SetTX@4',0
a_shid_writecon	db '_sHID_WriteConfigFlash@16',0
a_shid_writedat	db '_sHID_WriteDataFlash@16',0
a_shid_writereg	db '_sHID_WriteReg@12',0
a_shid_create@0	db '_sHID_create@0',0
a_shid_destroy@	db '_sHID_destroy@4',0
align 1000h
_rdata ends

; Section 3. (virtual address 0001D000)
; Virtual size			: 00005014 (  20500.)
; Section size in file		: 00002000 (   8192.)
; Offset to raw	data for section: 0001D000
; Flags	C0000040: Data Readable	Writable
; Alignment	: default

; Segment type:	Pure data
; Segment permissions: Read/Write
_data segment para public 'DATA' use32
assume cs:_data
;org 1001D000h
unk_1001D000 db	   0
db    0
db    0
db    0
dd offset ___security_init_cookie
dd offset sub_100157CD
dd offset sub_100157D9
dd offset sub_1000FC43
dd offset sub_10016A5C
dd offset sub_10016A72
dd offset sub_10016A40
dd offset unknown_libname_41 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_42 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_43 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_46 ; MFC 3.1-10.0 32bit
dd offset unknown_libname_47 ; MFC 3.1-10.0 32bit
dd offset sub_10015BF1
dd offset sub_10012CC0
dd offset sub_10012CCC
dd offset ??__E?wndTop@CWnd@@2V1@B@@YAXXZ ; `dynamic initializer for 'CWnd const CWnd::wndTop''(void)
dd offset ??__E?wndBottom@CWnd@@2V1@B@@YAXXZ ; `dynamic	initializer for	'CWnd const CWnd::wndBottom''(void)
dd offset ??__E?wndTopMost@CWnd@@2V1@B@@YAXXZ ;	`dynamic initializer for 'CWnd const CWnd::wndTopMost''(void)
dd offset ??__E?wndNoTopMost@CWnd@@2V1@B@@YAXXZ	; `dynamic initializer for 'CWnd const CWnd::wndNoTopMost''(void)
dd offset sub_100163DF
dd offset sub_10016406
unk_1001D058 db	   0
db    0
db    0
db    0
unk_1001D05C db	   0
db    0
db    0
db    0
dd offset ___onexitinit
dd offset ___initmbctable
dd offset ___initstdio
dd offset sub_1000A236
unk_1001D070 db	   0
db    0
db    0
db    0
unk_1001D074 db	   0
db    0
db    0
db    0
dd offset ___endstdio
unk_1001D07C db	   0
db    0
db    0
db    0
unk_1001D080 db	   0
db    0
db    0
db    0
dd offset sub_1000A249
unk_1001D088 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; volatile LONG	off_1001D090
off_1001D090 dd	offset ?_AtlGetThreadACPThunk@ATL@@YGIXZ ; ATL::_AtlGetThreadACPThunk(void)
off_1001D094 dd	offset _DllMain@12_0
dword_1001D098 dd 1
off_1001D09C dd	offset aNoplacesbar ; "NoPlacesBar"
db  80h	; €
db    0
db    0
db    0
dd offset aNobackbutton	; "NoBackButton"
db    0
db    1
db    0
db    0
dd offset aNofilemru	; "NoFileMru"
db    0
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001D0BC dd	offset aNoentirenetwor ; "NoEntireNetwork"
db  10h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001D0CC dd	offset aNorun ;	"NoRun"
db    1
db    0
db    0
db    0
dd offset aNodrives	; "NoDrives"
db    2
db    0
db    0
db    0
dd offset aRestrictrun	; "RestrictRun"
db    4
db    0
db    0
db    0
dd offset aNonetconnectdi ; "NoNetConnectDisconnect"
db    8
db    0
db    0
db    0
dd offset aNorecentdocshi ; "NoRecentDocsHistory"
db  20h
db    0
db    0
db    0
dd offset aNoclose	; "NoClose"
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001D104 dd	offset aSoftwareMicros ; "Software\\Microsoft\\Windows\\CurrentVersi"...
dd offset off_1001D0CC
dd offset aSoftwareMicr_1 ; "Software\\Microsoft\\Windows\\CurrentVersi"...
dd offset off_1001D0BC
dd offset aSoftwareMicr_0 ; "Software\\Microsoft\\Windows\\CurrentVersi"...
dd offset off_1001D09C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001D124 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  4Fh	; O
db  62h	; b
db  6Ah	; j
db  65h	; e
db  63h	; c
db  74h	; t
db  40h	; @
db  40h	; @
db    0
db    0
db    0
off_1001D13C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  43h	; C
db  6Dh	; m
db  64h	; d
db  54h	; T
db  61h	; a
db  72h	; r
db  67h	; g
db  65h	; e
db  74h	; t
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D158 dd	offset off_10018878
align 10h
a_?avcwinthread	db '.?AVCWinThread@@',0
align 4
off_1001D174 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  57h	; W
db  69h	; i
db  6Eh	; n
db  41h	; A
db  70h	; p
db  70h	; p
db  40h	; @
db  40h	; @
db    0
db    0
db    0
off_1001D18C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  50h	; P
db  41h	; A
db  56h	; V
db  43h	; C
db  4Dh	; M
db  65h	; e
db  6Dh	; m
db  6Fh	; o
db  72h	; r
db  79h	; y
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
db    0
stru_1001D1AC dq offset	off_10018878  ;	getInfoPtr
db '.PAVCException@@',0 ; Name
align 4
unk_1001D1C8 db	0FFh
db 0FFh
db 0FFh
db 0FFh
unk_1001D1CC db	0FFh
db 0FFh
db 0FFh
db 0FFh
unk_1001D1D0 db	0FFh
db 0FFh
db 0FFh
db 0FFh
off_1001D1D4 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  43h	; C
db  6Dh	; m
db  64h	; d
db  55h	; U
db  49h	; I
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D1EC dd	offset j_unknown_libname_20
off_1001D1F0 dd	offset off_10018878
align 8
a_?avcexception	db '.?AVCException@@',0
align 4
off_1001D20C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  4Fh	; O
db  6Ch	; l
db  65h	; e
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
off_1001D228 dd	offset off_10018878
align 10h
a_pax db '.PAX',0
align 4
off_1001D238 dd	offset off_10018878
align 10h
a_pavcobject@@ db '.PAVCObject@@',0
align 10h
off_1001D250 dd	offset off_10018878
align 8
a_pavcoleexcept	db '.PAVCOleException@@',0
off_1001D26C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  50h	; P
db  41h	; A
db  56h	; V
db  43h	; C
db  53h	; S
db  69h	; i
db  6Dh	; m
db  70h	; p
db  6Ch	; l
db  65h	; e
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
db    0
off_1001D28C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  50h	; P
db  41h	; A
db  56h	; V
db  43h	; C
db  49h	; I
db  6Eh	; n
db  76h	; v
db  61h	; a
db  6Ch	; l
db  69h	; i
db  64h	; d
db  41h	; A
db  72h	; r
db  67h	; g
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
db    0
off_1001D2B0 dd	offset off_10018878
align 8
a_?avcsimpleexc	db '.?AVCSimpleException@@',0
align 10h
off_1001D2D0 dd	offset off_10018878
align 8
a_?avcmemoryexc	db '.?AVCMemoryException@@',0
align 10h
off_1001D2F0 dd	offset off_10018878
align 8
a_?avcnotsuppor	db '.?AVCNotSupportedException@@',0
align 4
off_1001D318 dd	offset off_10018878
align 10h
a_?avcinvalidar	db '.?AVCInvalidArgException@@',0
align 4
off_1001D33C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  4Eh	; N
db  6Fh	; o
db  54h	; T
db  72h	; r
db  61h	; a
db  63h	; c
db  6Bh	; k
db  4Fh	; O
db  62h	; b
db  6Ah	; j
db  65h	; e
db  63h	; c
db  74h	; t
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D35C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  55h	; U
db  43h	; C
db  54h	; T
db  68h	; h
db  72h	; r
db  65h	; e
db  61h	; a
db  64h	; d
db  44h	; D
db  61h	; a
db  74h	; t
db  61h	; a
db  40h	; @
db  40h	; @
db    0
db    0
db    0
off_1001D378 dd	offset off_10018878
align 10h
a_?av_afx_threa	db '.?AV_AFX_THREAD_STATE@@',0
off_1001D398 dd	offset off_10018878
align 10h
a_?avafx_module	db '.?AVAFX_MODULE_STATE@@',0
align 4
off_1001D3B8 dd	offset off_10018878
align 10h
a_?avafx_modu_0	db '.?AVAFX_MODULE_THREAD_STATE@@',0
align 10h
off_1001D3E0 dd	offset off_10018878
align 8
a_?av_afx_base_	db '.?AV_AFX_BASE_MODULE_STATE@@',0
align 4
off_1001D408 dd	offset off_10018878
align 10h
a_?avchandlemap	db '.?AVCHandleMap@@',0
align 4
off_1001D424 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  50h	; P
db  41h	; A
db  56h	; V
db  43h	; C
db  55h	; U
db  73h	; s
db  65h	; e
db  72h	; r
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D444 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  52h	; R
db  65h	; e
db  73h	; s
db  6Fh	; o
db  75h	; u
db  72h	; r
db  63h	; c
db  65h	; e
db  45h	; E
db  78h	; x
db  63h	; c
db  65h	; e
db  70h	; p
db  74h	; t
db  69h	; i
db  6Fh	; o
db  6Eh	; n
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D468 dd	offset off_10018878
align 10h
a_?avcuserexcep	db '.?AVCUserException@@',0
align 4
off_1001D488 dd	offset off_10018878
align 10h
a_?avcgdiobject	db '.?AVCGdiObject@@',0
align 4
off_1001D4A4 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  44h	; D
db  43h	; C
db  40h	; @
db  40h	; @
db    0
db    0
db    0
off_1001D4B8 dd	offset off_10018878
align 10h
a_?auiatlstring	db '.?AUIAtlStringMgr@ATL@@',0
off_1001D4D8 dd	offset off_10018878
align 10h
a_?avcafxstring	db '.?AVCAfxStringMgr@@',0
align 8
dword_1001D4F8 dd 0FFFFEC78h
db  77h	; w
db 0ECh	; ì
db 0FFh
db 0FFh
db  76h	; v
db 0ECh	; ì
db 0FFh
db 0FFh
db  75h	; u
db 0ECh	; ì
db 0FFh
db 0FFh
db  74h	; t
db 0ECh	; ì
db 0FFh
db 0FFh
db  73h	; s
db 0ECh	; ì
db 0FFh
db 0FFh
db  72h	; r
db 0ECh	; ì
db 0FFh
db 0FFh
db  71h	; q
db 0ECh	; ì
db 0FFh
db 0FFh
db  70h	; p
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Fh	; o
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Eh	; n
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Dh	; m
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Ch	; l
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Bh	; k
db 0ECh	; ì
db 0FFh
db 0FFh
db  6Ah	; j
db 0ECh	; ì
db 0FFh
db 0FFh
db  69h	; i
db 0ECh	; ì
db 0FFh
db 0FFh
db  68h	; h
db 0ECh	; ì
db 0FFh
db 0FFh
db  67h	; g
db 0ECh	; ì
db 0FFh
db 0FFh
db  66h	; f
db 0ECh	; ì
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
off_1001D548 dd	offset aAccparent ; "accParent"
dd offset aAccchildcount ; "accChildCount"
dd offset aAccchild	; "accChild"
dd offset aAccname	; "accName"
dd offset aAccvalue	; "accValue"
dd offset aAccdescription ; "accDescription"
dd offset aAccrole	; "accRole"
dd offset aAccstate	; "accState"
dd offset aAcchelp	; "accHelp"
dd offset aAcchelptopic	; "accHelpTopic"
dd offset aAcckeyboardsho ; "accKeyboardShortcut"
dd offset aAccfocus	; "accFocus"
dd offset aAccselection	; "accSelection"
dd offset aAccdefaultacti ; "accDefaultAction"
dd offset aAccselect	; "accSelect"
dd offset aAcclocation	; "accLocation"
dd offset aAccnavigate	; "accNavigate"
dd offset aAcchittest	; "accHitTest"
dd offset aAccdodefaultac ; "accDoDefaultAction"
off_1001D594 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  58h	; X
db  41h	; A
db  63h	; c
db  63h	; c
db  65h	; e
db  73h	; s
db  73h	; s
db  69h	; i
db  62h	; b
db  6Ch	; l
db  65h	; e
db  40h	; @
db  43h	; C
db  57h	; W
db  6Eh	; n
db  64h	; d
db  40h	; @
db  40h	; @
db    0
db    0
off_1001D5B4 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  58h	; X
db  41h	; A
db  63h	; c
db  63h	; c
db  65h	; e
db  73h	; s
db  73h	; s
db  69h	; i
db  62h	; b
db  6Ch	; l
db  65h	; e
db  53h	; S
db  65h	; e
db  72h	; r
db  76h	; v
db  65h	; e
db  72h	; r
db  40h	; @
db  43h	; C
db  57h	; W
db  6Eh	; n
db  64h	; d
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D5DC dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  57h	; W
db  6Eh	; n
db  64h	; d
db  40h	; @
db  40h	; @
db    0
db    0
off_1001D5F0 dd	offset off_10018878
align 8
a_?av_afx_htmlh	db '.?AV_AFX_HTMLHELP_STATE@@',0
align 4
off_1001D614 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  54h	; T
db  65h	; e
db  73h	; s
db  74h	; t
db  43h	; C
db  6Dh	; m
db  64h	; d
db  55h	; U
db  49h	; I
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D630 dd	offset off_10018878
align 8
a_?auiaccessibl	db '.?AUIAccessibleProxy@@',0
align 10h
off_1001D650 dd	offset off_10018878
align 8
a_?auiunknown@@	db '.?AUIUnknown@@',0
align 4
off_1001D668 dd	offset off_10018878
align 10h
a_?auidispatch@	db '.?AUIDispatch@@',0
off_1001D680 dd	offset off_10018878
align 8
a_?auiaccessi_0	db '.?AUIAccessible@@',0
align 10h
off_1001D6A0 dd	offset off_10018878
align 8
a_?av?Iaccessib	db '.?AV?$IAccessibleProxyImpl@VCAccess'
db 'ibleProxy@ATL@@@ATL@@',0
align 4
off_1001D6E4 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  55h	; U
db  49h	; I
db  4Fh	; O
db  6Ch	; l
db  65h	; e
db  57h	; W
db  69h	; i
db  6Eh	; n
db  64h	; d
db  6Fh	; o
db  77h	; w
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
off_1001D700 dd	offset off_10018878
align 8
a_?avccomobject	db '.?AVCComObjectRootBase@ATL@@',0
align 4
off_1001D728 dd	offset off_10018878
align 10h
a_?av?Ccomobjec	db '.?AV?$CComObjectRootEx@VCComSingleT'
db 'hreadModel@ATL@@@ATL@@',0
align 4
off_1001D76C dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  41h	; A
db  63h	; c
db  63h	; c
db  65h	; e
db  73h	; s
db  73h	; s
db  69h	; i
db  62h	; b
db  6Ch	; l
db  65h	; e
db  50h	; P
db  72h	; r
db  6Fh	; o
db  78h	; x
db  79h	; y
db  40h	; @
db  41h	; A
db  54h	; T
db  4Ch	; L
db  40h	; @
db  40h	; @
db    0
db    0
off_1001D790 dd	offset off_10018878
align 8
a_?av?Cmfccomob	db '.?AV?$CMFCComObject@VCAccessiblePro'
db 'xy@ATL@@@@',0
align 4
off_1001D7C8 dd	offset off_10018878
align 10h
a_?avcmapptrtop	db '.?AVCMapPtrToPtr@@',0
align 4
off_1001D7E4 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  4Dh	; M
db  65h	; e
db  6Eh	; n
db  75h	; u
db  40h	; @
db  40h	; @
db    0
off_1001D7F8 dd	offset off_10018878
align 10h
a_pavcarchiveex	db '.PAVCArchiveException@@',0
off_1001D818 dd	offset off_10018878
align 10h
a_?avcarchiveex	db '.?AVCArchiveException@@',0
; struct CRuntimeClass off_1001D838
off_1001D838 dd	offset aCbytearray ; "CByteArray"
db  14h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset sub_100163F0
dd offset off_10017D5C
align 10h
dd offset unk_10020710
off_1001D854 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  43h	; C
db  42h	; B
db  79h	; y
db  74h	; t
db  65h	; e
db  41h	; A
db  72h	; r
db  72h	; r
db  61h	; a
db  79h	; y
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
dword_1001D870 dd 0BB40E64Eh
unk_1001D874 db	 20h
db    5
db  93h	; “
db  19h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001D890 dd	offset __exit
off_1001D894 dd	offset off_10018878
db    0
db    0
db    0
db    0
db  2Eh	; .
db  3Fh	; ?
db  41h	; A
db  56h	; V
db  74h	; t
db  79h	; y
db  70h	; p
db  65h	; e
db  5Fh	; _
db  69h	; i
db  6Eh	; n
db  66h	; f
db  6Fh	; o
db  40h	; @
db  40h	; @
db    0
db    0
db    0
db    0
db    0
dd offset ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z	; __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *)
align 8
byte_1001D8B8 db 1
db    2
db    4
db    8
db    0
db    0
db    0
db    0
dword_1001D8C0 dd 3A4h
aVyv db	'`‚y‚!',0
align 10h
aJ db '¦ß',0
align 8
aBe db '¡¥',0
align 10h
db  81h	; 
db  9Fh	; Ÿ
db 0E0h	; à
db 0FCh	; ü
db    0
db    0
db    0
db    0
db  40h	; @
db  7Eh	; ~
db  80h	; €
db 0FCh	; ü
db    0
db    0
db    0
db    0
db 0A8h	; ¨
db    3
db    0
db    0
db 0C1h	; Á
db 0A3h	; £
db 0DAh	; Ú
db 0A3h	; £
db  20h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  81h	; 
db 0FEh	; þ
db    0
db    0
db    0
db    0
db    0
db    0
db  40h	; @
db 0FEh	; þ
db    0
db    0
db    0
db    0
db    0
db    0
db 0B5h	; µ
db    3
db    0
db    0
db 0C1h	; Á
db 0A3h	; £
db 0DAh	; Ú
db 0A3h	; £
db  20h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  81h	; 
db 0FEh	; þ
db    0
db    0
db    0
db    0
db    0
db    0
db  41h	; A
db 0FEh	; þ
db    0
db    0
db    0
db    0
db    0
db    0
db 0B6h	; ¶
db    3
db    0
db    0
db 0CFh	; Ï
db 0A2h	; ¢
db 0E4h	; ä
db 0A2h	; ¢
db  1Ah
db    0
db 0E5h	; å
db 0A2h	; ¢
db 0E8h	; è
db 0A2h	; ¢
db  5Bh	; [
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  81h	; 
db 0FEh	; þ
db    0
db    0
db    0
db    0
db    0
db    0
db  40h	; @
db  7Eh	; ~
db 0A1h	; ¡
db 0FEh	; þ
db    0
db    0
db    0
db    0
db  51h	; Q
db    5
db    0
db    0
db  51h	; Q
db 0DAh	; Ú
db  5Eh	; ^
db 0DAh	; Ú
db  20h
db    0
db  5Fh	; _
db 0DAh	; Ú
db  6Ah	; j
db 0DAh	; Ú
db  32h	; 2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  81h	; 
db 0D3h	; Ó
db 0D8h	; Ø
db 0DEh	; Þ
db 0E0h	; à
db 0F9h	; ù
db    0
db    0
db  31h	; 1
db  7Eh	; ~
db  81h	; 
db 0FEh	; þ
db    0
db    0
db    0
db    0
dword_1001D9B0 dd 1
dword_1001D9B4 dd 16h
db    2
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    3
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    4
db    0
db    0
db    0
db  18h
db    0
db    0
db    0
db    5
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db    6
db    0
db    0
db    0
db    9
db    0
db    0
db    0
db    7
db    0
db    0
db    0
db  0Ch
db    0
db    0
db    0
db    8
db    0
db    0
db    0
db  0Ch
db    0
db    0
db    0
db    9
db    0
db    0
db    0
db  0Ch
db    0
db    0
db    0
db  0Ah
db    0
db    0
db    0
db    7
db    0
db    0
db    0
db  0Bh
db    0
db    0
db    0
db    8
db    0
db    0
db    0
db  0Ch
db    0
db    0
db    0
db  16h
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  16h
db    0
db    0
db    0
db  0Fh
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  11h
db    0
db    0
db    0
db  12h
db    0
db    0
db    0
db  12h
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db  21h	; !
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  35h	; 5
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db  41h	; A
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  43h	; C
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db  50h	; P
db    0
db    0
db    0
db  11h
db    0
db    0
db    0
db  52h	; R
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  53h	; S
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  57h	; W
db    0
db    0
db    0
db  16h
db    0
db    0
db    0
db  59h	; Y
db    0
db    0
db    0
db  0Bh
db    0
db    0
db    0
db  6Ch	; l
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  6Dh	; m
db    0
db    0
db    0
db  20h
db    0
db    0
db    0
db  70h	; p
db    0
db    0
db    0
db  1Ch
db    0
db    0
db    0
db  72h	; r
db    0
db    0
db    0
db    9
db    0
db    0
db    0
db    6
db    0
db    0
db    0
db  16h
db    0
db    0
db    0
db  80h	; €
db    0
db    0
db    0
db  0Ah
db    0
db    0
db    0
db  81h	; 
db    0
db    0
db    0
db  0Ah
db    0
db    0
db    0
db  82h	; ‚
db    0
db    0
db    0
db    9
db    0
db    0
db    0
db  83h	; ƒ
db    0
db    0
db    0
db  16h
db    0
db    0
db    0
db  84h	; „
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db  91h	; ‘
db    0
db    0
db    0
db  29h	; )
db    0
db    0
db    0
db  9Eh	; ž
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db 0A1h	; ¡
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db 0A4h	; ¤
db    0
db    0
db    0
db  0Bh
db    0
db    0
db    0
db 0A7h	; §
db    0
db    0
db    0
db  0Dh
db    0
db    0
db    0
db 0B7h	; ·
db    0
db    0
db    0
db  11h
db    0
db    0
db    0
db 0CEh	; Î
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db 0D7h	; ×
db    0
db    0
db    0
db  0Bh
db    0
db    0
db    0
db  18h
db    7
db    0
db    0
db  0Ch
db    0
db    0
db    0
db  75h	; u
db  98h	; ˜
db    0
db    0
db  73h	; s
db  98h	; ˜
db    0
db    0
off_1001DB20 dd	offset __fpmath
dd offset nullsub_2
dd offset nullsub_2
align 10h
db  10h
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; LPCRITICAL_SECTION lpCriticalSection
lpCriticalSection dd 0
dword_1001DB3C dd 1
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001DC58 dd	offset ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z ; __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *)
dword_1001DC5C dd 0FFFFFFFFh
; int (*off_1001DC60)(void)
off_1001DC60 dd	offset ?terminate@@YAXXZ ; terminate(void)
align 10h
unk_1001DC70 db	0FFh
db 0FFh
db 0FFh
db 0FFh
db  80h	; €
db  0Ah
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001DC98 db	   5
db    0
db    0
db 0C0h	; À
db  0Bh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  1Dh
db    0
db    0
db 0C0h	; À
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  96h	; –
db    0
db    0
db 0C0h	; À
db    4
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  8Dh	; 
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  8Eh	; Ž
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  8Fh	; 
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  90h	; 
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  91h	; ‘
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  92h	; ’
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  93h	; “
db    0
db    0
db 0C0h	; À
db    8
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dword_1001DD10 dd 3
dword_1001DD14 dd 7
db  78h	; x
db    0
db    0
db    0
dword_1001DD1C dd 0Ah
dword_1001DD20 dd 2
off_1001DD24 dd	offset aR6002FloatingP ; "R6002\r\n- floating point not	loaded\r\n"
db    8
db    0
db    0
db    0
dd offset aR6008NotEnough ; "R6008\r\n-	not enough space for arguments"...
db    9
db    0
db    0
db    0
dd offset aR6009NotEnough ; "R6009\r\n-	not enough space for environme"...
db  0Ah
db    0
db    0
db    0
dd offset aThisApplicatio ; "\r\nThis application has requested	the Ru"...
db  10h
db    0
db    0
db    0
dd offset aR6016NotEnough ; "R6016\r\n-	not enough space for thread da"...
db  11h
db    0
db    0
db    0
dd offset aR6017Unexpecte ; "R6017\r\n-	unexpected multithread lock er"...
db  12h
db    0
db    0
db    0
dd offset aR6018Unexpecte ; "R6018\r\n-	unexpected heap	error\r\n"
db  13h
db    0
db    0
db    0
dd offset aR6019UnableToO ; "R6019\r\n-	unable to open console device\r"...
db  18h
db    0
db    0
db    0
dd offset aR6024NotEnough ; "R6024\r\n-	not enough space for _onexit/a"...
db  19h
db    0
db    0
db    0
dd offset aR6025PureVirtu ; "R6025\r\n-	pure virtual function call\r\n"
db  1Ah
db    0
db    0
db    0
dd offset aR6026NotEnough ; "R6026\r\n-	not enough space for stdio ini"...
db  1Bh
db    0
db    0
db    0
dd offset aR6027NotEnough ; "R6027\r\n-	not enough space for lowio ini"...
db  1Ch
db    0
db    0
db    0
dd offset aR6028UnableToI ; "R6028\r\n-	unable to initialize heap\r\n"
db  1Dh
db    0
db    0
db    0
dd offset aR6029ThisAppli ; "R6029\r\n-	This application cannot	run us"...
db  78h	; x
db    0
db    0
db    0
dd offset aDomainError	; "DOMAIN error\r\n"
db  79h	; y
db    0
db    0
db    0
dd offset aSingError	; "SING	error\r\n"
db  7Ah	; z
db    0
db    0
db    0
dd offset aTlossError	; "TLOSS error\r\n"
db 0FCh	; ü
db    0
db    0
db    0
dd offset asc_10018BFC	; "\r\n"
db 0FFh
db    0
db    0
db    0
dd offset aRuntimeError	; "runtime error "
off_1001DDB8 dd	offset aNull ; "(null)"
off_1001DDBC dd	offset aNull_0 ; "(null)"
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  43h	; C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001DDD0 db	   1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset off_1001E3EC
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset asc_10019448	; "	    (((((		   H"
dd offset off_1001E330
db    0
db    0
db    0
db    0
off_1001DE24 dd	offset unk_1001DDD0
db    0
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  43h	; C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  43h	; C
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001DF60 dd	offset __fptrap
off_1001DF64 dd	offset __fptrap
off_1001DF68 dd	offset __fptrap
off_1001DF6C dd	offset __fptrap
off_1001DF70 dd	offset __fptrap
off_1001DF74 dd	offset __fptrap
db  80h	; €
db  70h	; p
db    0
db    0
db    1
db    0
db    0
db    0
db 0F0h	; ð
db 0F1h	; ñ
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
unk_1001DF88 db	 50h ; P
db  53h	; S
db  54h	; T
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001DFC8 db	 50h ; P
db  44h	; D
db  54h	; T
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dd offset unk_1001DF88
dd offset unk_1001DFC8
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db  1Eh
db    0
db    0
db    0
db  3Bh	; ;
db    0
db    0
db    0
db  5Ah	; Z
db    0
db    0
db    0
db  78h	; x
db    0
db    0
db    0
db  97h	; —
db    0
db    0
db    0
db 0B5h	; µ
db    0
db    0
db    0
db 0D4h	; Ô
db    0
db    0
db    0
db 0F3h	; ó
db    0
db    0
db    0
db  11h
db    1
db    0
db    0
db  30h	; 0
db    1
db    0
db    0
db  4Eh	; N
db    1
db    0
db    0
db  6Dh	; m
db    1
db    0
db    0
db 0FFh
db 0FFh
db 0FFh
db 0FFh
db  1Eh
db    0
db    0
db    0
db  3Ah	; :
db    0
db    0
db    0
db  59h	; Y
db    0
db    0
db    0
db  77h	; w
db    0
db    0
db    0
db  96h	; –
db    0
db    0
db    0
db 0B4h	; ´
db    0
db    0
db    0
db 0D3h	; Ó
db    0
db    0
db    0
db 0F2h	; ò
db    0
db    0
db    0
db  10h
db    1
db    0
db    0
db  2Fh	; /
db    1
db    0
db    0
db  4Dh	; M
db    1
db    0
db    0
db  6Ch	; l
db    1
db    0
db    0
off_1001E090 dd	offset unk_10020C80
align 8
dd offset unk_10020C80
db    1
db    1
db    0
db    0
unk_1001E0A0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  10h
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E0B0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E0D0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    2
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E100 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E2F0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
off_1001E310 dd	offset asc_10019448 ; "		(((((		       H"
dd offset unk_1001964A
align 10h
; size_t dword_1001E320
dword_1001E320 dd 1
byte_1001E324 db 2Eh
align 4
db    1
db    0
db    0
db    0
dd offset off_1001E330
off_1001E330 dd	offset aSun ; "Sun"
dd offset aMon		; "Mon"
dd offset aTue		; "Tue"
dd offset aWed		; "Wed"
dd offset aThu		; "Thu"
dd offset aFri		; "Fri"
dd offset aSat		; "Sat"
dd offset aSunday	; "Sunday"
dd offset aMonday	; "Monday"
dd offset aTuesday	; "Tuesday"
dd offset aWednesday	; "Wednesday"
dd offset aThursday	; "Thursday"
dd offset aFriday	; "Friday"
dd offset aSaturday	; "Saturday"
dd offset aJan		; "Jan"
dd offset aFeb		; "Feb"
dd offset aMar		; "Mar"
dd offset aApr		; "Apr"
dd offset aMay		; "May"
dd offset aJun		; "Jun"
dd offset aJul		; "Jul"
dd offset aAug		; "Aug"
dd offset aSep		; "Sep"
dd offset aOct		; "Oct"
dd offset aNov		; "Nov"
dd offset aDec		; "Dec"
dd offset aJanuary	; "January"
dd offset aFebruary	; "February"
dd offset aMarch	; "March"
dd offset aApril	; "April"
dd offset aMay		; "May"
dd offset aJune		; "June"
dd offset aJuly		; "July"
dd offset aAugust	; "August"
dd offset aSeptember	; "September"
dd offset aOctober	; "October"
dd offset aNovember	; "November"
dd offset aDecember	; "December"
dd offset aAm		; "AM"
dd offset aPm		; "PM"
dd offset aMmDdYy	; "MM/dd/yy"
dd offset aDdddMmmmDdYyyy ; "dddd, MMMM	dd, yyyy"
dd offset aHhMmSs	; "HH:mm:ss"
db    9
db    4
db    0
db    0
db    1
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E3E8 db	 2Eh ; .
db    0
db    0
db    0
off_1001E3EC dd	offset unk_1001E3E8
off_1001E3F0 dd	offset unk_10020B9C
off_1001E3F4 dd	offset unk_10020B9C
off_1001E3F8 dd	offset unk_10020B9C
off_1001E3FC dd	offset unk_10020B9C
off_1001E400 dd	offset unk_10020B9C
off_1001E404 dd	offset unk_10020B9C
off_1001E408 dd	offset unk_10020B9C
off_1001E40C dd	offset unk_10020B9C
off_1001E410 dd	offset unk_10020B9C
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
db  7Fh	; 
off_1001E41C dd	offset off_1001E3EC
unk_1001E420 db	   0
db    4
db    0
db    0
db    1
db 0FCh	; ü
db 0FFh
db 0FFh
db  35h	; 5
db    0
db    0
db    0
db  0Bh
db    0
db    0
db    0
db  40h	; @
db    0
db    0
db    0
db 0FFh
db    3
db    0
db    0
unk_1001E438 db	 80h ; €
db    0
db    0
db    0
db  81h	; 
db 0FFh
db 0FFh
db 0FFh
db  18h
db    0
db    0
db    0
db    8
db    0
db    0
db    0
db  20h
db    0
db    0
db    0
db  7Fh	; 
db    0
db    0
db    0
unk_1001E450 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0A0h	;  
db    2
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0C8h	; È
db    5
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db 0FAh	; ú
db    8
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  40h	; @
db  9Ch	; œ
db  0Ch
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  50h	; P
db 0C3h	; Ã
db  0Fh
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  24h	; $
db 0F4h	; ô
db  12h
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  80h	; €
db  96h	; –
db  98h	; ˜
db  16h
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  20h
db 0BCh	; ¼
db 0BEh	; ¾
db  19h
db  40h	; @
db    0
db    0
db    0
db    0
db    0
db    4
db 0BFh	; ¿
db 0C9h	; É
db  1Bh
db  8Eh	; Ž
db  34h	; 4
db  40h	; @
db    0
db    0
db    0
db 0A1h	; ¡
db 0EDh	; í
db 0CCh	; Ì
db 0CEh	; Î
db  1Bh
db 0C2h	; Â
db 0D3h	; Ó
db  4Eh	; N
db  40h	; @
db  20h
db 0F0h	; ð
db  9Eh	; ž
db 0B5h	; µ
db  70h	; p
db  2Bh	; +
db 0A8h	; ¨
db 0ADh	; ­
db 0C5h	; Å
db  9Dh	; 
db  69h	; i
db  40h	; @
db 0D0h	; Ð
db  5Dh	; ]
db 0FDh	; ý
db  25h	; %
db 0E5h	; å
db  1Ah
db  8Eh	; Ž
db  4Fh	; O
db  19h
db 0EBh	; ë
db  83h	; ƒ
db  40h	; @
db  71h	; q
db  96h	; –
db 0D7h	; ×
db  95h	; •
db  43h	; C
db  0Eh
db    5
db  8Dh	; 
db  29h	; )
db 0AFh	; ¯
db  9Eh	; ž
db  40h	; @
db 0F9h	; ù
db 0BFh	; ¿
db 0A0h	;  
db  44h	; D
db 0EDh	; í
db  81h	; 
db  12h
db  8Fh	; 
db  81h	; 
db  82h	; ‚
db 0B9h	; ¹
db  40h	; @
db 0BFh	; ¿
db  3Ch	; <
db 0D5h	; Õ
db 0A6h	; ¦
db 0CFh	; Ï
db 0FFh
db  49h	; I
db  1Fh
db  78h	; x
db 0C2h	; Â
db 0D3h	; Ó
db  40h	; @
db  6Fh	; o
db 0C6h	; Æ
db 0E0h	; à
db  8Ch	; Œ
db 0E9h	; é
db  80h	; €
db 0C9h	; É
db  47h	; G
db 0BAh	; º
db  93h	; “
db 0A8h	; ¨
db  41h	; A
db 0BCh	; ¼
db  85h	; …
db  6Bh	; k
db  55h	; U
db  27h	; '
db  39h	; 9
db  8Dh	; 
db 0F7h	; ÷
db  70h	; p
db 0E0h	; à
db  7Ch	; |
db  42h	; B
db 0BCh	; ¼
db 0DDh	; Ý
db  8Eh	; Ž
db 0DEh	; Þ
db 0F9h	; ù
db  9Dh	; 
db 0FBh	; û
db 0EBh	; ë
db  7Eh	; ~
db 0AAh	; ª
db  51h	; Q
db  43h	; C
db 0A1h	; ¡
db 0E6h	; æ
db  76h	; v
db 0E3h	; ã
db 0CCh	; Ì
db 0F2h	; ò
db  29h	; )
db  2Fh	; /
db  84h	; „
db  81h	; 
db  26h	; &
db  44h	; D
db  28h	; (
db  10h
db  17h
db 0AAh	; ª
db 0F8h	; ø
db 0AEh	; ®
db  10h
db 0E3h	; ã
db 0C5h	; Å
db 0C4h	; Ä
db 0FAh	; ú
db  44h	; D
db 0EBh	; ë
db 0A7h	; §
db 0D4h	; Ô
db 0F3h	; ó
db 0F7h	; ÷
db 0EBh	; ë
db 0E1h	; á
db  4Ah	; J
db  7Ah	; z
db  95h	; •
db 0CFh	; Ï
db  45h	; E
db  65h	; e
db 0CCh	; Ì
db 0C7h	; Ç
db  91h	; ‘
db  0Eh
db 0A6h	; ¦
db 0AEh	; ®
db 0A0h	;  
db  19h
db 0E3h	; ã
db 0A3h	; £
db  46h	; F
db  0Dh
db  65h	; e
db  17h
db  0Ch
db  75h	; u
db  81h	; 
db  86h	; †
db  75h	; u
db  76h	; v
db 0C9h	; É
db  48h	; H
db  4Dh	; M
db  58h	; X
db  42h	; B
db 0E4h	; ä
db 0A7h	; §
db  93h	; “
db  39h	; 9
db  3Bh	; ;
db  35h	; 5
db 0B8h	; ¸
db 0B2h	; ²
db 0EDh	; í
db  53h	; S
db  4Dh	; M
db 0A7h	; §
db 0E5h	; å
db  5Dh	; ]
db  3Dh	; =
db 0C5h	; Å
db  5Dh	; ]
db  3Bh	; ;
db  8Bh	; ‹
db  9Eh	; ž
db  92h	; ’
db  5Ah	; Z
db 0FFh
db  5Dh	; ]
db 0A6h	; ¦
db 0F0h	; ð
db 0A1h	; ¡
db  20h
db 0C0h	; À
db  54h	; T
db 0A5h	; ¥
db  8Ch	; Œ
db  37h	; 7
db  61h	; a
db 0D1h	; Ñ
db 0FDh	; ý
db  8Bh	; ‹
db  5Ah	; Z
db  8Bh	; ‹
db 0D8h	; Ø
db  25h	; %
db  5Dh	; ]
db  89h	; ‰
db 0F9h	; ù
db 0DBh	; Û
db  67h	; g
db 0AAh	; ª
db  95h	; •
db 0F8h	; ø
db 0F3h	; ó
db  27h	; '
db 0BFh	; ¿
db 0A2h	; ¢
db 0C8h	; È
db  5Dh	; ]
db 0DDh	; Ý
db  80h	; €
db  6Eh	; n
db  4Ch	; L
db 0C9h	; É
db  9Bh	; ›
db  97h	; —
db  20h
db  8Ah	; Š
db    2
db  52h	; R
db  60h	; `
db 0C4h	; Ä
db  25h	; %
db  75h	; u
db    0
db    0
db    0
db    0
unk_1001E5B0 db	0CDh ; Í
db 0CCh	; Ì
db 0CDh	; Í
db 0CCh	; Ì
db 0CCh	; Ì
db 0CCh	; Ì
db 0CCh	; Ì
db 0CCh	; Ì
db 0CCh	; Ì
db 0CCh	; Ì
db 0FBh	; û
db  3Fh	; ?
db  71h	; q
db  3Dh	; =
db  0Ah
db 0D7h	; ×
db 0A3h	; £
db  70h	; p
db  3Dh	; =
db  0Ah
db 0D7h	; ×
db 0A3h	; £
db 0F8h	; ø
db  3Fh	; ?
db  5Ah	; Z
db  64h	; d
db  3Bh	; ;
db 0DFh	; ß
db  4Fh	; O
db  8Dh	; 
db  97h	; —
db  6Eh	; n
db  12h
db  83h	; ƒ
db 0F5h	; õ
db  3Fh	; ?
db 0C3h	; Ã
db 0D3h	; Ó
db  2Ch	; ,
db  65h	; e
db  19h
db 0E2h	; â
db  58h	; X
db  17h
db 0B7h	; ·
db 0D1h	; Ñ
db 0F1h	; ñ
db  3Fh	; ?
db 0D0h	; Ð
db  0Fh
db  23h	; #
db  84h	; „
db  47h	; G
db  1Bh
db  47h	; G
db 0ACh	; ¬
db 0C5h	; Å
db 0A7h	; §
db 0EEh	; î
db  3Fh	; ?
db  40h	; @
db 0A6h	; ¦
db 0B6h	; ¶
db  69h	; i
db  6Ch	; l
db 0AFh	; ¯
db    5
db 0BDh	; ½
db  37h	; 7
db  86h	; †
db 0EBh	; ë
db  3Fh	; ?
db  33h	; 3
db  3Dh	; =
db 0BCh	; ¼
db  42h	; B
db  7Ah	; z
db 0E5h	; å
db 0D5h	; Õ
db  94h	; ”
db 0BFh	; ¿
db 0D6h	; Ö
db 0E7h	; ç
db  3Fh	; ?
db 0C2h	; Â
db 0FDh	; ý
db 0FDh	; ý
db 0CEh	; Î
db  61h	; a
db  84h	; „
db  11h
db  77h	; w
db 0CCh	; Ì
db 0ABh	; «
db 0E4h	; ä
db  3Fh	; ?
db  2Fh	; /
db  4Ch	; L
db  5Bh	; [
db 0E1h	; á
db  4Dh	; M
db 0C4h	; Ä
db 0BEh	; ¾
db  94h	; ”
db  95h	; •
db 0E6h	; æ
db 0C9h	; É
db  3Fh	; ?
db  92h	; ’
db 0C4h	; Ä
db  53h	; S
db  3Bh	; ;
db  75h	; u
db  44h	; D
db 0CDh	; Í
db  14h
db 0BEh	; ¾
db  9Ah	; š
db 0AFh	; ¯
db  3Fh	; ?
db 0DEh	; Þ
db  67h	; g
db 0BAh	; º
db  94h	; ”
db  39h	; 9
db  45h	; E
db 0ADh	; ­
db  1Eh
db 0B1h	; ±
db 0CFh	; Ï
db  94h	; ”
db  3Fh	; ?
db  24h	; $
db  23h	; #
db 0C6h	; Æ
db 0E2h	; â
db 0BCh	; ¼
db 0BAh	; º
db  3Bh	; ;
db  31h	; 1
db  61h	; a
db  8Bh	; ‹
db  7Ah	; z
db  3Fh	; ?
db  61h	; a
db  55h	; U
db  59h	; Y
db 0C1h	; Á
db  7Eh	; ~
db 0B1h	; ±
db  53h	; S
db  7Ch	; |
db  12h
db 0BBh	; »
db  5Fh	; _
db  3Fh	; ?
db 0D7h	; ×
db 0EEh	; î
db  2Fh	; /
db  8Dh	; 
db    6
db 0BEh	; ¾
db  92h	; ’
db  85h	; …
db  15h
db 0FBh	; û
db  44h	; D
db  3Fh	; ?
db  24h	; $
db  3Fh	; ?
db 0A5h	; ¥
db 0E9h	; é
db  39h	; 9
db 0A5h	; ¥
db  27h	; '
db 0EAh	; ê
db  7Fh	; 
db 0A8h	; ¨
db  2Ah	; *
db  3Fh	; ?
db  7Dh	; }
db 0ACh	; ¬
db 0A1h	; ¡
db 0E4h	; ä
db 0BCh	; ¼
db  64h	; d
db  7Ch	; |
db  46h	; F
db 0D0h	; Ð
db 0DDh	; Ý
db  55h	; U
db  3Eh	; >
db  63h	; c
db  7Bh	; {
db    6
db 0CCh	; Ì
db  23h	; #
db  54h	; T
db  77h	; w
db  83h	; ƒ
db 0FFh
db  91h	; ‘
db  81h	; 
db  3Dh	; =
db  91h	; ‘
db 0FAh	; ú
db  3Ah	; :
db  19h
db  7Ah	; z
db  63h	; c
db  25h	; %
db  43h	; C
db  31h	; 1
db 0C0h	; À
db 0ACh	; ¬
db  3Ch	; <
db  21h	; !
db  89h	; ‰
db 0D1h	; Ñ
db  38h	; 8
db  82h	; ‚
db  47h	; G
db  97h	; —
db 0B8h	; ¸
db    0
db 0FDh	; ý
db 0D7h	; ×
db  3Bh	; ;
db 0DCh	; Ü
db  88h	; ˆ
db  58h	; X
db    8
db  1Bh
db 0B1h	; ±
db 0E8h	; è
db 0E3h	; ã
db  86h	; †
db 0A6h	; ¦
db    3
db  3Bh	; ;
db 0C6h	; Æ
db  84h	; „
db  45h	; E
db  42h	; B
db    7
db 0B6h	; ¶
db  99h	; ™
db  75h	; u
db  37h	; 7
db 0DBh	; Û
db  2Eh	; .
db  3Ah	; :
db  33h	; 3
db  71h	; q
db  1Ch
db 0D2h	; Ò
db  23h	; #
db 0DBh	; Û
db  32h	; 2
db 0EEh	; î
db  49h	; I
db  90h	; 
db  5Ah	; Z
db  39h	; 9
db 0A6h	; ¦
db  87h	; ‡
db 0BEh	; ¾
db 0C0h	; À
db  57h	; W
db 0DAh	; Ú
db 0A5h	; ¥
db  82h	; ‚
db 0A6h	; ¦
db 0A2h	; ¢
db 0B5h	; µ
db  32h	; 2
db 0E2h	; â
db  68h	; h
db 0B2h	; ²
db  11h
db 0A7h	; §
db  52h	; R
db  9Fh	; Ÿ
db  44h	; D
db  59h	; Y
db 0B7h	; ·
db  10h
db  2Ch	; ,
db  25h	; %
db  49h	; I
db 0E4h	; ä
db  2Dh	; -
db  36h	; 6
db  34h	; 4
db  4Fh	; O
db  53h	; S
db 0AEh	; ®
db 0CEh	; Î
db  6Bh	; k
db  25h	; %
db  8Fh	; 
db  59h	; Y
db    4
db 0A4h	; ¤
db 0C0h	; À
db 0DEh	; Þ
db 0C2h	; Â
db  7Dh	; }
db 0FBh	; û
db 0E8h	; è
db 0C6h	; Æ
db  1Eh
db  9Eh	; ž
db 0E7h	; ç
db  88h	; ˆ
db  5Ah	; Z
db  57h	; W
db  91h	; ‘
db  3Ch	; <
db 0BFh	; ¿
db  50h	; P
db  83h	; ƒ
db  22h	; "
db  18h
db  4Eh	; N
db  4Bh	; K
db  65h	; e
db  62h	; b
db 0FDh	; ý
db  83h	; ƒ
db  8Fh	; 
db 0AFh	; ¯
db    6
db  94h	; ”
db  7Dh	; }
db  11h
db 0E4h	; ä
db  2Dh	; -
db 0DEh	; Þ
db  9Fh	; Ÿ
db 0CEh	; Î
db 0D2h	; Ò
db 0C8h	; È
db    4
db 0DDh	; Ý
db 0A6h	; ¦
db 0D8h	; Ø
db  0Ah
_data ends

;
; Delayed imports from OLEACC.dll
;

; Segment type:	Externs
; _idata
; LRESULT __stdcall LresultFromObject(const IID	*const riid, WPARAM wParam, LPUNKNOWN punk)
extrn __imp_LresultFromObject:dword
; HRESULT __stdcall CreateStdAccessibleObject(HWND hwnd, LONG idObject,	const IID *const riid, void **ppvObject)
extrn __imp_CreateStdAccessibleObject:dword


; Segment type:	Pure data
; Segment permissions: Read/Write
_data segment para public 'DATA' use32
assume cs:_data
;org 1001E714h
align 10h
unk_1001E720 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
byte_1001E7C0 db 0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
byte_1001E7CC db 0
align 10h
dword_1001E7D0 dd 0
dword_1001E7D4 dd 0
unk_1001E7D8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E870 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E908 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dword_1001E9A0 dd 0
dword_1001E9A4 dd 0
unk_1001E9A8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001E9E0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; struct _RTL_CRITICAL_SECTION CriticalSection
CriticalSection	_RTL_CRITICAL_SECTION <0>
align 10h
; struct _RTL_CRITICAL_SECTION stru_1001EA40
stru_1001EA40 _RTL_CRITICAL_SECTION <0>
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dword_1001EBD8 dd 0
unk_1001EBDC db	   0
db    0
db    0
db    0
unk_1001EBE0 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001EBE8 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001EC80 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_1001ED18 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
dword_1001ED30 dd 0
dword_1001ED34 dd 0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
; HCURSOR hCursor
hCursor	dd 0
dword_1001ED70 dd 0
align 10h
; HBITMAP hBitmapChecked
hBitmapChecked dd 0
align 8
dword_1001ED88 dd 0
align 10h
unk_1001ED90 db	   0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020590 dd ?
dword_10020594 dd ?
dword_10020598 dd ?
dword_1002059C dd ?
dword_100205A0 dd ?
dword_100205A4 dd ?
dword_100205A8 dd ?
dword_100205AC dd ?
dword_100205B0 dd ?
dword_100205B4 dd ?
dword_100205B8 dd ?
align 10h
unk_100205C0 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
unk_10020610 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
unk_10020660 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
unk_100206B0 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
word_10020700 dw ?
align 4
unk_10020704 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_1002070C dd ?
unk_10020710 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_1002072C dd ?
; void *dword_10020730
dword_10020730 dd ?
align 8
dword_10020738 dd ?
dword_1002073C dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020744 dd ?
dword_10020748 dd ?
dword_1002074C dd ?
dword_10020750 dd ?
dword_10020754 dd ?
dword_10020758 dd ?
dword_1002075C dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; void *dword_10020764
dword_10020764 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020774 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
byte_1002077C db ?
align 10h
dword_10020780 dd ?
dword_10020784 dd ?
dword_10020788 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020794 dd ?
unk_10020798 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_100208E8 dd ?
; int dword_100208EC
dword_100208EC dd ?
dword_100208F0 dd ?
dword_100208F4 dd ?
dword_100208F8 dd ?
dword_100208FC dd ?
dword_10020900 dd ?
align 8
dword_10020908 dd ?
unk_1002090C db	   ? ;
db    ?	;
db    ?	;
db    ?	;
dword_10020910 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; volatile LONG	Target
Target dd ?
align 8
; char Filename[260]
Filename db 104h dup(?)
byte_10020A5C db ?
align 10h
dword_10020A60 dd ?
dword_10020A64 dd ?
; LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
lpTopLevelExceptionFilter dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020A74 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020A84 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020A8C dd ?
dword_10020A90 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020B80 dd ?
dword_10020B84 dd ?
dword_10020B88 dd ?
dword_10020B8C dd ?
dword_10020B90 dd ?
dword_10020B94 dd ?
dword_10020B98 dd ?
unk_10020B9C db	   ? ;
db    ?	;
db    ?	;
db    ?	;
dword_10020BA0 dd ?
dword_10020BA4 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10020BF0 dd ?
dword_10020BF4 dd ?
dword_10020BF8 dd ?
dword_10020BFC dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
unk_10020C18 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; volatile LONG	dword_10020C20
dword_10020C20 dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
OLEACC_dll_handle dd ?
dword_10020C58 dd ?
; int (__stdcall *dword_10020C5C)(_DWORD, _DWORD)
dword_10020C5C dd ?
; int (__stdcall *dword_10020C60)(_DWORD, _DWORD)
dword_10020C60 dd ?
dword_10020C64 dd ?
dword_10020C68 dd ?
dword_10020C6C dd ?
dword_10020C70 dd ?
align 10h
unk_10020C80 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; size_t dword_10021C80
dword_10021C80 dd ?
; UINT uNumber
uNumber	dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10021CA0 dd ?
unk_10021CA4 db	   ? ;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; void *dword_10021DA0
dword_10021DA0 dd ?
dword_10021DA4 dd ?
; LPVOID lpMem
lpMem dd ?
dword_10021DAC dd ?
dword_10021DB0 dd ?
dword_10021DB4 dd ?
dword_10021DB8 dd ?
; HANDLE hHeap
hHeap dd ?
dword_10021DC0 dd ?
; LCID Locale
Locale dd ?
; void *dword_10021DC8
dword_10021DC8 dd ?
dword_10021DCC dd ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
byte_10021DE0 db ?
byte_10021DE1 db ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
; UINT CodePage
CodePage dd ?
align 10h
word_10021EF0 dw ?
align 10h
byte_10021F00 db ?
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
db    ?	;
dword_10022000 dd ?
dword_10022004 dd ?
; void *dword_10022008
dword_10022008 dd ?
dword_1002200C dd ?
dword_10022010 dd ?
align 1000h
_data ends


end DllEntryPoint
