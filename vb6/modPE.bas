Attribute VB_Name = "modPE"
Option Explicit

'2018 - 2022
'Author SERBice
'
'Basado en documentacion de Microsoft (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

'El presente codigo da informacion sobre archivos binarios/ejecutables de Microsoft (COFF, MZ, MZ PE, etc)
'Por favor, si este codigo le ha servido hagamelo saber.
'Si porta este codigo a otro lenguaje por favor publiquelo para que otros puedan utilizarlo.



'Modo de uso:
' Llamar a la funcion ReadPE, los parametros serán:
    ' path (String): Ruta del archivo a analizar
    ' info (ver tipo PE_Info)(variable por referencia, puntero)

'La funcion devolvera true (exitoso) o false (error/problema)
'adicionalmente en la variable info se obtendra el detalle del archivo
'Al final de este modulo hay una muestra de implementacion.
    

Public Enum ImageSignatureTypes
    IMAGE_DOS_SIGNATURE = &H5A4D     ''\\ MZ
    IMAGE_OS2_SIGNATURE = &H454E     ''\\ NE
    IMAGE_OS2_SIGNATURE_LE = &H454C  ''\\ LE
    IMAGE_VXD_SIGNATURE = &H454C     ''\\ LE
    IMAGE_NT_SIGNATURE = &H4550      ''\\ PE00
End Enum

Public Enum ImageSubsystem
    IMAGE_SUBSYSTEM_UNKNOWN = 0                     'An unknown subsystem
    'IMAGE_SUBSYSTEM_NATIVE = 1                      'Device drivers and native Windows processes
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2                 'The Windows graphical user interface (GUI) subsystem
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3                 'The Windows character subsystem
    IMAGE_SUBSYSTEM_OS2_CUI = 5                     'The OS/2 character subsystem
    IMAGE_SUBSYSTEM_POSIX_CUI = 7                   'The Posix character subsystem
    'IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8              'Native Win9x driver
    'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9              'Windows CE
    'IMAGE_SUBSYSTEM_EFI_APPLICATION = 10            'An Extensible Firmware Interface (EFI) application
    'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11    'An EFI driver with boot services
    'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12         'An EFI driver with run-time services
    'IMAGE_SUBSYSTEM_EFI_ROM = 13                    'An EFI ROM image
    'IMAGE_SUBSYSTEM_XBOX = 14                       'XBOX
    'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16   'Windows boot application.
End Enum

Public Type IMAGE_DOS_HEADER
    e_magic As Integer   ''\\ Magic number
    e_cblp As Integer    ''\\ Bytes on last page of file
    e_cp As Integer      ''\\ Pages in file
    e_crlc As Integer    ''\\ Relocations
    e_cparhdr As Integer ''\\ Size of header in paragraphs
    e_minalloc As Integer ''\\ Minimum extra paragraphs needed
    e_maxalloc As Integer ''\\ Maximum extra paragraphs needed
    e_ss As Integer    ''\\ Initial (relative) SS value
    e_sp As Integer    ''\\ Initial SP value
    e_csum As Integer  ''\\ Checksum
    e_ip As Integer  ''\\ Initial IP value
    e_cs As Integer  ''\\ Initial (relative) CS value
    e_lfarlc As Integer ''\\ File address of relocation table
    e_ovno As Integer ''\\ Overlay number
    e_res(0 To 3) As Integer ''\\ Reserved words
    e_oemid As Integer ''\\ OEM identifier (for e_oeminfo)
    e_oeminfo As Integer ''\\ OEM information; e_oemid specific
    e_res2(0 To 9) As Integer ''\\ Reserved words
    e_lfanew As Long ''\\ File address of new exe header
End Type



Public Enum ImageMachineTypes

    IMAGE_FILE_MACHINE_UNKNOWN = &H0    '\\ The contents of this field are assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_I386 = &H14C   ''\\ Intel 386.
    'IMAGE_FILE_MACHINE_AM33 = &H1D3 'Matsushita AM33
    IMAGE_FILE_MACHINE_AMD64 = &H8664 'x86-64 (AMD)
    'IMAGE_FILE_MACHINE_ARM = &H1C0 'ARM little endian
    'IMAGE_FILE_MACHINE_ARM64 = &HAA64 'ARM64 little endian
    'IMAGE_FILE_MACHINE_ARMNT = &H1C4 'ARM Thumb-2 little endian
    'IMAGE_FILE_MACHINE_EBC = &HEBC 'EFI byte code
    IMAGE_FILE_MACHINE_IA64 = &H200 'Intel Itanium processor family
    'IMAGE_FILE_MACHINE_M32R = &H9041 'Mitsubishi M32R little endian
    'IMAGE_FILE_MACHINE_MIPS16 = &H266 'MIPS16
    'IMAGE_FILE_MACHINE_MIPSFPU = &H366 'MIPS with FPU
    'IMAGE_FILE_MACHINE_MIPSFPU16 = &H466 'MIPS16 with FPU
    'IMAGE_FILE_MACHINE_POWERPC = &H1F0 'Power PC little endian
    'IMAGE_FILE_MACHINE_POWERPCFP = &H1F1 'Power PC with floating point support
    'IMAGE_FILE_MACHINE_R4000 = &H166 'MIPS little endian
    'IMAGE_FILE_MACHINE_RISCV32 = &H5032 'RISC-V 32-bit address space
    'IMAGE_FILE_MACHINE_RISCV64 = &H5064 'RISC-V 64-bit address space
    'IMAGE_FILE_MACHINE_RISCV128 = &H5128 'RISC-V 128-bit address space
    'IMAGE_FILE_MACHINE_SH3 = &H1A2 'Hitachi SH3
    'IMAGE_FILE_MACHINE_SH3DSP = &H1A3 'Hitachi SH3 DSP
    'IMAGE_FILE_MACHINE_SH4 = &H1A6 'Hitachi SH4
    'IMAGE_FILE_MACHINE_SH5 = &H1A8 'Hitachi SH5
    'IMAGE_FILE_MACHINE_THUMB = &H1C2 'Thumb
    'IMAGE_FILE_MACHINE_WCEMIPSV2 = &H169 'MIPS little-endian WCE v2
    'IMAGE_FILE_MACHINE_R3000 = &H162  ''\\ MIPS little-endian,= &H160 big-endian
    'IMAGE_FILE_MACHINE_R10000 = &H168  ''\\ MIPS little-endian
    'IMAGE_FILE_MACHINE_ALPHA = &H184      ''\\ Alpha_AXP
    'IMAGE_FILE_MACHINE_SH3E = &H1A4  ''\\ SH3E little-endian
    'IMAGE_FILE_MACHINE_80486 = &H14D   ''\\ Intel 486.
    'IMAGE_FILE_MACHINE_80586 = &H14E   ''\\ Intel 586.
    
    'No es oficial, es para usar en caso de que sea uno de los tipos comentados,
    'entonces se usa este tag con propositos generales. los tag no comentados son
    'los que usaremos como validos
    IMAGE_FILE_MACHINE_OTHER = &HF9F
    
End Enum

Private Type IMAGE_FILE_HEADER
    Machine As Integer
    NumberOfSections As Integer
    TimeDateStamp As Long
    PointerToSymbolTable As Long
    NumberOfSymbols As Long
    SizeOfOptionalHeader As Integer
    Characteristics As Integer
End Type



Public Type IMAGE_OPTIONAL_NE
    e_magic As Integer   ''\\ Magic number
    e_linker_ver As Byte
    e_linker_rev As Byte
    e_offset As Integer
    e_length As Integer
    e_rvd1 As Long
    
    e_contents As Integer
    e_atm_data_segment As Integer
    e_initial_szheap As Integer
    e_initial_szstack As Integer
    e_segment_offset_CSIP As Long
    e_segment_offset_SSSP As Long       '18H
    e_entries_segment As Integer
    e_entries_module As Integer '1Eh
    e_entries_tbl_name As Integer '20h
    
    e_offset_win_relative_segment  As Integer '22h
    
    e_offset_win_relative_res  As Integer '24h
    
    e_offset_win_relative_name  As Integer '26h
    
    e_offset_win_relative_ref  As Integer '28h
    e_offset_win_relative_imported  As Integer '2Ah
    
    e_offset_win_relative_nonresident  As Long '2ch
    e_movable As Integer '30h
    e_logical_align As Integer '32h
    e_n_res_segment As Integer '34h
    e_subsystem As Byte             '36h
    e_subsystem_aditional As Byte
    e_ewin_offset_sectors_fast As Integer
    e_win_reserved As Integer
    e_lfarlc As Integer
    e_expected_winver As Byte
    
End Type
  
Private Type IMAGE_OPTIONAL_HEADER
    Magic As Integer
    MajorLinkerVersion As Byte
    MinorLinkerVersion As Byte
    SizeOfCode As Long
    SizeOfInitializedData As Long
    SizeOfUninitializedData As Long
    AddressOfEntryPoint As Long
    BaseOfCode As Long
End Type

Private Type IMAGE_OPTIONAL_HEADER_x86
    BaseOfData As Long
End Type


Private Type IMAGE_DATA_DIRECTORY
    VirtualAddress As Long
    Size As Long
End Type


Private Type IMAGE_OPTIONAL_HEADER_NT_PE
    ImageBase As Long
    SectionAlignment As Long
    FileAlignment As Long
    MajorOperatingSystemVersion As Integer
    MinorOperatingSystemVersion As Integer
    MajorImageVersion As Integer
    MinorImageVersion As Integer
    MajorSubsystemVersion As Integer
    MinorSubsystemVersion As Integer
    Win32VersionValue As Long
    SizeOfImage As Long
    SizeOfHeaders As Long
    CheckSum As Long
    Subsystem As Integer
    DllCharacteristics As Integer
    SizeOfStackReserve As Long
    SizeOfStackCommit As Long
    SizeOfHeapReserve As Long
    SizeOfHeapCommit As Long
    LoaderFlags As Long
    NumberOfRvaAndSizes As Long
    DataDirectory(0 To 15) As IMAGE_DATA_DIRECTORY
End Type

Private Type IMAGE_OPTIONAL_HEADER_NT_PE_Plus
    ImageBase As Double
    SectionAlignment As Long
    FileAlignment As Long
    MajorOperatingSystemVersion As Integer
    MinorOperatingSystemVersion As Integer
    MajorImageVersion As Integer
    MinorImageVersion As Integer
    MajorSubsystemVersion As Integer
    MinorSubsystemVersion As Integer
    Win32VersionValue As Long
    SizeOfImage As Long
    SizeOfHeaders As Long
    CheckSum As Long
    Subsystem As Integer
    DllCharacteristics As Integer
    SizeOfStackReserve As Double
    SizeOfStackCommit As Double
    SizeOfHeapReserve As Double
    SizeOfHeapCommit As Double
    LoaderFlags As Long
    NumberOfRvaAndSizes As Long
    DataDirectory(0 To 15) As IMAGE_DATA_DIRECTORY
End Type

Public Enum ImageTypeFlags
    IMAGE_FILE_RELOCS_STRIPPED = &H1      ''\\ Relocation info stripped from file.
    IMAGE_FILE_EXECUTABLE_IMAGE = &H2     ''\\ File is executable  (i.e. no unresolved externel references).
    IMAGE_FILE_LINE_NUMS_STRIPPED = &H4   ''\\ Line nunbers stripped from file.
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = &H8  ''\\ Local symbols stripped from file.
    IMAGE_FILE_AGGRESIVE_WS_TRIM = &H10   ''\\ Agressively trim working set
    IMAGE_FILE_LARGE_ADDRESS_AWARE = &H20 ''\\ App can handle >2gb addresses
    IMAGE_FILE_RESERVED = &H40            ''\\ This flag is reserved for future use.
    IMAGE_FILE_BYTES_REVERSED_LO = &H80   ''\\ Bytes of machine word are reversed.
    IMAGE_FILE_32BIT_MACHINE = &H100      ''\\ 32 bit word machine.
    IMAGE_FILE_DEBUG_STRIPPED = &H200     ''\\ Debugging info stripped from file in .DBG file
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = &H400  ''\\ If Image is on removable media, copy and run from the swap file.
    IMAGE_FILE_NET_RUN_FROM_SWAP = &H800  ''\\ If Image is on Net, copy and run from the swap file.
    IMAGE_FILE_SYSTEM = &H1000            ''\\ System File.
    IMAGE_FILE_DLL = &H2000               ''\\ File is a DLL.
    IMAGE_FILE_UP_SYSTEM_ONLY = &H4000    ''\\ File should only be run on a UP machine
    IMAGE_FILE_BYTES_REVERSED_HI = &H8000 ''\\ Bytes of machine word are reversed.
End Enum




Public Type PE_Info
   
    DOSCOM As Boolean          'Si es un \0e\1f de menos de 64KB
    DOSEXE As Boolean          'Si es un MZ
    WINEXE As Boolean          'Si es un NE
    WINDRV As Boolean          'Si es un LE
    W32EXE As Boolean          'Si es un PE tipo 0x10b
    W64EXE As Boolean          'Si es un PE tipo 0x20b
    
    i386 As Boolean            'Intel x86
    AMD64 As Boolean           'AMD64 (x86-64, Intel/AMD)
    IA64 As Boolean            'Intel IA64
    
    Characteristics As Integer 'Mascara de bits con caracteristicas ImageTypeFlags
    EXECUTABLE As Boolean      'Flag 0x0002
    STRIPPED As Boolean        'Flag 0x0001
    
    CUI As Boolean             'Subsistema de consola (3) o (7)
    GUI As Boolean             'Subsistema de consola: Console (2)
    POSIX As Boolean           'Subsistema de consola POSIX (7)
    OS2 As Boolean             'Subsistema de consola OS2
    
    Errors As Boolean          'Se ha producido uno o más errorres. Proceso abortado
    ErrN As Long
    ErrDsc As String
End Type



Public Function ReadPE(ByVal path As String, ByRef info As PE_Info) As Boolean
    On Error GoTo HandleErr
    
    Dim Stub As IMAGE_DOS_HEADER
    
    Dim HeaderNE As IMAGE_OPTIONAL_NE
                
    Dim fnum As Integer
    Dim Signature As Long
    Dim SignatureShort As Integer
    Dim PE_Head As IMAGE_FILE_HEADER
    Dim OptionalHeader As IMAGE_OPTIONAL_HEADER
    Dim OptionalHeader32bit As IMAGE_OPTIONAL_HEADER_x86
    Dim ImageOptionalHeaderPE As IMAGE_OPTIONAL_HEADER_NT_PE
    Dim ImageOptionalHeaderPE_Plus As IMAGE_OPTIONAL_HEADER_NT_PE_Plus
    
    
    
    info.DOSCOM = False          'Si es un \0e\1f de menos de 64KB
    info.DOSEXE = False          'Si es un MZ
    info.WINEXE = False          'Si es un NE
    info.WINDRV = False          'Si es un LE
    info.W32EXE = False          'Si es un PE tipo 0x10b
    info.W64EXE = False          'Si es un PE tipo 0x20b
    
    info.i386 = False            'Intel x86
    info.AMD64 = False           'AMD64 (x86-64, Intel/AMD)
    info.IA64 = False            'Intel IA64
    
    info.Characteristics = 0     'Mascara de bits con caracteristicas ImageTypeFlags
    info.EXECUTABLE = False      'Flag 0x0002
    info.STRIPPED = False        'Flag 0x0001
    
    info.CUI = False             'Subsistema de consola (3) o (7)
    info.GUI = False             'Subsistema de consola: Console (2)
    info.POSIX = False           'Subsistema de consola POSIX (7)
    
    info.Errors = False          'Se ha producido uno o más errorres. Proceso abortado
    info.ErrN = 0
    info.ErrDsc = ""
    
    'Debug.Print path, Dir(path, vbNormal)
    If Dir(path, vbNormal) = "" Then
        Err.Raise 53, , "File Not Found"
    End If

    'Debug.Print Dir(path, vbNormal)
    fnum = FreeFile
    Open path For Binary As #fnum
        
        If LOF(fnum) < 40 Then
            'ImageSignatureTypes
            Get #fnum, , SignatureShort
            If SignatureShort = ImageSignatureTypes.IMAGE_DOS_SIGNATURE Then
                info.DOSEXE = True
            Else
                info.DOSCOM = True
            End If
            
            'Archivo demasiado pequeño, no es un ejecutable (ni siquiera entran los headers del stub)
            ReadPE = True
            
            Close #fnum
            Exit Function
        End If
        
        'Leer MS-DOS Header (Stub)
        Get #fnum, , Stub
        
        
        'Comprobar si es un EXE tipo "MZ", "MZ" "NE" (Windows 16bits) o "MZ" "PE" (Windows 32bits)
        If Stub.e_magic = ImageSignatureTypes.IMAGE_DOS_SIGNATURE Then
            
            
            If Not Hex(Stub.e_lfarlc) = 40 Then
                'If LOF(fnum) <= Stub.e_lfanew + 5 Then
                    info.DOSEXE = True
                    
                    ReadPE = True
                    Close #fnum
                    Exit Function
            End If
            
            'Ir a la posicion del PE
            Seek #fnum, Stub.e_lfanew + 1
            
            Get #fnum, , SignatureShort
            
            Seek #fnum, Seek(fnum) - 2
            
            Get #fnum, , Signature
            
            
            'Comprobar si es un EXE tipo "MZ" "NE" Windows 16bits y en 3Ch no tiene el valor 40h
            If Hex(Stub.e_lfarlc) = 40 And (SignatureShort = ImageSignatureTypes.IMAGE_OS2_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_OS2_SIGNATURE) And Not (SignatureShort = ImageSignatureTypes.IMAGE_VXD_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_VXD_SIGNATURE) Then
                'NE (IMAGE_OS2_SIGNATURE)
                info.WINEXE = True
                
                Seek #fnum, Seek(fnum) - 4
                
                
                Get #fnum, , HeaderNE

                If HeaderNE.e_subsystem = 2 Then
                    info.GUI = True
                End If
                ReadPE = True
                Close #fnum
                Exit Function
            'Comprobar si es un EXE tipo "MZ" "LE" Windows 16bits y en 3Ch no tiene el valor 40h
            ElseIf Hex(Stub.e_lfarlc) = 40 And Not (SignatureShort = ImageSignatureTypes.IMAGE_OS2_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_OS2_SIGNATURE) And (SignatureShort = ImageSignatureTypes.IMAGE_VXD_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_VXD_SIGNATURE) Then
                'LE (IMAGE_OS2_SIGNATURE)
                info.WINDRV = True
                
                ReadPE = True
                
                Close #fnum
                Exit Function
            'Comprobar si es un EXE tipo "MZ" "PE" Windows 32/64bits y en 3Ch tiene el valor 40h
            ElseIf Hex(Stub.e_lfarlc) = 40 And Not (SignatureShort = ImageSignatureTypes.IMAGE_VXD_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_VXD_SIGNATURE) And Not (SignatureShort = ImageSignatureTypes.IMAGE_OS2_SIGNATURE Or Signature = ImageSignatureTypes.IMAGE_OS2_SIGNATURE) And Signature = ImageSignatureTypes.IMAGE_NT_SIGNATURE Then
                'Es un ejecutable PE Windows 32/64bits
                
                    
                
                Get #fnum, , PE_Head
                            
                'Comprobar el tipo de arquitectura para el que esta compilado
                'Arbitrariamente se eligio permitir sistemas i386, AMD64 (x86-64, Intel/AMD), Intel IA64 y sistemas desconocidos
                If Not PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_I386 And _
                   Not PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_AMD64 And _
                   Not PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_IA64 And _
                   Not PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_UNKNOWN Then
                   
                    ReadPE = False
                    Close #fnum
                    Exit Function
                Else
                    If PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_I386 Then
                        info.i386 = True 'Intel x86
                    ElseIf PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_AMD64 Then
                        info.AMD64 = True 'AMD64 (x86-64, Intel/AMD)
                    ElseIf PE_Head.Machine = ImageMachineTypes.IMAGE_FILE_MACHINE_IA64 Then
                        info.IA64 = True 'Intel IA64
                    End If
                    Debug.Print PE_Head.Machine, Hex(PE_Head.Machine)
                End If
                
                'Mascara de bits con caracteristicas ImageTypeFlags
                info.Characteristics = PE_Head.Characteristics
                
                'Comprobar si es un ejecutable (IMAGE_FILE_EXECUTABLE_IMAGE) o un ejecutable sin reubicaciones (IMAGE_FILE_RELOCS_STRIPPED)
                If (PE_Head.Characteristics And Val(ImageTypeFlags.IMAGE_FILE_EXECUTABLE_IMAGE)) = False And (PE_Head.Characteristics And Val(ImageTypeFlags.IMAGE_FILE_RELOCS_STRIPPED)) = False Then
                    
                    'no es ejecutable
                    ReadPE = False
                    Close #fnum
                    Exit Function
                Else
                    If (PE_Head.Characteristics And Val(ImageTypeFlags.IMAGE_FILE_EXECUTABLE_IMAGE)) Then
                        info.EXECUTABLE = True  'Flag 0x0002
                    ElseIf (PE_Head.Characteristics And Val(ImageTypeFlags.IMAGE_FILE_RELOCS_STRIPPED)) Then
                        info.STRIPPED = True    'Flag 0x0001
                    End If
                End If
                

                'CUI As Boolean             'Subsistema de consola (3), (5) o (7)
                'GUI As Boolean             'Subsistema de consola: Console (2)
                'POSIX As Boolean           'Subsistema de consola POSIX (7)
                'OS2 As Boolean             'Subsistema de consola OS2 (5)
                
                'Obtener mas datos del PE
                Get #fnum, , OptionalHeader
                
                'PE32+ images allow for a 64-bit address space while limiting the image size to 2 gigabytes. Other PE32+ modifications are addressed in their respective sections.
                If OptionalHeader.Magic = &H10B Then
                    'PE32 Format - 32bits
                    info.W32EXE = True
                    Get #fnum, , OptionalHeader32bit
                    Get fnum, , ImageOptionalHeaderPE
                    Debug.Print path
                    Debug.Print ImageOptionalHeaderPE.MajorImageVersion, ImageOptionalHeaderPE.MinorImageVersion
                    Debug.Print ImageOptionalHeaderPE.MajorOperatingSystemVersion, ImageOptionalHeaderPE.MinorOperatingSystemVersion
                    Debug.Print ImageOptionalHeaderPE.MajorImageVersion, ImageOptionalHeaderPE.MinorSubsystemVersion
                    
                    If ImageOptionalHeaderPE.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_WINDOWS_CUI Then
                        info.CUI = True
                    ElseIf ImageOptionalHeaderPE.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_POSIX_CUI Then
                        info.CUI = True
                        info.POSIX = True
                    ElseIf ImageOptionalHeaderPE.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_OS2_CUI Then
                        info.CUI = True
                        info.OS2 = True
                    ElseIf ImageOptionalHeaderPE.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_WINDOWS_GUI Then
                        info.GUI = True
                    End If
                ElseIf OptionalHeader.Magic = &H20B Then
                    'PE32+ Format - 64bits
                    info.W64EXE = True
                    Get fnum, , ImageOptionalHeaderPE_Plus
                    If ImageOptionalHeaderPE_Plus.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_WINDOWS_CUI Then
                        info.CUI = True
                    ElseIf ImageOptionalHeaderPE_Plus.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_POSIX_CUI Then
                        info.CUI = True
                        info.POSIX = True
                    ElseIf ImageOptionalHeaderPE_Plus.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_OS2_CUI Then
                        info.CUI = True
                        info.OS2 = True
                    ElseIf ImageOptionalHeaderPE_Plus.Subsystem = ImageSubsystem.IMAGE_SUBSYSTEM_WINDOWS_GUI Then
                        info.GUI = True
                    End If
                Else
                    'PE Desconocido o corrupto
                    ReadPE = False
                    Close #fnum
                    Exit Function
                End If
                ReadPE = True
            End If
        
        Else
        
            If LOF(fnum) <= 64534 Then
                info.DOSCOM = True
                ReadPE = True
            Else
                ReadPE = False
            End If
        End If
    Close #fnum
    Exit Function
HandleErr:
    ReadPE = False
    info.Errors = True
        
    info.ErrN = Err.Number
    info.ErrDsc = Err.Description
    'Resume Next
End Function

Sub main()
  Dim info As PE_Info

  Dim i As Integer
  Dim path
  Dim mistr As String

  path = Array("c:\tests\test1.exe", _
          "c:\tests\test2.dll", _
          "c:\tests\test3.ocx", _
          "c:\tests\test4.bin", _
          "c:\tests\test5.com")

  For i = 0 To UBound(path)
      mistr = mistr & path(i) & vbCrLf

      Call ReadPE(path(i), info)

      mistr = mistr & vbCrLf

      mistr = mistr & "x86: " & IIf(info.i386, "Si", "No") & vbCrLf
      mistr = mistr & "x86-64: " & IIf(info.AMD64, "Si", "No") & vbCrLf
      mistr = mistr & "IA64: " & IIf(info.IA64, "Si", "No") & vbCrLf
      mistr = mistr & "DRIVER: " & IIf(info.WINDRV, "Si", "No") & vbCrLf
      mistr = mistr & "MS-DOS COM: " & IIf(info.DOSCOM, "Si", "No") & vbCrLf
      mistr = mistr & "MS-DOS EXE: " & IIf(info.DOSEXE, "Si", "No") & vbCrLf
      mistr = mistr & "Windows 16: " & IIf(info.WINEXE, "Si", "No") & vbCrLf
      mistr = mistr & "Windows 32: " & IIf(info.W32EXE, "Si", "No") & vbCrLf
      mistr = mistr & "Windows 64: " & IIf(info.W64EXE, "Si", "No") & vbCrLf
      mistr = mistr & "Graphic UI: " & IIf(info.GUI, "Si", "No") & vbCrLf
      mistr = mistr & "Console UI: " & IIf(info.CUI, "Si", "No") & vbCrLf
      mistr = mistr & "POSIX CUI: " & IIf(info.POSIX, "Si", "No") & vbCrLf
      mistr = mistr & "OS/2 CUI: " & IIf(info.OS2, "Si", "No") & vbCrLf
      mistr = mistr & "Executable: " & IIf(info.EXECUTABLE, "Si", "No") & vbCrLf
      mistr = mistr & "Exe Strip: " & IIf(info.STRIPPED, "Si", "No") & vbCrLf
      mistr = mistr & "Errores: " & IIf(info.Errors, "Si", "No") & vbCrLf
      mistr = mistr & "Err Num: " & info.ErrN & vbCrLf
      mistr = mistr & "Err Desc: " & info.ErrDsc & vbCrLf
      mistr = mistr & "-----------------" & vbCrLf & vbCrLf

      DoEvents
  Next i
    
  ChDir (App.path)
  Dim fnum As Long
  fnum = FreeFile
  Open App.path & "\logdemo.txt" For Binary As fnum
    Put fnum, , mistr
  Close fnum
  Debug.Print mistr
  End
End Sub
