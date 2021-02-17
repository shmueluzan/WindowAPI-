# Import the required module to handle Windows API Calls
import ctypes
from ctypes.wintypes import HANDLE, DWORD, WORD,LPBYTE ,LPSTR, LPCSTR, LPWSTR, ULONG

class PrintScreen:
    @staticmethod
    def log(message):
        print ("[INFO] + {}".format(message))
    
    @staticmethod
    def err(message):
        print ("[ERROR] - {}".format(message))        

    @staticmethod
    def warrning(message):
        print ("[WARNING] ^ {}".format(message))        
#Content of MessageBox
class MessageBoxType:
    MS_OK           = 0x00000000
    MB_OKCANCEL     = 0x00000001
    IDOK            = 1
    IDCANCEL        = 2
    IDABORT         = 3
    IDCONTINUE      =11
#Content of Process
class ProcessAccess:
    # Access Rights
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    #Type of process
    CREATE_NEW_CONSOLE  = 0x00000010 # The new process has a new console, instead of inheriting it parent's console
    #dwFlags
    STARTF_USERSHOWWINDOW = 0x00000001
#Content of Privilege 
class PrivilegeContent:
    SE_CHANGE_NOTIFY_NAME   =   "SeChangeNotifyPrivilege"   # Required to receive notifications of change to files ot direcotories.
    SE_DEBUG                =   "SeDebugPrivilege"
    SE_PRIVILEGE_ENABLED    = 0X00000002
    SE_PRIVILEGE_DISABLED    = 0X00000000
#Content of Token Access Righs
class TokenAccess:
    STANDARD_RIGHTS_REQUIRED    =   0X000F0000
    STANDARD_RIGHTS_READ        =   0X00020000
    TOKEN_ASSIGN_PRIMARY        =   0X0001
    TOKEN_DUPLICATE             =   0X0002
    TOKEN_IMPERSONATION         =   0X0004
    TOEKN_QUERY                 =   0X0008
    TOEKN_QUERY_SOURCE          =   0X0010
    TOKEN_ADJUST_PRIVILEGES     =   0X0020
    TOKEN_ADJUST_GROUPS         =   0X0040
    TOKEN_ADJUST_DEFAULT        =   0X0080
    TOKEN_ADJUST_SESSIONID      =   0X0100
    TOKEN_READ                  =   (STANDARD_RIGHTS_READ   |   TOEKN_QUERY)
    TOKEN_ALL_ACCESS            =   (STANDARD_RIGHTS_REQUIRED  | TOKEN_ASSIGN_PRIMARY    |   TOKEN_DUPLICATE    |
                                    TOKEN_IMPERSONATION     |   TOEKN_QUERY | TOEKN_QUERY_SOURCE    |   TOKEN_ADJUST_PRIVILEGES|
                                    TOKEN_ADJUST_GROUPS |   TOKEN_ADJUST_DEFAULT    |   TOKEN_ADJUST_SESSIONID)
#Structure for process info
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]
#Structure for Startup Info
class STARTUPINFRO(ctypes.Structure):
    _fields_ = [
        ("cd", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE) 
    ]
#Structure for DNS Cache Entry
class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_    =   [
        ("pNext",HANDLE),
        ("recName",LPWSTR),
        ("wType",DWORD),
        ("wDataLength",DWORD),
        ("dwFlags",DWORD)
    ]
#Structure for LUID - Describes a local identifier for an adapter
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD)
    ]
#Structure for LUID_AND_ATTRIBUTES - represents a locally unique idenifier and its attributes 
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD)
    ]
#Structure for PRIVILEGE SET - Specifies a set of privileges. it is also used to indicate which, if privileges are held by a user or group requsting access to an object
class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]
#Structure for TOKEN PRIVILEGES -
class TOKEN_PRIVILEGE(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]

class WindowsAPI:
    #Block of class
    def __init__(self):
        # Setting Up The Params

        #names of dll files
        USER32_DLL = "User32.dll"
        KERNERL_DLL = "Kernel32.dll"
        DNSAPI_DLL  = "DNSAPI.DLL"
        ADVAPI32_DLL  = "Advapi32.dll"

        # Grab a handle to kernel32.dll & USer32.dll
        self.__kernel_handler = ctypes.WinDLL(KERNERL_DLL)
        self.__user_handler = ctypes.WinDLL(USER32_DLL)
        self.__dns_handler = ctypes.WinDLL(DNSAPI_DLL)
        self.__advapi_handler = ctypes.WinDLL(ADVAPI32_DLL)

    #Check Last Error
    def assert_last_error(self):
        '''
            Function check last error, if occur error the program will exit with error 1
        '''
        error = self.__kernel_handler.GetLastError()
        PrintScreen.err("Error Code is [{}]".format(error))

        if error != 0:
            exit(1)

    def message_box_a(self, handle_window, lpText, lpCation, uType):
        # Calling the Windows API Call
        response = self.__user_handler.MessageBoxW(handle_window, lpText, lpCation, uType)

        self.assert_last_error()
        if response == 0:
            PrintScreen.err("message_box_a: - Could Not Pop Up Message Box")
        
        # Check to see if we have a valid Handle
        if response <= 0:
	        PrintScreen.log("Handle Not Created!")
        elif response >= 1:
	        PrintScreen.log("Handle Created!")    
        
        return response

    def find_window_a(self, widnowName):
        #hWndParent = 0
        #hWndChildAfter = 0
        lpClassName = None # ctypes.c_char_p(widnowName.encode("utf-8"))
        #lpWidnowName = ctypes.c_char_p(widnowName.encode('utf-8'))
        lpWidnowName = LPSTR(widnowName.encode('utf-8'))
        
        # Calling the Windows API Call
        #window_handle = self.__user_handler.FindWindowExA(hWndParent,hWndChildAfter, lpClassName, lpWidnowsName)
        window_handle = self.__user_handler.FindWindowA(lpClassName, lpWidnowName)
                                          #.FindWindowA(None, lpWindowName)

        if window_handle == 0 or window_handle is None:
            PrintScreen.err("find_window_a: Could Not Grab Handle".format())
            self.assert_last_error() # check if occur error
            exit(1)
        else:
            PrintScreen.log("find_window_a: Got Handle [{}]...".format(widnowName))

        return window_handle

    def get_windows_thread_process_id(self, handleWidnwos):
        hWnd = handleWidnwos
        # Get the PID of the process at the handle
        #lpdwProcessId = ctypes.c_ulong()
        lpdwProcessId = DWORD()

        # We use byref to pass a pointer to the value as needed by the API Call
        response = self.__user_handler.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))
        # Check to see if the call Completed
        if response <= 0 or response is None:
            PrintScreen.err("get_windows_thread_process_id: - Could Not Grab PID")
            self.assert_last_error() # check if occur error
            exit(1)
        else:
            PrintScreen.log("get_windows_thread_process_id: Got ID...")

        return lpdwProcessId

    def open_process(self, processID):
        # Opening the Process by PID with Specific Access
        dwDesiredAccess = ProcessAccess.PROCESS_ALL_ACCESS
        bInheritHandle  = False
        dwProcessID     = processID
        
        # Calling the Windows API Call to Open the Process
        process_handler = self.__kernel_handler.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessID)
        # Check to see if we have a valid Handle to the process
        if process_handler <= 0 or process_handler is None:
            PrintScreen.err("open_process: Could Not Grab Handle Priv Handle")
            #Check Errors
            self.assert_last_error()
            exit(1)
        else:
            PrintScreen.log("open_process: Got Process Handle....")
        
        return process_handler

    def terminate_process(self, hanldeProcess, exitCode):
        handleProcessTemp = hanldeProcess
        # Send Kill to the process
        uExitCode = exitCode
        # Calling the Windows API Call
        response = self.__kernel_handler.TerminateProcess(handleProcessTemp, uExitCode)

        if response <= 0 or response is None:
            PrintScreen.err("terminate_process: Error Code [0] - Could Not Kill Process")
            self.assert_last_error() # check if occur error
            exit(1)
        else:
            PrintScreen.log("terminate_process: Killed...")

        return response
    #Kill Proc By Name
    def kill_process(self, processName, exitCode=0x1):
        handleWindows   = self.find_window_a(processName)
        processID       = self.get_windows_thread_process_id(handleWindows)
        hanldeProcess   = self.open_process(processID)
        response        = self.terminate_process(hanldeProcess, exitCode)
        PrintScreen.log("Status {}".format(response))
    #Spawn Proc
    def create_process(self, lpApplicationName, dwCreationFlags, lpProcessInformation, lpStartupInfo):
        lpApplicationName   = LPSTR(lpApplicationName.encode("utf-8"))  #   LPCSTR
        lpCommandLine       = None  #   LPSTR
        lpProcessAttributes = None  #   LPSECUTITY_ATTRIBUTES
        lpThreadAttributes  = None  #   LPSECUTITY_ATTRIBUTES
        bInheritHandle      = False  #   Bool
        #dwCreationFlags     = None  #   DWORD
        lpEnvironment       = None  #   LPVOID
        lpCurrentDirectory  = None  #   LPCSTR
        #lpStartupInfo       = STARTUPINFRO()  #   LPSTARTUPINFOA
        #lpProcessInformation= PROCESS_INFORMATION()  #   #LPPROCESS_INFORMATION
        
        # Calling the Windows API Call
        response = self.__kernel_handler.CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandle, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
         # Check to see if we have a valid Handle to the process
        if response <= 0 or response is None:
            PrintScreen.err("create_process: Could Not Create Process Handle")
            self.assert_last_error()
        else:
            PrintScreen.log("Process Is Running...")

        return response
    #Undocumented
    def dns_get_cache_data_table(self, DNS_Entry):

        # Calling the Windows API Call
        response = self.__dns_handler.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

        if response <= 0 or response is None:
            PrintScreen.err("dns_get_cache_data_table: Could Not Get DNS Cache")
            self.assert_last_error()
        else:
            PrintScreen.log("Got DNS Cache...")

        return response
    #
    def open_process_token(self, processHandle, desiredAccess, tokenHandle):
        # Calling the Windows API Call
        response = self.__advapi_handler.OpenProcessToken(processHandle, desiredAccess, ctypes.byref(tokenHandle))

        if response <= 0 or response is None:
            PrintScreen.err("open_process_token: Could Not Grab Privilege Handle to Token")
            self.assert_last_error()
        else:
            PrintScreen.log("Privilege Handle Opened [{0}]".format(tokenHandle))

        return response

    def lookup_privilege_value(self, lpSystemName, lpName, luidPrivilege):

        # Calling the Windows API Call to
        response = self.__advapi_handler.LookupPrivilegeValueA(lpSystemName, LPCSTR(lpName.encode("utf-8")), ctypes.byref(luidPrivilege))

        if response <= 0 or response is None:
            PrintScreen.err("lookup_privilege_value: Could Not Get LUID Value")
            self.assert_last_error()
        else:
            PrintScreen.log("We Found The LUID...")

        return response

    def privilege_check(self, tokenHandle, requiredPrivileges, pfResult):
        # Calling the Windows API Call to
        response = self.__advapi_handler.PrivilegeCheck(tokenHandle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

        if response <= 0 or response is None:
            PrintScreen.err("privilege_check: Could Not Run Priv Check!")
            self.assert_last_error()
        else:
            PrintScreen.log("Run Priv Check...")

        return response

    def adjust_token_privileges(self, tokenHandle, disableAllPrivileges, newState, bufferLength, previousState, returnLength):
        '''
            function enables or disables privileges in the speccified accesss token. enabling or disabling privileges in an access token requires...
        '''
        # Calling the Windows API Call to AdjustTokenPrivileges
        response = self.__advapi_handler.AdjustTokenPrivileges(tokenHandle, disableAllPrivileges, ctypes.byref(newState), bufferLength, ctypes.byref(previousState), ctypes.byref(returnLength))

        if response <= 0 or response is None:
            PrintScreen.err("adjust_token_privileges: AdjustTokenPrivileges Failed!")
            self.assert_last_error()
        else:
            PrintScreen.log("AdjustTokenPrivileges Flipped Privilege...")

        return response

def walk_dns_entry(DNS_Entry):
    while True:
        try: #wallking for each entry and prints, in addition, example of how use cast function
            DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))
            PrintScreen.log("DNS Entry {0} - Type {1}".format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
        except:
            break

# Create WinApi Obj
api = WindowsAPI()
#-----------------------------------------------------------------------------------------------------
# Example Message Box 
#print(api.message_box_a(0, "Message Box Title", "Header Message Box", MessageBoxType.MB_OKCANCEL))
#-----------------------------------------------------------------------------------------------------
# Example Kill Proc
#input_user = "Task Manager"
#input_user = "new 1 - Notepad++"
#api.kill_process(input_user)
#-----------------------------------------------------------------------------------------------------
# Example Spawn Proc
#lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
#dwCreationFlags=ProcessAccess.CREATE_NEW_CONSOLE
#lpProcessInformation= PROCESS_INFORMATION()
#lpStartupInfo       = STARTUPINFRO()
#lpStartupInfo.wShowWindow   = 0x1
#lpStartupInfo.dwFlags       = ProcessAccess.STARTF_USERSHOWWINDOW
#api.create_process(lpApplicationName, dwCreationFlags, lpProcessInformation, lpStartupInfo)
#-----------------------------------------------------------------------------------------------------
# Example get Dns Doc
#DNS_Entry   = DNS_CACHE_ENTRY()
#DNS_Entry.wDataLength   = 1024
#
#print(api.dns_get_cache_data_table(DNS_Entry))
#walk_dns_entry(DNS_Entry)
#-----------------------------------------------------------------------------------------------------
# Example Get Token Privilege
processName =   "Task Manager"
processName =   "new 1 - Notepad++"
handleWindows   = api.find_window_a(processName)
processID       = api.get_windows_thread_process_id(handleWindows)
processHandle   = api.open_process(processID)   
desiredAccess   =   TokenAccess.TOKEN_ALL_ACCESS
tokenHandle     =   HANDLE()
api.open_process_token(processHandle, desiredAccess, tokenHandle)
#-----------------------------------------------------------------------------------------------------
# Example Lookup Privilege Value
lpSystemName    =   LPCSTR() #LPCSTR
luidPrivilege   =   LUID()
lpName          =   PrivilegeContent.SE_CHANGE_NOTIFY_NAME
response = api.lookup_privilege_value(lpSystemName, lpName, luidPrivilege)
#-----------------------------------------------------------------------------------------------------
# Example Check Privilege
requiredPrivileges = PRIVILEGE_SET()
requiredPrivileges.PrivilegeCount = 1

requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()
requiredPrivileges.Privileges.Luid = luidPrivilege  
requiredPrivileges.Privileges.Attributes = PrivilegeContent.SE_PRIVILEGE_ENABLED

pfResult = ctypes.c_long()
api.privilege_check(tokenHandle, requiredPrivileges, pfResult)
if pfResult:
    print("Priv Enabled {0}".format(lpName))
else:
    print("Priv Not Enabled {0}".format(lpName))
pass
#-----------------------------------------------------------------------------------------------------
# Example Adjust Token Privileges
disableAllPrivileges = False

newState = TOKEN_PRIVILEGE()
newState.PrivilegeCount = 1
newState.Privileges = requiredPrivileges.Privileges

bufferLength = ctypes.sizeof(newState)
previousState = ctypes.c_void_p()
returnLength = ctypes.c_void_p()


api.adjust_token_privileges(tokenHandle, disableAllPrivileges, newState, bufferLength, previousState, returnLength)
pass