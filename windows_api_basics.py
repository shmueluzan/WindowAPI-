# Import the required module to handle Windows API Calls
import ctypes
from ctypes.wintypes import HANDLE, DWORD, WORD,LPBYTE ,LPSTR, LPWSTR, ULONG

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

class WindowsAPI:
    #types for message box
    class MessageBoxType:
        MS_OK           = 0x00000000
        MB_OKCANCEL     = 0x00000001

        IDOK            = 1
        IDCANCEL        = 2
        IDABORT         = 3
        IDCONTINUE      =11
    # types for process
    class ProcessAccess:
        # Access Rights
        PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

        #Type of process
        CREATE_NEW_CONSOLE  = 0x00000010 # The new process has a new console, instead of inheriting it parent's console

        #dwFlags
        STARTF_USERSHOWWINDOW = 0x00000001
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

    #Block of class
    def __init__(self):
        # Setting Up The Params

        #names of dll files
        USER32_DLL = "User32.dll"
        KERNERL_DLL = "Kernel32.dll"
        DNSAPI_DLL  = "DNSAPI.DLL"

        # Grab a handle to kernel32.dll & USer32.dll
        self.__kernel_handler = ctypes.WinDLL(KERNERL_DLL)
        self.__user_handler = ctypes.WinDLL(USER32_DLL)
        self.__dns_handler = ctypes.WinDLL(DNSAPI_DLL)

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
        dwDesiredAccess = WindowsAPI.ProcessAccess.PROCESS_ALL_ACCESS
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
        #lpStartupInfo       = WindowsAPI.STARTUPINFRO()  #   LPSTARTUPINFOA
        #lpProcessInformation= WindowsAPI.PROCESS_INFORMATION()  #   #LPPROCESS_INFORMATION
        
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

def walk_dns_entry(DNS_Entry):
    while True:
        try: #wallking for each entry and prints
            DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(WindowsAPI.DNS_CACHE_ENTRY))
            PrintScreen.log("DNS Entry {0} - Type {1}".format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
        except:
            break

# Create WinApi Obj
api = WindowsAPI()

# Example Message Box 
#print(api.message_box_a(0, "Message Box Title", "Header Message Box", WindowsAPI.MessageBoxType.MB_OKCANCEL))

# Example Kill Proc
#input_user = "Task Manager"
#input_user = "new 1 - Notepad++"
#api.kill_process(input_user)

# Example Spawn Proc
#lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
#dwCreationFlags=WindowsAPI.ProcessAccess.CREATE_NEW_CONSOLE
#lpProcessInformation= WindowsAPI.PROCESS_INFORMATION()
#lpStartupInfo       = WindowsAPI.STARTUPINFRO()
#lpStartupInfo.wShowWindow   = 0x1
#lpStartupInfo.dwFlags       = WindowsAPI.ProcessAccess.STARTF_USERSHOWWINDOW
#api.create_process(lpApplicationName, dwCreationFlags, lpProcessInformation, lpStartupInfo)


# Example get Dns Doc
DNS_Entry   = WindowsAPI.DNS_CACHE_ENTRY()
DNS_Entry.wDataLength   = 1024

print(api.dns_get_cache_data_table(DNS_Entry))
walk_dns_entry(DNS_Entry)
pass

