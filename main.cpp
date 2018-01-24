#include <Windows.h> 
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <fstream>
#include <vector>

#define INIT_FUNCTION "tl2i_init"

using namespace std;

namespace TL2Injector 
{
	bool start_game(PROCESS_INFORMATION*); // launches the game, returns true if successful
	bool inject_dll(HANDLE*, string );
	bool get_dll_list(vector<string>*);
}

// process_info is a pointer used for output
bool TL2Injector::start_game(PROCESS_INFORMATION * process_info)
{
	bool success = CreateProcess("Torchlight2.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, NULL, process_info);
	return success;
}

bool inject_dll(HANDLE * target_process, string dll_name)
{
	const char * dll_name_cstr = dll_name.c_str();
	int dll_name_len = dll_name.length()+1;
	DWORD lib_address = 0;
	LPTHREAD_START_ROUTINE load_dll_address = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	LPTHREAD_START_ROUTINE free_dll_address = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "FreeLibrary");
	// Store the DLL name in the process's memory so we can load it
	void * lib_name_memory = VirtualAllocEx(target_process, NULL, dll_name_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//printf("Address: %p - size: %d \r\n", lib_name_memory, dll_name_len);
	WriteProcessMemory(target_process, lib_name_memory, dll_name_cstr, dll_name_len, NULL);
	HANDLE injection_thread = CreateRemoteThread(target_process, NULL, 0, load_dll_address, lib_name_memory, 0, NULL);
	WaitForSingleObject(injection_thread, INFINITE);
	GetExitCodeThread(injection_thread, &lib_address );
	//printf("DLL Address %p \r\n", (void*)lib_address);
	VirtualFreeEx(target_process, lib_name_memory, dll_name_len, MEM_RELEASE);
	CloseHandle(injection_thread);
	
	// Call init function
	// we must load the DLL first to find the function
	HMODULE loaded_lib = LoadLibrary(dll_name_cstr);
	// make sure the library has the init function - if not don't inject it
	if (GetProcAddress(loaded_lib, INIT_FUNCTION) == NULL)
	{
		FreeLibrary(loaded_lib);
		return false;
	}
	
	DWORD init_offset = (DWORD)(GetProcAddress(loaded_lib, INIT_FUNCTION)) - (DWORD)(loaded_lib);
	FreeLibrary(loaded_lib); // we've got the address so we dont need this anymore
	LPTHREAD_START_ROUTINE init_address = (LPTHREAD_START_ROUTINE)(init_offset + lib_address);
	HANDLE init_thread = CreateRemoteThread(target_process, NULL, 0, init_address, NULL, 0, NULL);
	WaitForSingleObject(init_thread, INFINITE);
	CloseHandle(init_thread);
	
	//DLL injected - unload it now
	HANDLE unload_thread = CreateRemoteThread(target_process, NULL, 0, free_dll_address, (void*)lib_address, 0, NULL);
	WaitForSingleObject(unload_thread, INFINITE);
	return true;
}

bool TL2Injector::get_dll_list(vector<string> * filenames)
{
	// iterate through each file in the subdirectory "TL2I" and save the filenames to a vector
	WIN32_FIND_DATA current_file_data;
	HANDLE file_search_handle = FindFirstFile(".\\TL2I\\*.dll", &current_file_data);
	while (file_search_handle != INVALID_HANDLE_VALUE)
	{
		filenames->push_back( string(current_file_data.cFileName) );
		FindNextFile(file_search_handle, &current_file_data);
	}
	if (filenames->size() == 0)
	{
		return false;
	}
	return true;
}

int main(int argc, char * argv[])
{
	PROCESS_INFORMATION process_info;
	if ( !TL2Injector::start_game(&process_info) ) // attempt to start the game
	{
		printf("Unable to start game.");
		return -1;
	}
	HANDLE * process_handle = &(process_info.hProcess); 
	
	// now get a list of every DLL in the subdirectory TL2I
	vector<string> dll_filenames;
	if ( !TL2Injector::get_dll_list(&dll_filenames) )
	{
		printf("No DLLs loaded.");
	}
	
	// Once we have all the DLL names, iterate through and inject them
	for (unsigned int i=0; i<dll_filenames.size(); i++)
	{
		if ( !inject_dll(process_handle, dll_filenames[i]) )
		{
			printf("Injection failed for file %s", dll_filenames[i].c_str());
		}
	}
	
	return 0;
}