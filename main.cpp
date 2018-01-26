#include <Windows.h> 
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <fstream>
#include <vector>

#define INIT_FUNCTION "Tl2iInit" 

using namespace std;

namespace TL2Injector 
{
	bool StartGame(PROCESS_INFORMATION*); // launches the game, returns true if successful
	bool InjectDll(HANDLE*, string );
	bool GetDllList(vector<string>*);
}

// processInfo is a pointer used for output
bool TL2Injector::StartGame(PROCESS_INFORMATION * processInfo)
{
	STARTUPINFO startupInfo;
	ZeroMemory( &startupInfo, sizeof(startupInfo) );
	bool success = CreateProcess("Torchlight2.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, processInfo);
	return success;
}

bool InjectDll(HANDLE * targetProcess, string dllName)
{
	const char * dllNameCstr = dllName.c_str();
	int dllNameLen = dllName.length()+1;
	DWORD libAddress = 0;
	LPTHREAD_START_ROUTINE loadDllAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	
	// Store the DLL name in the process's memory so we can load it
	void * libNameMemory = VirtualAllocEx(targetProcess, NULL, dllNameLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(targetProcess, libNameMemory, dllNameCstr, dllNameLen, NULL);
	HANDLE injectionThread = CreateRemoteThread(targetProcess, NULL, 0, loadDllAddress, libNameMemory, 0, NULL);
	WaitForSingleObject(injectionThread, INFINITE);
	GetExitCodeThread(injectionThread, &libAddress );
	VirtualFreeEx(targetProcess, libNameMemory, dllNameLen, MEM_RELEASE);
	CloseHandle(injectionThread);
	
	// Call init function
	// If there's no init function then DllMain should be defined instead
	HMODULE loadedLib = LoadLibrary(dllNameCstr);
	if (GetProcAddress(loadedLib, INIT_FUNCTION) == NULL) // if there's no init function, don't call it!
	{
		FreeLibrary(loadedLib);
	}
	else
	{
		DWORD initOffset = (DWORD)(GetProcAddress(loadedLib, INIT_FUNCTION)) - (DWORD)(loadedLib);
		FreeLibrary(loadedLib); // we've got the address so we dont need this anymore
		LPTHREAD_START_ROUTINE initAddress = (LPTHREAD_START_ROUTINE)(initOffset+libAddress);
		HANDLE initThread = CreateRemoteThread(targetProcess, NULL, 0, initAddress, NULL, 0, NULL);
		WaitForSingleObject(initThread, INFINITE);
		CloseHandle(initThread);
	}
	
	return true;
}

bool TL2Injector::GetDllList(vector<string> * filenames)
{
	// iterate through each file in the subdirectory "TL2I" and save the filenames to a vector
	WIN32_FIND_DATA currentFileData;
	HANDLE fileSearchHandle = FindFirstFile("TL2I\\*.dll", &currentFileData);
	bool stillSearching = true;
	while (fileSearchHandle != INVALID_HANDLE_VALUE && stillSearching)
	{
		filenames->push_back( string("TL2I\\") + string(currentFileData.cFileName) );
		stillSearching = FindNextFile(fileSearchHandle, &currentFileData);
	}
	if (filenames->size() == 0)
	{
		return false;
	}
	return true;
}

int main(int argc, char * argv[])
{
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));
	
	if ( !TL2Injector::StartGame(&processInfo) ) // attempt to start the game
	{
		printf("Unable to start game.");
		return -1;
	}
	printf("Torchlight 2 has been started.");
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processInfo.dwProcessId); 
	
	// now get a list of every DLL in the subdirectory TL2I
	vector<string> dllFilenames;
	if ( !TL2Injector::GetDllList(&dllFilenames) )
	{
		printf("No DLLs loaded.");
	}
	printf("Found %u DLLs.", dllFilenames.size());
	// Once we have all the DLL names, iterate through and inject them
	for (unsigned int i=0; i<dllFilenames.size(); i++)
	{
		if ( !InjectDll(&processHandle, dllFilenames[i]) )
		{
			printf("Injection failed for file %s", dllFilenames[i].c_str());
		}
		else 
		{
			printf("Injected file %s successfully.", dllFilenames[i].c_str());
		}
	}
	
	return 0;
}