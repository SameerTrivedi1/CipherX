# include <iostream>
# include <stdio.h>
# include "Headers.h"
# include "SCode.h"

# pragma comment(lib, "Crypt32")

BOOL ConvertToBase64(LPBYTE buff, DWORD buffsize)
{
	DWORD pcchString = 0;

	std::cout << buffsize << std::endl;

	if (!CryptBinaryToStringA(buff, buffsize, CRYPT_STRING_BASE64, NULL, &pcchString)) {
		std::cout << "[!] Base64 conversion Failed \n";
		std::cout << "Error : " << GetLastError() << std::endl;
		return FALSE;
	}

	std::cout << "Output Buffer Size : " << pcchString << std::endl;

	// Allocate memory for output buffer.
	
	LPSTR output = NULL;

	output = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcchString);
	if (output == NULL) {
		std::cout << "[!] Failed to Allocate memory for output buffer....\n";
		std::cout << "Error : " << GetLastError() << std::endl;
		return FALSE;
	}

	std::cout << "[+] Memory Allocation Successfull !!\n";
	

	// convert to Base64
	if (!CryptBinaryToStringA(buffer, buffsize, CRYPT_STRING_BASE64, output, &pcchString)) {
		std::cout << "[!] Base64 conversion Failed \n";
		std::cout << "Error : " << GetLastError() << std::endl;
		return FALSE;
	}

	std::cout << output << std::endl;
	HeapFree(GetProcessHeap(), 0, output);

	return TRUE;
}

BOOL ScToRC4(const BYTE payload[], DWORD psize)
{
	fnSystemFunction032 RC4Crypt = NULL;
	HMODULE hadvapi32 = NULL;

	if ((hadvapi32 = LoadLibraryA("advapi32.dll")) == NULL) {
		std::cout << "[!] Failed to load advapi32.dll....\n";
		return FALSE;
	}

	RC4Crypt = (fnSystemFunction032)GetProcAddress(hadvapi32, "SystemFunction032");

	if (RC4Crypt == NULL) {
		std::cout << "Error : " << GetLastError() << "\n";
		return FALSE;
	}
	std::cout << "SUCCESS\n";

	ustring data, key;
	unsigned char rc4key[] = {'C', 'O', 'K', 'E', 'B', 'E', 'A', 'R'};
	DWORD keylen = sizeof(rc4key);

	data.Buffer = (unsigned char *)payload;
	data.Length = psize;
	data.MaximumLength = data.Length;

	key.Buffer = rc4key;
	key.Length = keylen;
	key.MaximumLength = key.Length;

	if (RC4Crypt(&data, &key) != 0x00) {
		std::cout << "[!] RC4Crypt failed !!\n";
		std::cout << "[!] Error : " << GetLastError() << "\n";
		return FALSE;
	}
	//std::cout << "SUCCESS\n";

	for (int i = 0; i < (int)data.Length; i++)
	{
		if ((i % 15) == 0)
			printf("\n");
		printf("0X%.2X ,", data.Buffer[i]);
	}
	return TRUE;
}

BOOL XOR(const BYTE payload[], size_t pldsize)
{
	PBYTE tmpBuffer = NULL;
	std::cout << "Payload size : " << pldsize << "\n";
	
	tmpBuffer = (PBYTE)malloc(pldsize);

	if (tmpBuffer == NULL) {
		std::cout << "[!] Failed to allocate buffer...\n";
		return FALSE;
	}

	for (size_t i = 0; i < pldsize; i++) {
		tmpBuffer[i] = payload[i] ^ 'X';
		if ((i % 12) == 0)
			std::cout << "\n";
		printf("0X%.2X ", tmpBuffer[i]);
	}
	free(tmpBuffer);

	return TRUE;
}

BOOL WriteToFile(const unsigned char* data, size_t size, std::string filename)
{
	// Write to a file.
		
	FILE* handle = NULL;

	fopen_s(&handle, filename.c_str(), "wb");
	if (handle == NULL) {
		std::cout << "[!] Failed to open file....\n";
		return -1;
	}

	fwrite(data, 1, size, handle);
	std::cout << "\n" << size << " bytes of Shellcode written successfully ....\n";
	return TRUE;
}

BOOL ConvertToIPv4(const BYTE payload[], DWORD pldsize)
{
	if (payload == NULL || pldsize == NULL || (pldsize % 4) != 0) {
		std::cout << "[!] Invalid input parameters supplied....\n";
		return FALSE;
	}

	for (size_t i = 0; i < pldsize; i+=4)
	{
		if ((i % 12) == 0) {
			printf("\n");
		}
		printf("%d.%d.%d.%d, ", payload[i], payload[i + 1], payload[i + 2], payload[i + 3]);
	}
	return TRUE;
}

BOOL ConvertToIPv6(const BYTE payload[], DWORD pldsize)
{
	if (payload == NULL || pldsize == NULL || (pldsize % 16) != 0) {
		std::cout << "[!] Invalid input parameters supplied....\n";
		return FALSE;
	}

	for (size_t i = 0; i < pldsize; i += 16)
	{
		if ((i % 32) == 0) {
			printf("\n");
		}
		printf("%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X, ",
			payload[i], payload[i + 1], payload[i + 2], payload[i + 3],
			payload[i + 4], payload[i + 5], payload[i + 6], payload[i + 7],
			payload[i + 8], payload[i + 9], payload[i + 10], payload[i + 11],
			payload[i + 12], payload[i + 13], payload[i + 14], payload[i + 15]);
	}
	return TRUE;
}

BOOL MacFuscate(const BYTE payload[], DWORD pldsize)
{
	if (payload == NULL || pldsize == NULL || (pldsize % 6) != 0) {
		std::cout << "[!] Invalid input parameters supplied....\n";
		return FALSE;
	}
	for (size_t i = 0; i < pldsize; i+=6)
	{
		if ((i % 18) == 0) {
			printf("\n");
		}
		printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X, ", payload[i], payload[i + 1], payload[i + 2],
			payload[i + 3], payload[i + 4], payload[i + 5]);
	}
	return TRUE;
}

BOOL UUIDFuscate(const BYTE payload[], DWORD pldsize)
{
	if (payload == NULL || pldsize == NULL || (pldsize % 16) != 0) {
		std::cout << "[!] Invalid input parameters supplied....\n";
		return FALSE;
	}
	for (size_t i = 0; i < pldsize; i += 16)
	{
		printf("%.2X%.2X%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X,\n",
			payload[i+3], payload[i + 2], payload[i + 1], payload[i],
			payload[i + 5], payload[i + 4], payload[i + 7], payload[i + 6],
			payload[i + 8], payload[i + 9], payload[i + 10], payload[i + 11], payload[i + 12], payload[i + 13],
			payload[i + 14], payload[i + 15]);
	}
	return TRUE;
}

int main()
{

	for(int i=0; i<50; i++)
		std::cout << "#";
	std::cout << "\n\n\t\tWelcome to CipherX....\n\n";
	
	for (int i = 0; i < 50; i++)
		std::cout << "#";
	printf("\n\n");

	// xor, rc4, base64, ipv4, ipv6, mac, uuid, exit.
	std::cout << "\t 1) XOR Obfuscation     \n";
	std::cout << "\t 2) RC4 Obfuscation     \n";
	std::cout << "\t 3) MAC Obfuscation     \n";
	std::cout << "\t 4) IPv4 Obfuscation    \n";
	std::cout << "\t 5) IPv6 Obfuscation    \n";
	std::cout << "\t 6) UUID Obfuscation    \n";
	std::cout << "\t 7) BASE64 Obfuscation  \n";
	std::cout << "\t 8) Exit  \n";

	int option = 0;

	do {
		std::cout << "\n\n[Choose an Option : ]>> ";
		std::cin >> option;

		//std::cout << option;

		if (option > 0 && option <= 8)
		{
			DWORD BufferSize = sizeof(buffer);

			switch (option)
			{
			case 1:XOR(buffer, BufferSize);break;
			case 2:ScToRC4(buffer, BufferSize);break;
			case 3:MacFuscate(buffer, BufferSize);break;
			case 4:ConvertToIPv4(buffer, BufferSize);break;
			case 5:ConvertToIPv6(buffer, BufferSize);break;
			case 6:UUIDFuscate(buffer, BufferSize);break;
			case 7:ConvertToBase64(buffer, BufferSize);break;
			case 8:std::cout << "[*] Quitting....\n";
				return 0;
			} // switch end

		} // end if
		else {
			std::cout << "[!] Please select a valid option....\n";
		}
	} while (true); // end do-while
	

	return 0;
}