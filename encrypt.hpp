#pragma once

extern BOOL ReadFileToByteArray( const char* szFileName, PBYTE* lpBuffer, PDWORD dwDataLen );

extern BOOL BCryptImportPrivateKey( BCRYPT_ALG_HANDLE hProvider, PBYTE lpData, ULONG dwDataLen, BCRYPT_KEY_HANDLE* hKey );
extern BOOL BCryptImportPublicKey( BCRYPT_ALG_HANDLE hProvider, PBYTE lpData, ULONG dwDataLen, BCRYPT_KEY_HANDLE* hKey );

extern BOOL RSADecrypt( PBYTE pbInputData, DWORD dwInputDataSize, PBYTE* lpDecryptedBuffer, PDWORD dwDecryptedBufferLen );
extern BOOL RSAEncrypt( PBYTE pbInputData, DWORD dwInputDataSize, PBYTE* lpEncryptedBuffer, PDWORD dwEncryptedBufferLen );

extern BOOL AESEncrypt( PBYTE pbInputData, DWORD dwInputDataSize, PBYTE pbKey, DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen, PBYTE* lpEncryptedBuffer, PDWORD dwEncryptedBufferLen );
extern BOOL AESDecrypt( PBYTE pbInputData, DWORD dwInputDataSize, PBYTE pbKey, DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen, PBYTE* lpDecryptedBuffer, PDWORD dwDecryptedBufferLen );