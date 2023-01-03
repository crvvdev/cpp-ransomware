#pragma once

#include <windows.h>
#include <Shlwapi.h>
#include <cstdio>
#include <bcrypt.h>

#pragma comment( lib, "Bcrypt" )
#pragma comment( lib, "Crypt32" )
#pragma comment( lib, "Shlwapi" )

#define RSA_PUBLIC_KEY_FILENAME			"public.pem"
#define RSA_PRIVATE_KEY_FILENAME		"private.pem"

#include "encrypt.hpp"