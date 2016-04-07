/*
RSA2048 - RSA 2048 encryption using CryptoAPI and C
Copyright (C) 2016  @maldevel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Windows.h>
#include <Wincrypt.h>
#include "common.h"

#ifndef MY_ENCODING_TYPE
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#endif

#include "base64.h"

bool Base64EncodeW(WCHAR **dest, unsigned long *dlen, const unsigned char *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptBinaryToStringW(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
		return false;

	*dest = (WCHAR *)malloc(*dlen * sizeof(WCHAR));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, *dlen * sizeof(WCHAR));

	if (!CryptBinaryToStringW(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool Base64EncodeA(char **dest, unsigned long *dlen, const unsigned char *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
		return false;

	*dest = (char *)malloc(*dlen * sizeof(char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, *dlen * sizeof(char));

	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool Base64DecodeW(unsigned char **dest, unsigned long *dlen, const WCHAR *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptStringToBinaryW(src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
		return false;

	*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

	if (!CryptStringToBinaryW(src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool Base64DecodeA(unsigned char **dest, unsigned long *dlen, const char *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
		return false;

	*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

	if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}
