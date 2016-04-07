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
#include <stdio.h>
#include "common.h"
#include "rsa2048.h"

int main(void)
{
	HCRYPTPROV hCryptProv = 0;
	HCRYPTKEY key = 0;
	unsigned long cLen = 0;
	char *cipherText = 0;
	char *plainText = "PLAIN_TEXT_PLAIN_TEXT\0";
	unsigned char *decrypted = 0;
	unsigned char *publicKey = 0;
	unsigned char *privateKey = 0;

	if (!CryptoInit(&key, &hCryptProv, &publicKey, &privateKey))
	{
		printf("Crypto initializing failed\n");
		return EXIT_FAILURE;
	}

	if (!Encrypt(key, &cipherText, &cLen, (unsigned char *)plainText, strlen(plainText)))
	{
		printf("Encryption failed\n");
		if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
		return EXIT_FAILURE;
	}

	printf("Encrypted string: %s\n", cipherText);

	if (!Decrypt(key, &decrypted, cipherText, cLen))
	{
		printf("Decryption failed\n");
		SAFE_FREE(cipherText);
		if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
		return EXIT_FAILURE;
	}

	SAFE_FREE(cipherText);

	printf("Decrypted string: %s\n", decrypted);

	SAFE_FREE(decrypted);

	CryptoUninit(key, hCryptProv);

	SAFE_FREE(publicKey);
	SAFE_FREE(privateKey);

	return EXIT_SUCCESS;
}
