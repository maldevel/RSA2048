#pragma once

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

#include <stdbool.h>

bool CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, unsigned char **publicKey, unsigned char **privateKey);
bool Encrypt(HCRYPTKEY key, char **cipherText, unsigned long *cLen, unsigned char *plainText, unsigned long pLen);
bool Decrypt(HCRYPTKEY key, unsigned char **plainText, char *cipherText, unsigned long cLen);
void CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider);
