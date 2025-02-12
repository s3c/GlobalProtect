#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

//gcc -o crypt.exe crypt.c

/*
#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

key = hashlib.md5(b'abc' + hashlib.md5("pannetwork".encode()).digest()).digest() + hashlib.md5(b'abc' + hashlib.md5("pannetwork".encode()).digest()).digest()
iv = b'\x00' * 16 
plaintext = b"abc"

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

padding_length = 16 - (len(plaintext) % 16)
padded_plaintext = plaintext + bytes([padding_length]) * padding_length

ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print(f"Ciphertext: {ciphertext.hex()}")

//a7de25a394edbf920e7c53c30e6d0b6f
*/

#define ENCRYPT 1
#define DECRYPT 2

#define MD5_DIGEST_LENGTH 16
#define AES_KEY_SIZE 32

typedef struct APLAINTEXTKEYBLOB {
	BLOBHEADER hdr;
	DWORD keySize;
	BYTE keyData[AES_KEY_SIZE];
} APLAINTEXTKEYBLOB, *APPLAINTEXTKEYBLOB;

void print_in_hex(unsigned char *bytes, int bytes_len){
    for (int i = 0; i < bytes_len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int MD5_hash(unsigned char *input, size_t length, unsigned char *output) {
    HCRYPTPROV hCryptProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed: %x\n", GetLastError());
        return 1;
    }

    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        printf("CryptCreateHash failed: %x\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        return 2;
    }

    if (!CryptHashData(hHash, input, (DWORD)length, 0)) {
        printf("CryptHashData failed: %x\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        CryptDestroyHash(hHash);
        return 3;
    }

    DWORD dwHashLen = MD5_DIGEST_LENGTH;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, output, &dwHashLen, 0)) {
        printf("CryptGetHashParam failed: %x\n", GetLastError());
		return 4;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);

	return 0;
}

int generate_key(unsigned char *key, size_t key_len, unsigned char *output) {
    unsigned char key_static_md5[MD5_DIGEST_LENGTH];
	unsigned char hashed_static_key[MD5_DIGEST_LENGTH];
	unsigned char hashes_combined[MD5_DIGEST_LENGTH * 2];
    unsigned char blob_and_hashed_key[256];
	unsigned char key_static[] = {0x70, 0x61, 0x6E, 0x6E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B};

	if (MD5_hash(key_static, sizeof(key_static), hashed_static_key)) {
		printf("Failed to create MD5 of static key: %d\n", GetLastError());
		return 1;
	}

    memcpy(blob_and_hashed_key, key, key_len);
    memcpy(blob_and_hashed_key + key_len, hashed_static_key, MD5_DIGEST_LENGTH);
	
	if (MD5_hash(blob_and_hashed_key, key_len + MD5_DIGEST_LENGTH, key_static_md5)) {
		printf("Failed to create MD5 of SID: %d\n", GetLastError());
		return 2;
	}
	
    memcpy(output, key_static_md5, MD5_DIGEST_LENGTH);
    memcpy(output + MD5_DIGEST_LENGTH, key_static_md5, MD5_DIGEST_LENGTH);
	
	return 0;
}

int crypt_aes_256_cbc(char *key, char *data, DWORD data_len, DWORD buffer_len, int action) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    BYTE iv[16] = {0};
    APLAINTEXTKEYBLOB key_blob;

    key_blob.hdr.bType = PLAINTEXTKEYBLOB;
    key_blob.hdr.bVersion = CUR_BLOB_VERSION;
    key_blob.hdr.reserved = 0;
    key_blob.hdr.aiKeyAlg = CALG_AES_256;
    key_blob.keySize = AES_KEY_SIZE;
    memcpy(key_blob.keyData, key, AES_KEY_SIZE);

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed: %x\n", GetLastError());
        return 0;
    }
	
    if (!CryptImportKey(hProv, (BYTE*)&key_blob, sizeof(key_blob), 0, 0, &hKey)) {
        printf("CryptImportKey failed: %x\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        return 0;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("CryptSetKeyParam failed: %x\n", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return 0;
    }

    if (action == ENCRYPT) {
        if (!CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)data, &data_len, buffer_len)) {
			printf("CryptEncrypt failed: %x\n", GetLastError());
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return 0;
        }
    } else if (action == DECRYPT) {
        if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE*)data, &data_len)) {
			printf("CryptDecrypt failed: %x\n", GetLastError());
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return 0;
        }
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return data_len;
}