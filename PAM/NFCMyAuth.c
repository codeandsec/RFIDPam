
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

typedef unsigned char BYTE;
typedef BYTE *        PBYTE;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	int i, nrounds = 5;
	unsigned char key[32], iv[32];
  	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) return -1;

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	return 0;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}


int CheckNFC()
{

	void* handle;
	char* error;
	long (*ReaderOpen)(void);
	long (*ReaderClose)(void);
	long (*LinearRead)(PBYTE, short, short, short*, unsigned char, unsigned char); 
	long i;
	BYTE DataBuf[753];
	short bytesret;
	char printable[64];
	FILE *fp;
	char secrettext[]= "Welcome Back Master! Unlocking.";
	EVP_CIPHER_CTX en,de;
	unsigned int salt[] = {12345, 54321};
	unsigned char ciphertext[48];
	char *plaintext;
	int len;
	
	handle = dlopen ("/usr/local/lib/libuFCoder1x64.so", RTLD_LAZY);
	error = dlerror ();
	if (error) return 1;

	ReaderOpen = dlsym (handle, "ReaderOpen");
	error = dlerror ();
	if (error) return 2;
 	ReaderClose = dlsym (handle, "ReaderClose");
	error = dlerror ();
	if (error) return 3;

	i = ReaderOpen();
	if (i != 0) return 4;

	LinearRead = dlsym (handle, "LinearRead");
	error = dlerror ();
	if (error) return 5;
	
	i = LinearRead(DataBuf, 0, 752, &bytesret, 0x60, 0);
	if (i != 0) return 6;

	for (i=0;i<32;i++)
		printable[i] = DataBuf[i];
	printable[32]=0x00;

	i=ReaderClose();

	if (aes_init(printable, strlen(printable), (unsigned char *)&salt, &en, &de)) return 7;
	
	fp = fopen("/etc/MyAuth", "r");
	if (!fp) 
	{
		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
		return 8;
	}
	fread(ciphertext, 1, 48, fp);
	fclose(fp);
	len =48;
	plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

	if (strcmp(plaintext, secrettext) == 0)
		return 0;
	else
	{
		
		free(plaintext);
		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
		return 9;
	}
  

}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	
	int retval = CheckNFC();
	if (retval != 0)
	{
		printf("\nNFC Auth Err: %d", retval);
		return PAM_AUTH_ERR;
	}
	else
		return PAM_SUCCESS;
}
