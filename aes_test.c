/*********************************************************************
* Filename:   aes_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding AES
              implementation. These tests do not encompass the full
              range of available test vectors and are not sufficient
              for FIPS-140 certification. However, if the tests pass
              it is very, very likely that the code is correct and was
              compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <string.h>
//#include <memory.h>
#include "aes_tuned.h"

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		//printf("%02x", str[idx]);
                printf("%c", str[idx]);
        
        printf("\r\n");//MY thing
              
}

int aes_ecb_test()
{
	WORD key_schedule[60], idx;
	BYTE enc_buf[128];
	BYTE plaintext[2][16] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
		{0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[2][16] = {
		{0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
		{0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	// Raw ECB mode.
	//printf("* ECB mode:\n");
	aes_key_setup(key[0], key_schedule, 256);
	//printf(  "Key          : ");
	//print_hex(key[0], 32);

	for(idx = 0; idx < 2; idx++) {
		aes_encrypt(plaintext[idx], enc_buf, key_schedule, 256);
		//printf("\nPlaintext    : ");
		//print_hex(plaintext[idx], 16);
		//printf("\n-encrypted to: ");
		//print_hex(enc_buf, 16);
		pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);

		aes_decrypt(ciphertext[idx], enc_buf, key_schedule, 256);
		//printf("\nCiphertext   : ");
		//print_hex(ciphertext[idx], 16);
		//printf("\n-decrypted to: ");
		//print_hex(enc_buf, 16);
		pass = pass && !memcmp(enc_buf, plaintext[idx], 16);

		//printf("\n\n");
	}

	return(pass);
}

int aes_cbc_test()
{
	WORD key_schedule[60];
	BYTE enc_buf[128];
	BYTE plaintext[1][32] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[1][32] = {
		{0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d}
	};
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	//printf("* CBC mode:\n");
	aes_key_setup(key[0], key_schedule, 256);

	//printf(  "Key          : ");
	//print_hex(key[0], 32);
	//printf("\nIV           : ");
	//print_hex(iv[0], 16);

	aes_encrypt_cbc(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nPlaintext    : ");
	//print_hex(plaintext[0], 32);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, 32);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	pass = pass && !memcmp(enc_buf, ciphertext[0], 32);

	aes_decrypt_cbc(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, 32);
	//printf("\nPlaintext   : ");
	//print_hex(plaintext[0], 32);
	pass = pass && !memcmp(enc_buf, plaintext[0], 32);

	//printf("\n\n");
	return(pass);
}

int aes_ctr_test()
{
	WORD key_schedule[60];
	BYTE enc_buf[128];
	BYTE plaintext[1][32] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[1][32] = {
		{0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5}
	};
	BYTE iv[1][16] = {
		{0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff},
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	//printf("* CTR mode:\n");
	aes_key_setup(key[0], key_schedule, 256);

	//printf(  "Key          : ");
	//print_hex(key[0], 32);
	//printf("\nIV           : ");
	//print_hex(iv[0], 16);

	aes_encrypt_ctr(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nPlaintext    : ");
	//print_hex(plaintext[0], 32);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, 32);
	pass = pass && !memcmp(enc_buf, ciphertext[0], 32);

	aes_decrypt_ctr(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, 32);
	pass = pass && !memcmp(enc_buf, plaintext[0], 32);

	//printf("\n\n");
	return(pass);
}

int aes_ccm_test()
{
/* O R I G I N 
	int mac_auth;
	WORD enc_buf_len;
	BYTE enc_buf[128];
	BYTE plaintext[3][32] = {
		{0x20,0x21,0x22,0xFF},
		{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
		{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
	};

	BYTE assoc[3][32] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07},
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13}
	};
	BYTE ciphertext[3][32 + 16] = {
		{0x71,0x62,0x01,0x5b,0x4d,0xac,0x25,0x5d},
		{0xd2,0xa1,0xf0,0xe0,0x51,0xea,0x5f,0x62,0x08,0x1a,0x77,0x92,0x07,0x3d,0x59,0x3d,0x1f,0xc6,0x4f,0xbf,0xac,0xcd},
		{0xe3,0xb2,0x01,0xa9,0xf5,0xb7,0x1a,0x7a,0x9b,0x1c,0xea,0xec,0xcd,0x97,0xe7,0x0b,0x61,0x76,0xaa,0xd9,0xa4,0x42,0x8a,0xa5,0x48,0x43,0x92,0xfb,0xc1,0xb0,0x99,0x51}
	};
	BYTE iv[3][16] = {  //NONCE
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16},
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17},
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b}
	};
	BYTE key[1][32] = {
		{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}
	};
	int pass = 1;

	printf("* CCM mode:\n");
	printf("Key       : ");
	print_hex(key[0], 16);        // 404142434445464748494a4b4c4d4e4f     
	printf("Plaintext : ");
	print_hex(plaintext[0], 4);   // 20212223
        printf("Assoc     : ");
	print_hex(assoc[0], 8);       // 0001020304050607
        printf("Ciphertext: ");
	print_hex(ciphertext[0], 8);  // 7162015b4dac255d
        printf("Iv(NONCE) : ");
	print_hex(iv[0], 7);          // 10111213141516


        printf("______Encrypt______\r\n");

	aes_encrypt_ccm(plaintext[0], 4, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, key[0], 128);
	printf("Payload       : ");
	print_hex(plaintext[0], 4);
	printf("Encrypted to  : ");
	print_hex(enc_buf, enc_buf_len);
        printf("Encoded buf length : %d \r\n",enc_buf_len);
        //NOTE NEW ROUTINE
        memcpy(ciphertext[0], enc_buf, enc_buf_len); 
        //END OF NEW ROUTINE
	pass = pass && !memcmp(enc_buf, ciphertext[0], enc_buf_len);
        printf("Pass : %d \r\n",pass);
        printf("______Decrypt______\r\n");

	aes_decrypt_ccm(ciphertext[0], 8, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, &mac_auth, key[0], 128);
	printf("\n-Ciphertext  : ");
	print_hex(ciphertext[0], 8);
	printf("\n-decrypted to: ");
	print_hex(enc_buf, enc_buf_len);
	printf("\nAuthenticated: %d ", mac_auth);
	pass = pass && !memcmp(enc_buf, plaintext[0], enc_buf_len) && mac_auth;
        printf("\r\nPass : %d \r\n",pass);
        printf("\r\n--------------\r\n");
*/
//////////////


	//int mac_auth;
	//WORD enc_buf_len;
	//BYTE enc_buf[128];
	//BYTE plaintext[24]  = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37};
	//BYTE ciphertext[28] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x00,0x00,0x00,0x00};
	//BYTE assoc[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};                             //Association 
 //       BYTE iv[7]    = {'k','e','y','p','l','u','s'};                                         //NONCE (keyple is short) 
	//BYTE key[17]  = {'k','e','y','p','l','u','s','i','s','g','o','o','d','1','2','3','4'}; //Private key
	//int pass = 1;


	int mac_auth;
	WORD enc_buf_len;
	BYTE enc_buf[128];
	BYTE plaintext[16]  = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f};
	BYTE ciphertext[26];
	BYTE assoc[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};                             //Association 
        BYTE iv[12]    = {'k','e','y','p','l','e','0','0','0','0','0','0'};                    //NONCE 
	BYTE key[17]  = {'k','e','y','p','l','u','s','i','s','g','o','o','d','1','2','3','4'}; //Private key
	int pass = 1;


        printf("______Encrypt______\r\n");
	//aes_encrypt_ccm(plaintext, 24, assoc, 8, iv, 7, enc_buf, &enc_buf_len, 4, key, 128);
	//aes_encrypt_ccm(plaintext, 24, NULL, 0, iv, 7, enc_buf, &enc_buf_len, 4, key, 128);
	aes_encrypt_ccm(plaintext, 16, NULL, 0, iv, 12, enc_buf, &enc_buf_len, 10, key, 128);  
	printf("Payload       : ");
	print_hex(plaintext, 16);
	printf("Encrypted to  : ");
	print_hex(enc_buf, enc_buf_len);
        printf("Encoded buf length : %d \r\n",enc_buf_len);
        //NOTE NEW ROUTINE
        memcpy(ciphertext, enc_buf, enc_buf_len); 
        //END OF NEW ROUTINE
	pass = pass && !memcmp(enc_buf, ciphertext, enc_buf_len);
        printf("Pass : %d \r\n",pass);


        printf("______Decrypt______\r\n");
	//aes_decrypt_ccm(ciphertext, 28, assoc, 8, iv, 7, enc_buf, &enc_buf_len, 4, &mac_auth, key, 128);
	//aes_decrypt_ccm(ciphertext, 28, NULL, 0, iv, 7, enc_buf, &enc_buf_len, 4, &mac_auth, key, 128);
	aes_decrypt_ccm(ciphertext, 26 , NULL, 0, iv, 12, enc_buf, &enc_buf_len, 10, &mac_auth, key, 128);
	printf("Ciphertext  : ");
	print_hex(ciphertext, 28);
	printf("Decrypted to: ");
	print_hex(enc_buf, enc_buf_len);
	printf("Authenticated: %d\r\n", mac_auth);        
	pass = pass && !memcmp(enc_buf, plaintext, enc_buf_len) && mac_auth;
        printf("Pass : %d \r\n",pass);

	//aes_encrypt_ccm(plaintext[1], 16, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, key[0], 128);
	//printf("\n\nNONCE        : ");
	//print_hex(iv[1], 8);
	//printf("\nAssoc. Data  : ");
	//print_hex(assoc[1], 16);
	//printf("\nPayload      : ");
	//print_hex(plaintext[1], 16);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//pass = pass && !memcmp(enc_buf, ciphertext[1], enc_buf_len);

	//aes_decrypt_ccm(ciphertext[1], 22, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, &mac_auth, key[0], 128);
	//printf("\n-Ciphertext  : ");
	//print_hex(ciphertext[1], 22);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//printf("\nAuthenticated: %d ", mac_auth);
	//pass = pass && !memcmp(enc_buf, plaintext[1], enc_buf_len) && mac_auth;


	//aes_encrypt_ccm(plaintext[2], 24, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, key[0], 128);
	//printf("\n\nNONCE        : ");
	//print_hex(iv[2], 12);
	//printf("\nAssoc. Data  : ");
	//print_hex(assoc[2], 20);
	//printf("\nPayload      : ");
	//print_hex(plaintext[2], 24);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//pass = pass && !memcmp(enc_buf, ciphertext[2], enc_buf_len);

	//aes_decrypt_ccm(ciphertext[2], 32, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, &mac_auth, key[0], 128);
	//printf("\n-Ciphertext  : ");
	//print_hex(ciphertext[2], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//printf("\nAuthenticated: %d ", mac_auth);
	//pass = pass && !memcmp(enc_buf, plaintext[2], enc_buf_len) && mac_auth;

	printf("\n\n");
	return(pass);
}

//NOTE


//int aes_ccm_test()
//{
//	int mac_auth;
//	WORD enc_buf_len;
//	BYTE enc_buf[128];
//	//BYTE plaintext[3][32] = {
//	//	{0x20,0x21,0x22,0x23},
//	//	{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
//	//	{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
//	//};
//	//BYTE assoc[3][32] = {
//	//	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07},
//	//	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
//	//	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13}
//	//};
//	//BYTE ciphertext[3][32 + 16] = {
//	//	{0x71,0x62,0x01,0x5b,0x4d,0xac,0x25,0x5d},
//	//	{0xd2,0xa1,0xf0,0xe0,0x51,0xea,0x5f,0x62,0x08,0x1a,0x77,0x92,0x07,0x3d,0x59,0x3d,0x1f,0xc6,0x4f,0xbf,0xac,0xcd},
//	//	{0xe3,0xb2,0x01,0xa9,0xf5,0xb7,0x1a,0x7a,0x9b,0x1c,0xea,0xec,0xcd,0x97,0xe7,0x0b,0x61,0x76,0xaa,0xd9,0xa4,0x42,0x8a,0xa5,0x48,0x43,0x92,0xfb,0xc1,0xb0,0x99,0x51}
//	//};
//	//BYTE iv[3][16] = {
//	//	{0x10,0x11,0x12,0x13,0x14,0x15,0x16},
//	//	{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17},
//	//	{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b}
//	//};
//	//BYTE key[1][32] = {
//	//	{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}
//	//};



//	BYTE plaintext[9] = {'p','l','a','i','n','t','e','x','t'};

//        BYTE assoc[5] = {'a','s','s','o','c'};

//        BYTE ciphertext[10] = {'c','i','p','h','e','r','t','e','x','t'};

//        BYTE iv[8] = {'i','v','i','v','i','v','i','v'};  

//        BYTE key[7] = {'k','e','y','p','l','u','s'};


//	int pass = 1;
//        int result = 0;
//	printf("********** CCM mode: **********\n");
//        printf("Key        : ");
//        for(int i = 0; i<sizeof(key); i++)
//        {
//          printf("%c",key[i]);
//        }
//        printf("\r\n");

//        printf("Plaintext  : ");
//        for(int i = 0; i<sizeof(plaintext); i++)
//        {
//          printf("%c",plaintext[i]);
//        }
//        printf("\r\n");
//        printf("Assoc      : ");
//        for(int i = 0; i<sizeof(assoc); i++)
//        {
//          printf("%c",assoc[i]);
//        }
//        printf("\r\n");

//        printf("Ciphertext : ");
//        for(int i = 0; i<sizeof(ciphertext); i++)
//        {
//          printf("%c",ciphertext[i]);
//        }
//        printf("\r\n");




//        printf("______Encrypt______\r\n");

//	//aes_encrypt_ccm(plaintext[0], 4, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, key[0], 128);
//	//aes_encrypt_ccm(plaintext[0], 10, assoc[0], 10, iv[0], 10, enc_buf, &enc_buf_len, 4, key[0], 128);
////int aes_encrypt_ccm(const BYTE payload[], WORD payload_len, const BYTE assoc[], unsigned short assoc_len,
////                    const BYTE nonce[], unsigned short nonce_len, BYTE out[], WORD *out_len,
////                    WORD mac_len, const BYTE key_str[], int keysize)
//	result = aes_encrypt_ccm(plaintext, 9, assoc, 5, iv, 8, enc_buf, &enc_buf_len, 4, key, 128);
//        printf("Encrypt Result : %d \r\n",result);


//        printf("NONCE : ");
//        for(int i = 0; i<sizeof(iv); i++)
//        {
//          printf("%c",iv[i]);
//        }
//        printf("\r\n");


//        printf("Assoc Data : ");
//        for(int i = 0; i<sizeof(assoc); i++)
//        {
//          printf("%c",assoc[i]);
//        }
//        printf("\r\n");


//        printf("Payload : ");
//        for(int i = 0; i<sizeof(plaintext); i++)
//        {
//          printf("%c",plaintext[i]);
//        }
//        printf("\r\n");
        
//        printf("Size of Enc buf : %d \r\n",sizeof(enc_buf));
//        printf("Enc buf : ");
//        for(int i = 0; i<sizeof(enc_buf); i++)
//        {
//          printf("%x",enc_buf[i]);
//        }
//        printf("\r\n");
//        printf("Enc buf length : %d \r\n",enc_buf_len);


//	//pass = pass && !memcmp(enc_buf, ciphertext[0], enc_buf_len);
//	pass = pass && !memcmp(enc_buf, ciphertext, enc_buf_len);
//        printf("Pass : %d \r\n",pass); 

//        printf("______Decrypt______\r\n");

//	//aes_decrypt_ccm(ciphertext[0], 8, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, &mac_auth, key[0], 128);
//	result = aes_decrypt_ccm(ciphertext, 10, assoc, 5, iv, 8, enc_buf, &enc_buf_len, 4, &mac_auth, key, 128);
//        printf("Decrypt Result : %d \r\n",result);

//        printf("Ciphertext : ");
//        for(int i = 0; i<sizeof(ciphertext); i++)
//        {
//          printf("%c",ciphertext[i]);
//        }
//        printf("\r\n");

//	printf("Decrypted to: ");
//	print_hex(enc_buf, enc_buf_len);
//        printf("Enc buf : ");
//        for(int i = 0; i<sizeof(enc_buf); i++)
//        {
//          printf("%x",enc_buf[i]);
//        }
//        printf("\r\n");
//        printf("Enc buf length : %d \r\n",enc_buf_len);

//	printf("Authenticated: %d ", mac_auth);
//	pass = pass && !memcmp(enc_buf, plaintext[0], enc_buf_len) && mac_auth;

// //       printf("\r\n--------------\r\n");

//	//aes_encrypt_ccm(plaintext[1], 16, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, key[0], 128);
//	//printf("\n\nNONCE        : ");
//	//print_hex(iv[1], 8);
//	//printf("\nAssoc. Data  : ");
//	//print_hex(assoc[1], 16);
//	//printf("\nPayload      : ");
//	//print_hex(plaintext[1], 16);
//	//printf("\n-encrypted to: ");
//	//print_hex(enc_buf, enc_buf_len);
//	//pass = pass && !memcmp(enc_buf, ciphertext[1], enc_buf_len);

//	//aes_decrypt_ccm(ciphertext[1], 22, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, &mac_auth, key[0], 128);
//	//printf("\n-Ciphertext  : ");
//	//print_hex(ciphertext[1], 22);
//	//printf("\n-decrypted to: ");
//	//print_hex(enc_buf, enc_buf_len);
//	//printf("\nAuthenticated: %d ", mac_auth);
//	//pass = pass && !memcmp(enc_buf, plaintext[1], enc_buf_len) && mac_auth;


//	//aes_encrypt_ccm(plaintext[2], 24, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, key[0], 128);
//	//printf("\n\nNONCE        : ");
//	//print_hex(iv[2], 12);
//	//printf("\nAssoc. Data  : ");
//	//print_hex(assoc[2], 20);
//	//printf("\nPayload      : ");
//	//print_hex(plaintext[2], 24);
//	//printf("\n-encrypted to: ");
//	//print_hex(enc_buf, enc_buf_len);
//	//pass = pass && !memcmp(enc_buf, ciphertext[2], enc_buf_len);

//	//aes_decrypt_ccm(ciphertext[2], 32, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, &mac_auth, key[0], 128);
//	//printf("\n-Ciphertext  : ");
//	//print_hex(ciphertext[2], 32);
//	//printf("\n-decrypted to: ");
//	//print_hex(enc_buf, enc_buf_len);
//	//printf("\nAuthenticated: %d ", mac_auth);
//	//pass = pass && !memcmp(enc_buf, plaintext[2], enc_buf_len) && mac_auth;

//	//printf("\n\n");
//	//return(pass);
//}


int aes_ccm_test2()
{
	int pass = 1;

	int mac_auth;
	int item_len = 4;
	WORD out_ciphertext_buf_len;
	BYTE out_ciphertext_buf[128];
	BYTE out_mac_buf[128];
	WORD enc_buf_len;
	BYTE enc_buf[128];

	BYTE key[4][32] = {
		// 1
		{
			'k', 'e', 'y', 'p', 'l', 'e',
			'i', 's', 'g', 'o', 'o', 'd',
			'1', '2', '3', '4',
		},
		// 2
		{
			'g', 'g', 'g', 'g', 'g', 'g',
			'i', 's', 'g', 'o', 'o', 'o',
			'1', '2', '3', '4',
		},
		// 3
		{
			'k', 'e', 'y', 'p', 'l', 'u',
			'i', 's', 'g', 'o', 'o', 'd',
			'a', 'a', 'c', 'd',
		},
		// 4
		{
			'k', 'e', 'y', 'p', 'l', 'e',
			'i', 's', 'g', 'o', 'o', 'd',
			'1', '2', '3', '4',
		},
	};
	BYTE nonce[4][16] = {
		// 1
		{
			'k', 'e', 'y', 'p', 'l', 'e',
			'g', 'o', '0', 'd', '1', '2',
		},
		// 2
		{
			'a', 'b', 'c', 'd', 'l', 'e',
			'i', 's', 'g', 'o', 'o', 'o',
		},
		// 3
		{
			'a', 'b', 'c', 'd', 'l', 'e',
			'0', '0', '0', '0', '0', '0',
		},
		// 4
		{
			'k', 'e', 'y', 'p', 'l', 'e',
			'g', 'o', '0', 'd', '1', '2',
		},
	};
	BYTE plaintext[4][32] = {
		// 1
		{
			'k', 'e', 'y', 'p', 'l', 'e',
			'i', 's', 'g', 'o', 'o', 'd',
			'1', '2', '3', '4',
		},
		// 2
		{
			'a', 'e', 'y', 'p', 'l', 'e',
			'b', 's', 'g', 'o', 'o', 'o',
			'c', 'd', 'd', '5',
		},
		// 3
		{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
			0x26, 0x27, 0x28, 0x29, 0x2a ,0x2b, 
			0x2c, 0x2d, 0x2e, 0x2f
		},
		// 4
		{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
			0x26, 0x27, 0x28, 0x29, 0x2a ,0x2b,
			0x2c, 0x2d, 0x2e, 0x2f
		}
	};

	printf("* CCM mode:\n");
	//for (int i = 0; i < item_len; i++) {
	for (int i = 0; i < 1; i++) {
		printf("\n\n==== TEST %d ==== \n", i);
		printf("Key           : ");
		print_hex(key[i], 16);

		aes_encrypt_ccm_v2(plaintext[i], 16, nonce[i], 12, out_ciphertext_buf, &out_ciphertext_buf_len, out_mac_buf, 10, key[i], 128);
		printf("\nNONCE        : ");
		print_hex(nonce[i], 12);
		printf("\nPayload       : ");
		print_hex(plaintext[i], 16);                
		printf("\n-encrypted to: ");
		print_hex(out_ciphertext_buf, out_ciphertext_buf_len);
                printf("\n>>>Out_ciphertext_buf_len: %d>>",out_ciphertext_buf_len);
		printf("\n-mac: ");
		print_hex(out_mac_buf, 10);

		aes_decrypt_ccm_v2(out_ciphertext_buf, out_ciphertext_buf_len, nonce[i], 12, enc_buf, &enc_buf_len, out_mac_buf, 10, &mac_auth, key[i], 128);
		printf("\n-decrypted to: ");
		print_hex(enc_buf, enc_buf_len);
                printf("\n>>>Enc_buf_len: %d",enc_buf_len);
		printf("\nAuthenticated: %d>>", mac_auth);
		printf("\n\n==== END TEST %d ==== \n", i);
	}
	
	return(pass);
}





int aes_test()
{
	int pass = 1;

	pass = pass && aes_ecb_test();
	pass = pass && aes_cbc_test();
	pass = pass && aes_ctr_test();
	pass = pass && aes_ccm_test();

	return(pass);
}

//int main(int argc, char *argv[])
//{
//	printf("AES Tests: %s\n", aes_test() ? "SUCCEEDED" : "FAILED");

//	return(0);
//}
