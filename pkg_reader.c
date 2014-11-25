/*
 * pkg_reader.c
 *
 *  Created on: 24/10/2014
 *      Author: fahrenheit
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "tools.h"
#include "little_endian.h"
#include "types.h"

#ifdef WIN32
#define MKDIR(x,y) mkdir(x)
#else
#define MKDIR(x,y) mkdir(x,y)
#endif

// keys
static u8 pspKey[16] = {
	0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
};

static u8 ps3Key[16] = {
	0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8
};

static u8 unkKey[16] = {
	0xAB, 0x5A, 0xBC, 0x9F, 0xC1, 0xF4, 0x9D, 0xE6, 0xA0, 0x51, 0xDB, 0xAE, 0xFA, 0x51, 0x88, 0x59
};

static u8 klic_ret_key[16] = {
	0xF2, 0xFB, 0xCA, 0x7A, 0x75, 0xB0, 0x4E, 0xDC, 0x13, 0x90, 0x63, 0x8C, 0xCD, 0xFD, 0xD1, 0xEE
};

// also psx
static u8 klic_dev_key[16] = {
	0x52, 0xC0, 0xB5, 0xCA, 0x76, 0xD6, 0x13, 0x4B,	0xB4, 0x5F, 0xC6, 0x6C, 0xA6, 0x37, 0xF2, 0xC1
};

static u8 klic_free_key[16] = {
	0x72, 0xF9, 0x90, 0x78, 0x8F, 0x9C, 0xFF, 0x74,	0x57, 0x25, 0xF0, 0x8E, 0x4C, 0x12, 0x83, 0x87
};

static u8 klic_minis[16] = {
	0x2A, 0x6A, 0xFB, 0xCF, 0x43, 0xD1, 0x57, 0x9F,	0x7D, 0x73, 0x87, 0x41, 0xA1, 0x3B, 0xD4, 0x2E
};

// playstation portable remasters
static u8 klic_psp_remasters[16] = {
	0x0D, 0xB8, 0x57, 0x32, 0x36, 0x6C, 0xD7, 0x34, 0xFC, 0x87, 0x9E, 0x74, 0x33, 0x43, 0xBB, 0x4F
};

static u8 klic_np[16] = {
	0x30, 0x9D, 0xEF, 0x36, 0xFE, 0xD3, 0x48, 0xA6, 0xBB, 0x06, 0xB7, 0x18, 0xDC, 0xE4, 0xFC, 0xA8
};

static u8 klic_rif_key[16] = {
	0xDA, 0x7D, 0x4B, 0x5E, 0x49, 0x9A, 0x4F, 0x53, 0xB1, 0xC1, 0xA1, 0x4A, 0x74, 0x84, 0x44, 0x3B
};

static u8 klic_dat_key[16] = {
	0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

static u8 klic_dat_riv[16] = {
	0x30, 0x32, 0xAD, 0xFC, 0xDE, 0x09, 0xCF, 0xBF, 0xF0, 0xA3, 0xB3, 0x52, 0x5B, 0x09, 0x7F, 0xAF
};

static u8 klicensee_constant[16] = {
	0x5E, 0x06, 0xE0, 0x4F, 0xD9, 0x4A, 0x71, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static u8 klic_NP_ci[16] = {
	0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B
};

static u8 klic_NP_tid[16] = {
	0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97
};


/* PSP save keys
static const u8 hash198C[16] = {0xFA, 0xAA, 0x50, 0xEC, 0x2F, 0xDE, 0x54, 0x93, 0xAD, 0x14, 0xB2, 0xCE, 0xA5, 0x30, 0x05, 0xDF};
static const u8 hash19BC[16] = {0xCB, 0x15, 0xF4, 0x07, 0xF9, 0x6A, 0x52, 0x3C, 0x04, 0xB9, 0xB2, 0xEE, 0x5C, 0x53, 0xFA, 0x86};

static const u8 key19CC[16]  = {0x70, 0x44, 0xA3, 0xAE, 0xEF, 0x5D, 0xA5, 0xF2, 0x85, 0x7F, 0xF2, 0xD6, 0x94, 0xF5, 0x36, 0x3B};
static const u8 key19DC[16]  = {0xEC, 0x6D, 0x29, 0x59, 0x26, 0x35, 0xA5, 0x7F, 0x97, 0x2A, 0x0D, 0xBC, 0xA3, 0x26, 0x33, 0x00};
static const u8 key199C[16]  = {0x36, 0xA5, 0x3E, 0xAC, 0xC5, 0x26, 0x9E, 0xA3, 0x83, 0xD9, 0xEC, 0x25, 0x6C, 0x48, 0x48, 0x72};
static const u8 key19AC[16]  = {0xD8, 0xC0, 0xB0, 0xF3, 0x3E, 0x6B, 0x76, 0x85, 0xFD, 0xFB, 0x4D, 0x7D, 0x45, 0x1E, 0x92, 0x03};
 */

static u8 *pkg = NULL;

static u8 ** keys = NULL;

void readPKG(PKG_HEADER * header){
	u32 offset=0;
	if (pkg[0] != 0x7F && pkg[1] != 0x50 && pkg[2] != 0x4B && pkg[3] != 47) {
		fprintf(stderr,"[Unknown FILE] File is not a PKG, invalid magic identifier: 0x%04X\n",be32(pkg));
		exit(1);
	}
	header->magic = be32(pkg);
	offset += sizeof(u32);
	header->pkg_revision = be16(pkg+offset);
	offset += sizeof(u16);
	header->pkg_type = be16(pkg+offset);
	offset += sizeof(u16);
	header->pkg_info_offset = be32(pkg+offset);
	offset += sizeof(u32);
	header->pkg_info_count = be32(pkg+offset);

	offset += sizeof(u32);
	header->header_size = be32(pkg+offset);
	offset += sizeof(u32);
	header->item_count = be32(pkg+offset);
	offset += sizeof(u32);
	header->total_size = be64(pkg+offset);
	offset += sizeof(u64);

	header->data_offset = be64(pkg+offset);
	offset += sizeof(u64);
	header->data_size = be64(pkg+offset);
	offset += sizeof(u64);

	memcpy(header->contentid,pkg+offset,sizeof(char)*0x30);
	offset += sizeof(char)*0x30;

	memcpy(header->digest, pkg+offset, sizeof(char)*0x10);
	offset += sizeof(char)*0x10;

	memcpy(header->pkg_data_riv, pkg+offset, sizeof(char)*0x10);
	offset += sizeof(char)*0x10;

	memcpy(header->header_cmac_hash, pkg+offset, sizeof(char)*0x10);
	offset += sizeof(char)*0x10;

	memcpy(header->header_npdrm_signature, pkg+offset, sizeof(char)*0x28);
	offset += sizeof(char)*0x28;

	memcpy(header->header_cmac_hash, pkg+offset, sizeof(char)*0x08);
	offset += sizeof(char)*0x08;

	// print information about the package

	printf("Playstation ");
	switch (header->pkg_type) {
		case PKG_TYPE_PS3: printf("3"); break;
		case PKG_TYPE_PSP: printf("Portable / Vita / TV"); break;
		default: printf("? (%d)",header->pkg_type); break;
	}
	printf(" ");
	switch (header->pkg_revision) {
		case PKG_REV_RETAIL: printf("retail"); break;
		case PKG_REV_BETA: printf("debug"); break;
		default: printf("? (%d)",header->pkg_revision); break;
	}
	printf(" package\n");
	// content id
	printf("Content ID: %s\n",header->contentid);
	printf("[INFO.OFFSET] %d\n",header->pkg_info_offset);
	printf("[INFO.COUNT] %d\n",header->pkg_info_count);
	printf("[HDR.SIZE] %u\n",header->header_size);
	printf("[HDR.COUNT] %u\n",header->item_count);
	printf("[TOTAL.SIZE] %lu\n",header->total_size);
	printf("[DATA.OFFSET] %lu\n",header->data_offset);
	printf("[DATA.SIZE] %lu\n",header->data_size);
	fflush(stdout);
}

boolean testDecrypt(PKG_HEADER * header, u8* data) {
	printf("sizeof(data) = %d, n=%d\n",sizeof(data), (sizeof(data)/sizeof(data[0])));
	fflush(stdout);
	u8 *tmp = NULL;
	PKG_FILE_HEADER file;

	file.filename_offset = be32(data);

	file.filename_size = be32(data + 0x04);
	file.data_offset = be64(data + 0x08);
	file.data_size = be64(data + 0x10);
	file.flags = be32(data + 0x18);

	if (file.filename_size > 256)
		return FALSE;
	else
		return TRUE;
}

void decryptPkgPS3(PKG_HEADER * header, u8 ** keys, int key_len) {

}

void decryptPkgPSP(PKG_HEADER * header, u8 ** keys, int key_len) {
	PKG_FILE_HEADER * files = NULL;
	u8 * key = NULL;
	u8 *tmp = NULL;
	int i;
	u8 * data = (u8 *) malloc(sizeof(u8)*header->data_size); // allocate space for data
	if (header->pkg_revision == PKG_REV_BETA) {
		key = (u8*)*pspKey;
		aes128ctr(key, header->pkg_data_riv, pkg + header->data_offset, header->data_size, data);
		if (testDecrypt(header,data) == FALSE) {
			fprintf(stderr,"Beta key is invalid for the file\n");
			return;
		}
	} else {
		boolean foundKey = FALSE;
		char * buf = NULL;
		for (i = 0; i < key_len; i++) {
			key = keys[i];
			aes128ctr(key, header->pkg_data_riv, pkg + header->data_offset, header->data_size, pkg + header->data_offset);
			if (testDecrypt(header,pkg + header->data_offset) == TRUE) {
				printf("Key[%d] is VALID for file\n",i);
				foundKey = TRUE;
				break;
			}
		}
		if (!foundKey) {
			printf("No key is valid for file, could not list files\n");
			return;
		}
	}
	files = (PKG_FILE_HEADER *) malloc(sizeof(PKG_FILE_HEADER)*header->item_count);
	for (i = 0; i < header->item_count; i++) {
		tmp = pkg + header->data_offset + i*0x20;

		PKG_FILE_HEADER file = files[i];

		file.filename_offset = be32(tmp);
		file.filename_size = be32(tmp + 0x04);
		file.data_offset = be64(tmp + 0x08);
		file.data_size = be64(tmp + 0x10);
		file.flags = be32(tmp + 0x18);

		strncpy(file.filename, (char*)(data + file.filename_offset), file.filename_size >= sizeof(file.filename) ? sizeof(file.filename) : file.filename_size); // copy up to limit

		file.flags &= 0xff;
		printf("%s (%ld bytes, flags= %08x)\n",file.filename,file.data_size,file.flags);
/*
		if (flags == 4)
			MKDIR(fname, 0777);
		else if (flags == 0 || flags == 1 || flags == 3 || flags == 14)
			memcpy_to_file(fname, pkg + file_offset, size);
		else
			fail("unknown flags: %08x", flags);
*/
	}
	fflush(stdout);
}

void decryptPkg(PKG_HEADER * header, u8 ** keys, int key_len) {
	// to decrypt a package we need a key and the associated iv
	// the iv is on the package the key needs to be provided
	if (header->pkg_type == PKG_TYPE_PS3)
		decryptPkgPSP(header,keys,key_len);
	else if (header->pkg_type == PKG_TYPE_PSP)
		decryptPkgPSP(header,keys,key_len);
}

int main(int argc, char *argv[]){
	PKG_HEADER header;
	int i;
	boolean validKey = TRUE;
	if (argc < 2)
		fprintf(stderr,"usage: %s vita_system_package.pkg [AESKEY]\n",argv[0]);
	pkg = mmap_file(argv[1]);
	readPKG(&header);
	// some basic keys + given key
	keys = (u8 **) malloc(sizeof(u8)*2*16);
	keys[0] = pspKey;
	keys[1] = ps3Key;
/*
	keys[2] = unkKey;
	keys[3] = klic_ret_key;
	keys[4] = klic_dev_key;
	keys[5] = klic_free_key;
	keys[6] = klic_minis;
	keys[7] = klic_psp_remasters;
	keys[8] = klic_np;
	keys[9] = klic_rif_key;
	keys[10] = klic_dat_key;
	keys[11] = klic_dat_riv;
	keys[12] = klicensee_constant;
	keys[13] = klic_NP_ci;
	keys[14] = klic_NP_tid;
	if (argc == 3) {
		if (strlen(argv[2]) == 16) {
			for (i = 0; i < 16; i++) {
				int c = (int)argv[2][i];
				if ((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)) {
					keys[15][i] = c;
				} else {
					validKey = FALSE;
					break;
				}
			}
		} else
			validKey = FALSE;
		if (!validKey)
			fprintf(stdout,"Invalid key: %s\n",argv[2]);
	} else
		validKey = FALSE;
*/
	decryptPkg(&header,keys,2);
	return 0;
}
