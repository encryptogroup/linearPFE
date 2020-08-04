/**
 \file 		yaosharing.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Yao Sharing class implementation.
 */

#include "yaosharing.h"
#include <iomanip>
#include <openssl/sha.h>


void YaoSharing::Init() {
	/* init the class for correctly sized Yao key operations*/
	InitYaoKey(&m_pKeyOps, m_cCrypto->get_seclvl().symbits);

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext, m_cCircuitFileDir);

	m_bZeroBuf = (BYTE*) calloc(m_nSecParamBytes, sizeof(BYTE));
	m_bTempKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_nGarbledTableCtr = 0;

	m_bResKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);
	m_kGarble = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	m_cCrypto->init_aes_key(m_kGarble, (uint8_t*) m_vFixedKeyAESSeed);

	m_nSecParamIters = ceil_divide(m_nSecParamBytes, sizeof(UGATE_T));

#ifdef KM11_GARBLING
	m_nDJNBytes = ceil_divide(m_cCrypto->get_seclvl().ifcbits, 8);
	m_nWireKeyBytes = m_nSecParamBytes; // the length of the randomly chosen wirekeys (e.g. 16 Bytes)
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	m_nCiphertextSize = 2 * m_nDJNBytes + 1; // encrypted plaintext might be twice as large as m_nDJNBytes
	assert(m_nWireKeyBytes < m_nDJNBytes); // m_nDJNBytes must be greater than m_nSecParamBytes (requirement of djn_encrypt)
	mpz_init(m_zWireKeyMaxValue);
	mpz_ui_pow_ui(m_zWireKeyMaxValue, 2, 128);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	m_cPKCrypto = m_cCrypto->gen_field(ECC_FIELD);
	m_nCiphertextSize = m_cPKCrypto->fe_byte_size();
#endif
#endif
}

YaoSharing::~YaoSharing() {
	delete m_pKeyOps;
	delete m_cBoolCircuit;
	free(m_bZeroBuf);
	free(m_bTempKeyBuf);
	free(m_bResKeyBuf);
	m_cCrypto->clean_aes_key(m_kGarble);
	free(m_kGarble);
}

#define AES_BLOCK_SIZE 32

// symmectric encrytion function (AES encrytion using key as the seed for the AES key)
void YaoSharing::sEnc(BYTE* c, BYTE* p, uint32_t p_len, BYTE* key, uint32_t key_len, uint32_t gateid)
{
	int nrounds = 1000; // rounds of key material hashing
	unsigned char evp_key_and_iv[32];

	BYTE bytesToKey[key_len + 4];
	memcpy(bytesToKey, key, key_len);
	memcpy(bytesToKey + key_len, reinterpret_cast<BYTE*>(&gateid), 4);

	int success = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(bytesToKey), key_len + 4,
			  NULL, 0, nrounds,
			  EVP_sha256(),
			  32, evp_key_and_iv);
	assert(success == 1);

	EVP_CIPHER_CTX* enc_ctx;
	enc_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(enc_ctx);
	EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, evp_key_and_iv, &evp_key_and_iv[16]);

	// encrypt counter to get (p_len bytes + 40 bits) of encrypted data (will later be XORed with plaintext)
	uint32_t num_AES_blocks = (p_len + AES_BYTES - 1) / AES_BYTES; // ceil(plen/AES_BYTES)
	BYTE tmpCipherBlock[16];
	BYTE block_cipher[num_AES_blocks * AES_BYTES];

	int block_cipher_len;
	for(uint32_t counter = 0; counter < num_AES_blocks; counter++) {
		memset(&tmpCipherBlock, counter, AES_BYTES);
		EVP_EncryptUpdate(enc_ctx, block_cipher + counter * AES_BYTES, &block_cipher_len, tmpCipherBlock, AES_BYTES);
	}
	EVP_CIPHER_CTX_free(enc_ctx);

	// ----- ----- -----

	if (p_len == 16 + m_nPADDING_BYTES) {
		// XOR (16 + PADDING_BYTES) BYTES
		((uint64_t*) c)[0] = ((uint64_t*) block_cipher)[0] ^ ((uint64_t*) p)[0]; //  0- 7
		((uint64_t*) c)[1] = ((uint64_t*) block_cipher)[1] ^ ((uint64_t*) p)[1]; //  8-15
		((uint32_t*) c)[4] = ((uint32_t*) block_cipher)[4] ^ ((uint32_t*) p)[4]; // 16-19
		((uint8_t*) c)[20] = ((uint8_t*) block_cipher)[20] ^ ((uint8_t*) p)[20]; // 20-20
	} else if (p_len == 33 + m_nPADDING_BYTES) {
		// XOR (33 + PADDING_BYTES) BYTES
		((uint64_t*) (c))[0]  = ((uint64_t*) block_cipher)[0]  ^ ((uint64_t*) p)[0]; //  0- 7
		((uint64_t*) (c))[1]  = ((uint64_t*) block_cipher)[1]  ^ ((uint64_t*) p)[1]; //  8-15
		((uint64_t*) (c))[2]  = ((uint64_t*) block_cipher)[2]  ^ ((uint64_t*) p)[2]; // 16-23
		((uint64_t*) (c))[3]  = ((uint64_t*) block_cipher)[3]  ^ ((uint64_t*) p)[3]; // 24-31
		((uint32_t*) (c))[8]  = ((uint32_t*) block_cipher)[8]  ^ ((uint32_t*) p)[8]; // 32-35
		((uint16_t*) (c))[18] = ((uint16_t*) block_cipher)[18] ^ ((uint16_t*) p)[18]; // 36-37
	} else {
		std::cerr << "sEnc not implemented for p_len (= " << p_len << ") not in {16,33}!" << std::endl;
		std::exit(1);
	}
}

bool YaoSharing::sDec(BYTE* p, uint32_t p_len, BYTE* table, BYTE* key, uint32_t key_len, uint32_t gateid)
{
	int nrounds = 1000; // rounds of key material hashing
	unsigned char evp_key_and_iv[32];

	BYTE bytesToKey[key_len + 4];
	memcpy(bytesToKey, key, key_len);
	memcpy(bytesToKey + key_len, reinterpret_cast<BYTE*>(&gateid), 4);

	PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(bytesToKey), key_len + 4,
			  NULL, 0, nrounds,
			  EVP_sha256(),
			  32, evp_key_and_iv);

	EVP_CIPHER_CTX* enc_ctx;
	enc_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(enc_ctx);
	EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, evp_key_and_iv, &evp_key_and_iv[16]);

	// encrypt counter to get (p_len bytes + 40 bits) of encrypted data (will later be XORed with plaintext)
	uint32_t num_AES_blocks = (p_len + m_nPADDING_BYTES + AES_BYTES - 1) / AES_BYTES; // ceil(plen/AES_BYTES)
	BYTE tmpCipherBlock[16];
	BYTE block_cipher[num_AES_blocks * AES_BYTES];

	int block_cipher_len;
	for(uint32_t counter = 0; counter < num_AES_blocks; counter++) {
		memset(&tmpCipherBlock, counter, AES_BYTES);
		EVP_EncryptUpdate(enc_ctx, block_cipher + counter * AES_BYTES, &block_cipher_len, tmpCipherBlock, AES_BYTES);
	}
	EVP_CIPHER_CTX_free(enc_ctx);

	// ----- ----- -----

	BOOL valid;
	for(int i = 0; i < 4; i++) {
		valid = memcmp(table + i * (p_len + m_nPADDING_BYTES) + p_len, block_cipher + p_len, 5) == 0;
		if (valid) {
			if (p_len == 16) {
				m_pKeyOps->XOR(p, block_cipher, table + i * (p_len + m_nPADDING_BYTES));
			} else if (p_len == 33) {
				m_pKeyOps->XOR33(p, block_cipher, table + i * (p_len + m_nPADDING_BYTES));
			} else {
				std::cerr << "sDec not implemented for p_len (= " << p_len << ") not in {16,33}!" << std::endl;
				std::exit(1);
			}
			break;
		} else if (i == 3) {
			return 0;
		}
	}
	return 1;
}

BOOL YaoSharing::EncryptWire(BYTE* c, BYTE* p, uint32_t id)
{
	memset(m_bTempKeyBuf, 0, AES_BYTES);
	memcpy(m_bTempKeyBuf, (BYTE*) (&id), sizeof(uint32_t));
	m_pKeyOps->XOR_DOUBLE_B(m_bTempKeyBuf, m_bTempKeyBuf, p);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, p);
	m_cCrypto->encrypt(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf, AES_BYTES);

	m_pKeyOps->XOR(c, m_bResKeyBuf, m_bTempKeyBuf);


#ifdef DEBUGYAO
	std::cout << std::endl << " encrypting : ";
	PrintKey(p);
	std::cout << " to : ";
	PrintKey(c);
#endif

	return true;
}

BOOL YaoSharing::EncryptWireGRR3(BYTE* c, BYTE* p, BYTE* l, BYTE* r, uint32_t id)
{
	//cout << "Start with c = " << (unsigned long) c << ", p = " << (unsigned long) p << endl;
	memset(m_bTempKeyBuf, 0, AES_BYTES);
	memcpy(m_bTempKeyBuf, (BYTE*) (&id), sizeof(uint32_t));
	//cout << "XOR left" << endl;
	m_pKeyOps->XOR_DOUBLE_B(m_bTempKeyBuf, m_bTempKeyBuf, l);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, l);//todo, this is a circular leftshift of l by one and an XOR
	//cout << "XOR right " << endl;
	m_pKeyOps->XOR_QUAD_B(m_bTempKeyBuf, m_bTempKeyBuf, r);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, r);//todo, this is a circular leftshift of r by two and an XOR

	//MPC_AES_ENCRYPT(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf);
	m_cCrypto->encrypt(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf, AES_BYTES);

	//cout << "XOR reskeybuf" << endl;
	m_pKeyOps->XOR(m_bResKeyBuf, m_bResKeyBuf, m_bTempKeyBuf);
	//cout << "Final XOR with c = " << (unsigned long) c << ", p = " << (unsigned long) p << endl;
	m_pKeyOps->XOR(c, m_bResKeyBuf, p);


#ifdef DEBUGYAO
	cout << endl << " encrypting : ";
	PrintKey(p);
	cout << " using: ";
	PrintKey(l);
	cout << " and : ";
	PrintKey(r);
	cout << " to : ";
	PrintKey(c);
#endif

	return true;
}


void YaoSharing::PrintKey(BYTE* key) {
	for (uint32_t i = 0; i < m_nSecParamBytes; i++) {
		std::cout << std::setw(2) << std::setfill('0') << (std::hex) << (uint32_t) key[i];
	}
	std::cout << (std::dec);
}

void YaoSharing::PrintPerformanceStatistics() {
	std::cout <<  get_sharing_name(m_eContext) << ": ANDs: " << m_nANDGates << " ; Depth: " << GetMaxCommunicationRounds() << std::endl;
}
