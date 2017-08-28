#include "sha1.h"

void hex_string_to_hex(const std::string &hex_str, std::string &hex)
{
	if (!hex.empty())
	{
		hex.clear();
	}

	for (size_t i = 0; i < hex_str.size(); i += 2)
	{
		int temp = 0;
		sscanf(hex_str.substr(i, 2).c_str(), "%2x", &temp);
		hex += temp;
	}
}

int sha1_compute(const char *msg, size_t len, char digest[DIGEST_LEN])
{
	std::string orig_str(msg, len);
	std::string hash_str;
	std::string hex_str;

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHmacHash = 0;
	BYTE pbHash[32] = { 0 };
	DWORD dwDataLen = sizeof(pbHash) / sizeof(pbHash[0]);

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
	{
		printf("CryptAcquireContext error: %d\n", GetLastError());
		goto EXIT;
	}

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHmacHash))
	{
		printf("CryptCreateHash error: %d\n", GetLastError());
		goto EXIT;
	}

	if (!CryptHashData(hHmacHash, (BYTE*)orig_str.c_str(), orig_str.size(), 0))
	{
		printf("CryptHashData error: %d\n", GetLastError());
		goto EXIT;
	}

	if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0))
	{
		printf("CryptGetHashParam error: %d\n", GetLastError());
		goto EXIT;
	}

	for (unsigned int i = 0; i < dwDataLen; i++)
	{
		char buff[8] = { 0 };
		sprintf_s(buff, "%02x", pbHash[i]);
		hash_str += buff;
	}

	hex_string_to_hex(hash_str, hex_str);
	memcpy(digest, hex_str.c_str(), DIGEST_LEN);

EXIT:
	if (hHmacHash)
		CryptDestroyHash(hHmacHash);
	if (hProv)
		CryptReleaseContext(hProv, 0);

	return 0;
}
