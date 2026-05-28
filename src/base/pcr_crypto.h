#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

class CryptoUtils
{
public:
	static bool GenerateX25519KeyPair(std::vector<uint8_t> &out_priv_key, std::vector<uint8_t> &out_pub_key);
	static bool X25519_Encrypt(const std::vector<uint8_t> &receiver_pub_bytes,
		const std::vector<uint8_t> &plaintext,
		std::vector<uint8_t> &out_packet);
	static bool X25519_Decrypt(const std::vector<uint8_t> &my_priv_bytes,
		const std::vector<uint8_t> &packet,
		std::vector<uint8_t> &out_plaintext);

	static bool GenerateAESKey(std::vector<uint8_t> &out_aes_key);
	static bool AES_Encrypt(const std::vector<uint8_t> &aes_key,
		const std::vector<uint8_t> &plaintext,
		std::vector<uint8_t> &out_packet);
	static bool AES_Decrypt(const std::vector<uint8_t> &aes_key,
		const std::vector<uint8_t> &packet,
		std::vector<uint8_t> &out_plaintext);

	static unsigned char *CU_SHA256(const unsigned char *d, size_t n, unsigned char *md);
};

class Base32768
{
private:
	static uint32_t IndexToCodePoint(uint16_t index)
	{
		if(index < 27648)
			return 0x3400 + index;
		else
			return 0xAC00 + (index - 27648);
	}

	static int32_t CodePointToIndex(uint32_t cp)
	{
		if(cp >= 0x3400 && cp <= 0x9FFF)
			return cp - 0x3400;
		else if(cp >= 0xAC00 && cp <= 0xBFFF)
			return cp - 0xAC00 + 27648;
		return -1;
	}

	static void AppendCodePointAsUTF8(uint32_t cp, std::string &out)
	{
		if(cp <= 0x7F)
		{
			out.push_back(static_cast<char>(cp));
		}
		else if(cp <= 0x7FF)
		{
			out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
			out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
		}
		else if(cp <= 0xFFFF)
		{
			out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
			out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
			out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
		}
		else
		{
			out.push_back(0xEF);
			out.push_back(0xBF);
			out.push_back(0xBD);
		}
	}

	static uint32_t NextUTF8CodePoint(const std::string &str, size_t &start_idx)
	{
		if(start_idx >= str.size())
			return 0;
		uint8_t c1 = str[start_idx++];
		if((c1 & 0x80) == 0)
			return c1;

		if((c1 & 0xE0) == 0xC0)
		{
			if(start_idx >= str.size())
				return 0;
			uint8_t c2 = str[start_idx++];
			return ((c1 & 0x1F) << 6) | (c2 & 0x3F);
		}
		else if((c1 & 0xF0) == 0xE0)
		{
			if(start_idx + 1 >= str.size())
				return 0;
			uint8_t c2 = str[start_idx++];
			uint8_t c3 = str[start_idx++];
			return ((c1 & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
		}
		return 0;
	}

public:
	static std::string Encode(const std::vector<uint8_t> &data)
	{
		std::string result;
		uint32_t buffer = 0;
		int bits_left = 0;

		uint16_t origin_len = static_cast<uint16_t>(data.size());
		std::vector<uint8_t> payload;
		payload.push_back(static_cast<uint8_t>(origin_len >> 8));
		payload.push_back(static_cast<uint8_t>(origin_len & 0xFF));
		payload.insert(payload.end(), data.begin(), data.end());

		for(uint8_t byte : payload)
		{
			buffer = (buffer << 8) | byte;
			bits_left += 8;

			while(bits_left >= 15)
			{
				bits_left -= 15;
				uint16_t index = (buffer >> bits_left) & 0x7FFF;
				AppendCodePointAsUTF8(IndexToCodePoint(index), result);
			}
		}

		if(bits_left > 0)
		{
			uint16_t index = (buffer << (15 - bits_left)) & 0x7FFF;
			AppendCodePointAsUTF8(IndexToCodePoint(index), result);
		}

		return result;
	}

	static std::vector<uint8_t> Decode(const std::string &str)
	{
		std::vector<uint8_t> raw_stream;
		uint32_t buffer = 0;
		int bits_left = 0;
		size_t str_idx = 0;

		while(str_idx < str.size())
		{
			uint32_t cp = NextUTF8CodePoint(str, str_idx);
			if(cp == 0)
				break;

			int32_t index = CodePointToIndex(cp);
			if(index == -1)
				continue;

			buffer = (buffer << 15) | index;
			bits_left += 15;

			while(bits_left >= 8)
			{
				bits_left -= 8;
				raw_stream.push_back(static_cast<uint8_t>((buffer >> bits_left) & 0xFF));
			}
		}

		if(raw_stream.size() < 2)
			return {};

		uint16_t expected_len = (static_cast<uint16_t>(raw_stream[0]) << 8) | raw_stream[1];

		std::vector<uint8_t> result;
		if(raw_stream.size() >= static_cast<size_t>(2 + expected_len))
		{
			result.insert(result.end(), raw_stream.begin() + 2, raw_stream.begin() + 2 + expected_len);
		}
		return result;
	}
};
