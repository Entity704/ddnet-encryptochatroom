#ifndef BASE_PCR_CRYPTO_H
#define BASE_PCR_CRYPTO_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

class CryptoUtils
{
public:
	static bool GenerateX25519KeyPair(std::vector<uint8_t> &OutPrivKey, std::vector<uint8_t> &OutPubKey);
	static bool X25519Encrypt(const std::vector<uint8_t> &ReceiverPubBytes,
		const std::vector<uint8_t> &Plaintext,
		std::vector<uint8_t> &OutPacket);
	static bool X25519Decrypt(const std::vector<uint8_t> &MyPrivBytes,
		const std::vector<uint8_t> &Packet,
		std::vector<uint8_t> &OutPlaintext);

	static bool GenerateXChaCha20Poly1305Key(std::vector<uint8_t> &OutXChaCha20Poly1305Key);
	static bool XChaCha20Poly1305Encrypt(const std::vector<uint8_t> &XChaCha20Poly1305Key,
		const std::vector<uint8_t> &Plaintext,
		std::vector<uint8_t> &OutPacket);
	static bool XChaCha20Poly1305Decrypt(const std::vector<uint8_t> &XChaCha20Poly1305Key,
		const std::vector<uint8_t> &Packet,
		std::vector<uint8_t> &OutPlaintext);

	static unsigned char *Blake2b(const unsigned char *Message, size_t MessageSize, unsigned char *OutHash);

private:
	static bool PlatformRandomBytes(uint8_t *Buf, size_t Len);
};

class Base32768
{
private:
	static uint32_t IndexToCodePoint(uint16_t Index)
	{
		if(Index < 27648)
			return 0x3400 + Index;
		else
			return 0xAC00 + (Index - 27648);
	}

	static int32_t CodePointToIndex(uint32_t Cp)
	{
		if(Cp >= 0x3400 && Cp <= 0x9FFF)
			return Cp - 0x3400;
		else if(Cp >= 0xAC00 && Cp <= 0xBFFF)
			return Cp - 0xAC00 + 27648;
		return -1;
	}

	static void AppendCodePointAsUTF8(uint32_t Cp, std::string &Out)
	{
		if(Cp <= 0x7F)
		{
			Out.push_back(static_cast<char>(Cp));
		}
		else if(Cp <= 0x7FF)
		{
			Out.push_back(static_cast<char>(0xC0 | ((Cp >> 6) & 0x1F)));
			Out.push_back(static_cast<char>(0x80 | (Cp & 0x3F)));
		}
		else if(Cp <= 0xFFFF)
		{
			Out.push_back(static_cast<char>(0xE0 | ((Cp >> 12) & 0x0F)));
			Out.push_back(static_cast<char>(0x80 | ((Cp >> 6) & 0x3F)));
			Out.push_back(static_cast<char>(0x80 | (Cp & 0x3F)));
		}
		else
		{
			Out.push_back(0xEF);
			Out.push_back(0xBF);
			Out.push_back(0xBD);
		}
	}

	static uint32_t NextUTF8CodePoint(const std::string &Str, size_t &StartIndex)
	{
		if(StartIndex >= Str.size())
			return 0;
		uint8_t C1 = Str[StartIndex++];
		if((C1 & 0x80) == 0)
			return C1;

		if((C1 & 0xE0) == 0xC0)
		{
			if(StartIndex >= Str.size())
				return 0;
			uint8_t C2 = Str[StartIndex++];
			return ((C1 & 0x1F) << 6) | (C2 & 0x3F);
		}
		else if((C1 & 0xF0) == 0xE0)
		{
			if(StartIndex + 1 >= Str.size())
				return 0;
			uint8_t C2 = Str[StartIndex++];
			uint8_t C3 = Str[StartIndex++];
			return ((C1 & 0x0F) << 12) | ((C2 & 0x3F) << 6) | (C3 & 0x3F);
		}
		return 0;
	}

public:
	static std::string Encode(const std::vector<uint8_t> &Data)
	{
		std::string Result;
		uint32_t Buffer = 0;
		int BitsLeft = 0;

		uint16_t OriginLen = static_cast<uint16_t>(Data.size());
		std::vector<uint8_t> Payload;
		Payload.push_back(static_cast<uint8_t>(OriginLen >> 8));
		Payload.push_back(static_cast<uint8_t>(OriginLen & 0xFF));
		Payload.insert(Payload.end(), Data.begin(), Data.end());

		for(uint8_t Byte : Payload)
		{
			Buffer = (Buffer << 8) | Byte;
			BitsLeft += 8;

			while(BitsLeft >= 15)
			{
				BitsLeft -= 15;
				uint16_t Index = (Buffer >> BitsLeft) & 0x7FFF;
				AppendCodePointAsUTF8(IndexToCodePoint(Index), Result);
			}
		}

		if(BitsLeft > 0)
		{
			uint16_t Index = (Buffer << (15 - BitsLeft)) & 0x7FFF;
			AppendCodePointAsUTF8(IndexToCodePoint(Index), Result);
		}

		return Result;
	}

	static std::vector<uint8_t> Decode(const std::string &Str)
	{
		std::vector<uint8_t> RawStream;
		uint32_t Buffer = 0;
		int BitsLeft = 0;
		size_t StrIndex = 0;

		while(StrIndex < Str.size())
		{
			uint32_t Cp = NextUTF8CodePoint(Str, StrIndex);
			if(Cp == 0)
				break;

			int32_t Index = CodePointToIndex(Cp);
			if(Index == -1)
				continue;

			Buffer = (Buffer << 15) | Index;
			BitsLeft += 15;

			while(BitsLeft >= 8)
			{
				BitsLeft -= 8;
				RawStream.push_back(static_cast<uint8_t>((Buffer >> BitsLeft) & 0xFF));
			}
		}

		if(RawStream.size() < 2)
			return {};

		uint16_t ExpectedLen = (static_cast<uint16_t>(RawStream[0]) << 8) | RawStream[1];

		std::vector<uint8_t> Result;
		if(RawStream.size() >= static_cast<size_t>(2 + ExpectedLen))
		{
			Result.insert(Result.end(), RawStream.begin() + 2, RawStream.begin() + 2 + ExpectedLen);
		}
		return Result;
	}
};

#endif // BASE_PCR_CRYPTO_H
