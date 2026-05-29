#include "pcr_crypto.h"

#include <engine/external/monocypher/src/monocypher.h>

// 神经，给我包含顺序调了
// clang-format off
#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#include <stddef.h>

#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <wincrypt.h>

#else
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

#ifdef __EMSCRIPTEN__
EM_JS(void, emscripten_get_random_bytes, (void* ptr, size_t len), {
    const CHUNK_SIZE = 65536;
    var heapU8 = HEAPU8;
    var byteOffset = ptr;
    var remaining = len;
    while (remaining > 0) {
        var chunk = Math.min(remaining, CHUNK_SIZE);
        var array = new Uint8Array(chunk);
        crypto.getRandomValues(array);
        for (var i = 0; i < chunk; ++i) {
            heapU8[byteOffset + i] = array[i];
        }
        byteOffset += chunk;
        remaining -= chunk;
    }
});
#endif
// clang-format on

bool CryptoUtils::PlatformRandomBytes(uint8_t *Buf, size_t Len)
{
#if defined(__EMSCRIPTEN__)
	emscripten_get_random_bytes(Buf, Len);
	return true;
#elif defined(_WIN32)
	HCRYPTPROV HProvider = 0;
	if(!CryptAcquireContextW(&HProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		return false;
	}
	bool Success = CryptGenRandom(HProvider, static_cast<DWORD>(Len), Buf);
	CryptReleaseContext(HProvider, 0);
	return Success;
#elif defined(__APPLE__)
	arc4random_buf(Buf, Len);
	return true;
#elif defined(__ANDROID__)
	int Fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if(Fd < 0)
		return false;
	size_t BytesRead = 0;
	while(BytesRead < Len)
	{
		ssize_t R = read(Fd, Buf + BytesRead, Len - BytesRead);
		if(R <= 0)
		{
			close(Fd);
			return false;
		}
		BytesRead += R;
	}
	close(Fd);
	return true;
#else
	ssize_t Ret = getrandom(Buf, Len, 0);
	if(Ret == static_cast<ssize_t>(Len))
	{
		return true;
	}

	int Fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if(Fd < 0)
	{
		return false;
	}

	size_t BytesRead = 0;
	while(BytesRead < Len)
	{
		ssize_t R = read(Fd, Buf + BytesRead, Len - BytesRead);
		if(R <= 0)
		{
			close(Fd);
			return false;
		}
		BytesRead += R;
	}
	close(Fd);
	return true;
#endif
}

bool CryptoUtils::GenerateX25519KeyPair(std::vector<uint8_t> &OutPrivKey, std::vector<uint8_t> &OutPubKey)
{
	OutPrivKey.resize(32);
	OutPubKey.resize(32);

	if(!PlatformRandomBytes(OutPrivKey.data(), 32))
	{
		return false;
	}

	crypto_x25519_public_key(OutPubKey.data(), OutPrivKey.data());
	return true;
}

bool CryptoUtils::X25519Encrypt(const std::vector<uint8_t> &ReceiverPubBytes,
	const std::vector<uint8_t> &Plaintext,
	std::vector<uint8_t> &OutPacket)
{
	if(ReceiverPubBytes.size() != 32)
	{
		return false;
	}

	std::vector<uint8_t> EphemeralPriv(32);
	std::vector<uint8_t> EphemeralPub(32);
	std::vector<uint8_t> SharedSecret(32);
	std::vector<uint8_t> ChachaKey(32);
	std::vector<uint8_t> Nonce(24);
	std::vector<uint8_t> Tag(16);
	std::vector<uint8_t> Ciphertext(Plaintext.size());

	if(!PlatformRandomBytes(EphemeralPriv.data(), 32))
	{
		return false;
	}
	crypto_x25519_public_key(EphemeralPub.data(), EphemeralPriv.data());

	crypto_x25519(SharedSecret.data(), EphemeralPriv.data(), ReceiverPubBytes.data());

	crypto_blake2b(ChachaKey.data(), 32, SharedSecret.data(), SharedSecret.size());

	if(!PlatformRandomBytes(Nonce.data(), Nonce.size()))
	{
		return false;
	}

	crypto_aead_lock(Ciphertext.data(), Tag.data(), ChachaKey.data(), Nonce.data(), nullptr, 0, Plaintext.data(), Plaintext.size());

	OutPacket.clear();
	OutPacket.insert(OutPacket.end(), EphemeralPub.begin(), EphemeralPub.end());
	OutPacket.insert(OutPacket.end(), Nonce.begin(), Nonce.end());
	OutPacket.insert(OutPacket.end(), Tag.begin(), Tag.end());
	OutPacket.insert(OutPacket.end(), Ciphertext.begin(), Ciphertext.end());

	crypto_wipe(EphemeralPriv.data(), EphemeralPriv.size());
	crypto_wipe(SharedSecret.data(), SharedSecret.size());
	crypto_wipe(ChachaKey.data(), ChachaKey.size());

	return true;
}

bool CryptoUtils::X25519Decrypt(const std::vector<uint8_t> &MyPrivBytes,
	const std::vector<uint8_t> &Packet,
	std::vector<uint8_t> &OutPlaintext)
{
	if(Packet.size() < (32 + 24 + 16) || MyPrivBytes.size() != 32)
	{
		return false;
	}

	std::vector<uint8_t> EphemeralPubBytes(Packet.begin(), Packet.begin() + 32);
	std::vector<uint8_t> Nonce(Packet.begin() + 32, Packet.begin() + 32 + 24);
	std::vector<uint8_t> Tag(Packet.begin() + 32 + 24, Packet.begin() + 32 + 24 + 16);
	std::vector<uint8_t> Ciphertext(Packet.begin() + 32 + 24 + 16, Packet.end());

	std::vector<uint8_t> SharedSecret(32);
	std::vector<uint8_t> ChachaKey(32);

	OutPlaintext.resize(Ciphertext.size());

	crypto_x25519(SharedSecret.data(), MyPrivBytes.data(), EphemeralPubBytes.data());

	crypto_blake2b(ChachaKey.data(), 32, SharedSecret.data(), SharedSecret.size());

	if(crypto_aead_unlock(OutPlaintext.data(), Tag.data(), ChachaKey.data(), Nonce.data(), nullptr, 0, Ciphertext.data(), Ciphertext.size()) != 0)
	{
		crypto_wipe(SharedSecret.data(), SharedSecret.size());
		crypto_wipe(ChachaKey.data(), ChachaKey.size());
		OutPlaintext.clear();
		return false;
	}

	crypto_wipe(SharedSecret.data(), SharedSecret.size());
	crypto_wipe(ChachaKey.data(), ChachaKey.size());
	return true;
}

bool CryptoUtils::GenerateXChaCha20Poly1305Key(std::vector<uint8_t> &OutXChaCha20Poly1305Key)
{
	OutXChaCha20Poly1305Key.resize(32);
	return PlatformRandomBytes(OutXChaCha20Poly1305Key.data(), OutXChaCha20Poly1305Key.size());
}

bool CryptoUtils::XChaCha20Poly1305Encrypt(const std::vector<uint8_t> &XChaCha20Poly1305Key,
	const std::vector<uint8_t> &Plaintext,
	std::vector<uint8_t> &OutPacket)
{
	if(XChaCha20Poly1305Key.size() != 32)
	{
		return false;
	}

	std::vector<uint8_t> Nonce(24);
	std::vector<uint8_t> Tag(16);
	std::vector<uint8_t> Ciphertext(Plaintext.size());

	if(!PlatformRandomBytes(Nonce.data(), Nonce.size()))
	{
		return false;
	}

	crypto_aead_lock(Ciphertext.data(), Tag.data(), XChaCha20Poly1305Key.data(), Nonce.data(), nullptr, 0, Plaintext.data(), Plaintext.size());

	OutPacket.clear();
	OutPacket.insert(OutPacket.end(), Nonce.begin(), Nonce.end());
	OutPacket.insert(OutPacket.end(), Tag.begin(), Tag.end());
	OutPacket.insert(OutPacket.end(), Ciphertext.begin(), Ciphertext.end());
	return true;
}

bool CryptoUtils::XChaCha20Poly1305Decrypt(const std::vector<uint8_t> &XChaCha20Poly1305Key,
	const std::vector<uint8_t> &Packet,
	std::vector<uint8_t> &OutPlaintext)
{
	if(Packet.size() < (24 + 16) || XChaCha20Poly1305Key.size() != 32)
	{
		return false;
	}

	std::vector<uint8_t> Nonce(Packet.begin(), Packet.begin() + 24);
	std::vector<uint8_t> Tag(Packet.begin() + 24, Packet.begin() + 24 + 16);
	std::vector<uint8_t> Ciphertext(Packet.begin() + 24 + 16, Packet.end());

	OutPlaintext.resize(Ciphertext.size());

	if(crypto_aead_unlock(OutPlaintext.data(), Tag.data(), XChaCha20Poly1305Key.data(), Nonce.data(), nullptr, 0, Ciphertext.data(), Ciphertext.size()) != 0)
	{
		OutPlaintext.clear();
		return false;
	}

	return true;
}

unsigned char *CryptoUtils::Blake2b(const unsigned char *Message, size_t MessageSize, unsigned char *OutHash)
{
	crypto_blake2b(OutHash, 32, Message, MessageSize);
	return OutHash;
}
