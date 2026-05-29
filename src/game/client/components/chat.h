/* (c) Magnus Auvinen. See licence.txt in the root of the distribution for more information. */
/* If you are missing that file, acquire a complete release at teeworlds.com.                */
#ifndef GAME_CLIENT_COMPONENTS_CHAT_H
#define GAME_CLIENT_COMPONENTS_CHAT_H

#include <base/str.h>
#include <base/pcr_crypto.h>

#include <engine/console.h>
#include <engine/shared/config.h>
#include <engine/shared/protocol.h>
#include <engine/shared/ringbuffer.h>

#include <generated/protocol7.h>

#include <game/client/component.h>
#include <game/client/lineinput.h>
#include <game/client/render.h>

#include <vector>
#include <map>

constexpr auto SAVES_FILE = "ddnet-saves.txt";

class CChat : public CComponent
{
	static constexpr float CHAT_HEIGHT_FULL = 200.0f;
	static constexpr float CHAT_HEIGHT_MIN = 50.0f;
	static constexpr float CHAT_FONTSIZE_WIDTH_RATIO = 2.5f;

	enum
	{
		MAX_LINES = 64,
		MAX_LINE_LENGTH = 256
	};

	CLineInputBuffered<MAX_LINE_LENGTH> m_Input;
	class CLine
	{
	public:
		CLine();
		void Reset(CChat &This);

		bool m_Initialized;
		int64_t m_Time;
		float m_aYOffset[2];
		int m_ClientId;
		int m_TeamNumber;
		bool m_Team;
		bool m_Whisper;
		int m_NameColor;
		char m_aName[64];
		char m_aText[MAX_LINE_LENGTH];
		bool m_Friend;
		bool m_Highlighted;
		std::optional<ColorRGBA> m_CustomColor;

		STextContainerIndex m_TextContainerIndex;
		int m_QuadContainerIndex;

		std::shared_ptr<CManagedTeeRenderInfo> m_pManagedTeeRenderInfo;

		float m_TextYOffset;

		int m_TimesRepeated;
	};

	bool m_PrevScoreBoardShowed;
	bool m_PrevShowChat;

	CLine m_aLines[MAX_LINES];
	int m_CurrentLine;

	enum
	{
		// client IDs for special messages
		CLIENT_MSG = -2,
		SERVER_MSG = -1,
	};

	enum
	{
		MODE_NONE = 0,
		MODE_ALL,
		MODE_TEAM,
	};

	enum
	{
		CHAT_SERVER = 0,
		CHAT_HIGHLIGHT,
		CHAT_CLIENT,
		CHAT_NUM,
	};

	int m_Mode;
	bool m_Show;
	bool m_CompletionUsed;
	int m_CompletionChosen;
	char m_aCompletionBuffer[MAX_LINE_LENGTH];
	int m_PlaceholderOffset;
	int m_PlaceholderLength;
	static char ms_aDisplayText[MAX_LINE_LENGTH];
	class CRateablePlayer
	{
	public:
		int m_ClientId;
		int m_Score;
	};
	CRateablePlayer m_aPlayerCompletionList[MAX_CLIENTS];
	int m_PlayerCompletionListLength;

	struct CCommand
	{
		char m_aName[IConsole::TEMPCMD_NAME_LENGTH];
		char m_aParams[IConsole::TEMPCMD_PARAMS_LENGTH];
		char m_aHelpText[IConsole::TEMPCMD_HELP_LENGTH];

		CCommand() = default;
		CCommand(const char *pName, const char *pParams, const char *pHelpText)
		{
			str_copy(m_aName, pName);
			str_copy(m_aParams, pParams);
			str_copy(m_aHelpText, pHelpText);
		}

		bool operator<(const CCommand &Other) const { return str_comp(m_aName, Other.m_aName) < 0; }
		bool operator<=(const CCommand &Other) const { return str_comp(m_aName, Other.m_aName) <= 0; }
		bool operator==(const CCommand &Other) const { return str_comp(m_aName, Other.m_aName) == 0; }
	};

	std::vector<CCommand> m_vServerCommands;
	bool m_ServerCommandsNeedSorting;

	struct CHistoryEntry
	{
		int m_Team;
		char m_aText[1];
	};
	CHistoryEntry *m_pHistoryEntry;
	CStaticRingBuffer<CHistoryEntry, 64 * 1024, CRingBufferBase::FLAG_RECYCLE> m_History;
	int m_PendingChatCounter;
	int64_t m_LastChatSend;
	int64_t m_aLastSoundPlayed[CHAT_NUM];
	bool m_IsInputCensored;
	char m_aCurrentInputText[MAX_LINE_LENGTH];
	bool m_EditingNewLine;

	bool m_ServerSupportsCommandInfo;

	class CPrivateChatRoom
	{
	public:
		std::vector<uint8_t> m_X25519PrivateKey;
		std::vector<uint8_t> m_X25519PublicKey;
		std::vector<uint8_t> m_AESKey;
		std::map<int, std::vector<uint8_t>> m_JoinRequests;
		int m_RequestObjectID = -1;

		bool GenerateX25519KeyPair()
		{
			m_X25519PrivateKey.clear();
			m_X25519PublicKey.clear();
			return CryptoUtils::GenerateX25519KeyPair(m_X25519PrivateKey, m_X25519PublicKey);
		}

		bool IsValidRoom() const { return !m_AESKey.empty(); }

		const std::string &GetRoomPrefix()
		{
			if(!IsValidRoom()) return EmptyPrefix;
			if(m_CachedPrefix.empty())
			{
				uint8_t Hash[32];
				CryptoUtils::CU_SHA256(m_AESKey.data(), m_AESKey.size(), Hash);
				std::vector<uint8_t> Prefix(Hash, Hash + 3);
				m_CachedPrefix = Base32768::Encode(Prefix);
			}
			return m_CachedPrefix;
		}

		void CreateNewRoom()
		{
			QuitRoom();
			m_RequestObjectID = -1;
			CryptoUtils::GenerateAESKey(m_AESKey);
		}

		void QuitRoom()
		{
			m_AESKey.clear();
			m_JoinRequests.clear();
			m_CachedPrefix.clear();
		}

		std::string EncodeMessage(const std::string &Message)
		{
			if(!IsValidRoom()) return "{eInvalid room";

			std::string truncated;
			if(Message.size() > 121)
			{
				size_t pos = 0;
				size_t remaining = 121;
				while (pos < Message.size() && remaining > 0)
				{
					unsigned char c = static_cast<unsigned char>(Message[pos]);
					size_t char_len = 1;
					if(c >= 0x80)
					{
						if((c & 0xE0) == 0xC0)
							char_len = 2;
						else if((c & 0xF0) == 0xE0)
							char_len = 3;
						else if((c & 0xF8) == 0xF0)
							char_len = 4;
					}
					if(remaining < char_len)
						break;
					remaining -= char_len;
					pos += char_len;
				}
				truncated = Message.substr(0, pos);
			}
			else
			{
				truncated = Message;
			}

			std::vector<uint8_t> CipherRaw;
			if(!CryptoUtils::AES_Encrypt(m_AESKey,
					std::vector<uint8_t>(truncated.begin(), truncated.end()),
					CipherRaw))
				return "{eEncode failed";

			std::string encoded = Base32768::Encode(CipherRaw);
			std::string result = "{m" + GetRoomPrefix() + encoded;
			return result;
		}

		std::string DecodeMessage(const std::string &RawChat)
		{
			if(!IsValidRoom()) return "{eInvalid room";
			std::string encoded = RawChat.substr(11);
			std::vector<uint8_t> Ciphertext = Base32768::Decode(encoded);
			if(Ciphertext.empty())
				return "{eEmpty message";
			std::vector<uint8_t> PlainRaw;
			if(!CryptoUtils::AES_Decrypt(m_AESKey, Ciphertext, PlainRaw))
				return "{eDecode failed";
			return std::string(PlainRaw.begin(), PlainRaw.end());
		}

		std::string EncodeJoinRequest(int ClientID)
		{
			if(ClientID < 0 || ClientID >= MAX_CLIENTS)
				return "{eInvalid client ID";

			if(m_X25519PublicKey.size() != 32)
				return "{eNo public key";

			if(m_RequestObjectID != -1 && m_RequestObjectID != ClientID)
				return "{ePending join request exists";

			m_RequestObjectID = ClientID;
			std::string cidStr = std::to_string(ClientID);
			std::string encodedPub = Base32768::Encode(m_X25519PublicKey);
			return "{j" + cidStr + encodedPub;
		}

		std::string EncodeKeyDistributionMessage(int TargetClientID)
		{
			if(!IsValidRoom())
				return "{eInvalid room";

			auto it = m_JoinRequests.find(TargetClientID);
			if(it == m_JoinRequests.end())
				return "{eNo such request";

			const std::vector<uint8_t> &peerPub = it->second;
			std::vector<uint8_t> cipher;
			if(!CryptoUtils::X25519_Encrypt(peerPub, m_AESKey, cipher))
				return "{eEncrypt failed";

			std::string encodedCipher = Base32768::Encode(cipher);
			std::string cidStr = std::to_string(TargetClientID);

			m_JoinRequests.erase(it);
			return "{k" + cidStr + encodedCipher;
		}

		void DecodeJoinRequest(const std::string &Message)
		{
			if(Message.size() < 3 || Message[0] != '{' || Message[1] != 'j')
				return;

			size_t pos = 2;
			std::string cidStr;
			while (pos < Message.size() && isdigit(static_cast<unsigned char>(Message[pos])))
				cidStr += Message[pos++];

			if(cidStr.empty())
				return;

			int clientID = std::stoi(cidStr);
			std::string encodedPub = Message.substr(pos);
			std::vector<uint8_t> pubkey = Base32768::Decode(encodedPub);
			if(pubkey.size() != 32)
				return;

			m_JoinRequests[clientID] = pubkey;
		}

	private:
		std::string m_CachedPrefix;
		static inline const std::string EmptyPrefix;
	};
	CPrivateChatRoom m_PrivChatRoom;

	static void ConSay(IConsole::IResult *pResult, void *pUserData);
	static void ConSayTeam(IConsole::IResult *pResult, void *pUserData);
	static void ConChat(IConsole::IResult *pResult, void *pUserData);
	static void ConShowChat(IConsole::IResult *pResult, void *pUserData);
	static void ConEcho(IConsole::IResult *pResult, void *pUserData);
	static void ConClearChat(IConsole::IResult *pResult, void *pUserData);

	static void ConchainChatOld(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData);
	static void ConchainChatFontSize(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData);
	static void ConchainChatWidth(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData);

	bool LineShouldHighlight(const char *pLine, const char *pName);
	void StoreSave(const char *pText);

public:
	CChat();
	int Sizeof() const override { return sizeof(*this); }

	static constexpr float MESSAGE_TEE_PADDING_RIGHT = 0.5f;

	bool IsActive() const { return m_Mode != MODE_NONE; }
	void AddLine(int ClientId, int Team, const char *pLine);
	void EnableMode(int Team);
	void DisableMode();
	void RegisterCommand(const char *pName, const char *pParams, const char *pHelpText);
	void UnregisterCommand(const char *pName);
	void Echo(const char *pString);

	void OnWindowResize() override;
	void OnConsoleInit() override;
	void OnStateChange(int NewState, int OldState) override;
	void OnRender() override;
	void OnPrepareLines(float y);
	void Reset();
	void OnRelease() override;
	void OnMessage(int MsgType, void *pRawMsg) override;
	bool OnInput(const IInput::CEvent &Event) override;
	void OnInit() override;

	void RebuildChat();
	void ClearLines();

	void EnsureCoherentFontSize() const;
	void EnsureCoherentWidth() const;

	float FontSize() const { return g_Config.m_ClChatFontSize / 10.0f; }
	float MessagePaddingX() const { return FontSize() * (5 / 6.f); }
	float MessagePaddingY() const { return FontSize() * (1 / 6.f); }
	float MessageTeeSize() const { return FontSize() * (7 / 6.f); }
	float MessageRounding() const { return FontSize() * (1 / 2.f); }

	// ----- send functions -----

	// Sends a chat message to the server.
	//
	// @param Team MODE_ALL=0 MODE_TEAM=1
	// @param pLine the chat message
	void SendChat(int Team, const char *pLine);

	// Sends a chat message to the server.
	//
	// It uses a queue with a maximum of 3 entries
	// that ensures there is a minimum delay of one second
	// between sent messages.
	//
	// It uses team or public chat depending on m_Mode.
	void SendChatQueued(const char *pLine);
};
#endif
