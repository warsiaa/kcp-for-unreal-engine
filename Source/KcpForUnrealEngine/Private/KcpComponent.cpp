#include "KcpComponent.h"

#include "Sockets.h"
#include "SocketSubsystem.h"
#include "IPAddress.h"
#include "Kcp/ikcp.h"
#include "Misc/SecureHash.h"
#include "Runtime/Launch/Resources/Version.h"

#include "Misc/AES.h"
#include "Logging/LogMacros.h"
#include "Containers/StringConv.h"

DEFINE_LOG_CATEGORY_STATIC(LogKcpComponent, Log, All);

namespace
{
#if UE_VERSION_OLDER_THAN(5, 3, 0)
    bool EncryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        FAES::EncryptData(Data.GetData(), Data.Num(), DerivedKey.GetData());
        return true;
    }

    bool DecryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        FAES::DecryptData(Data.GetData(), Data.Num(), DerivedKey.GetData());
        return true;
    }
#else
    FAES::FAESKey BuildAesKey(const TArray<uint8>& DerivedKey)
    {
        FAES::FAESKey AesKey;
        AesKey.Set(DerivedKey.GetData());
        return AesKey;
    }

    bool EncryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        const FAES::FAESKey AesKey = BuildAesKey(DerivedKey);
        const uint64 DataSize = static_cast<uint64>(Data.Num());
        return FAES::EncryptData(Data.GetData(), DataSize, AesKey);
    }

    bool DecryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        const FAES::FAESKey AesKey = BuildAesKey(DerivedKey);
        const uint64 DataSize = static_cast<uint64>(Data.Num());
        return FAES::DecryptData(Data.GetData(), DataSize, AesKey);
    }
#endif

    int32 KcpOutputCallback(const char* Buf, int32 Len, struct IKCPCB* Kcp, void* User)
    {
        if (!User || Len <= 0)
        {
            return 0;
        }

        UKcpComponent* Component = static_cast<UKcpComponent*>(User);
        if (!Component->IsConnected())
        {
            return 0;
        }

        FSocket* Socket = Component->GetSocket();
        const TSharedPtr<FInternetAddr>& RemoteAddr = Component->GetRemoteAddr();
        if (!Socket || !RemoteAddr.IsValid())
        {
            return 0;
        }

        int32 BytesSent = 0;
        Socket->SendTo(reinterpret_cast<const uint8*>(Buf), Len, BytesSent, *RemoteAddr);
        UE_LOG(LogKcpComponent, Verbose, TEXT("KCP sent %d bytes"), BytesSent);
        return 0;
    }

#if UE_VERSION_OLDER_THAN(5, 3, 0)
    void HashSha256(const void* Data, int32 Length, uint8 Out[32])
    {
        FSHA256::HashBuffer(Data, Length, Out);
    }
#else
    namespace Sha256
    {
        constexpr uint32 BlockSize = 64;

        struct FContext
        {
            uint8 Data[BlockSize];
            uint32 DataLength = 0;
            uint64 BitLength = 0;
            uint32 State[8] = {0};
        };

        constexpr uint32 K[64] =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        FORCEINLINE uint32 RotateRight(uint32 Value, uint32 Count)
        {
            return (Value >> Count) | (Value << (32 - Count));
        }

        FORCEINLINE uint32 Choose(uint32 E, uint32 F, uint32 G)
        {
            return (E & F) ^ (~E & G);
        }

        FORCEINLINE uint32 Majority(uint32 A, uint32 B, uint32 C)
        {
            return (A & B) ^ (A & C) ^ (B & C);
        }

        FORCEINLINE uint32 Sigma0(uint32 X)
        {
            return RotateRight(X, 2) ^ RotateRight(X, 13) ^ RotateRight(X, 22);
        }

        FORCEINLINE uint32 Sigma1(uint32 X)
        {
            return RotateRight(X, 6) ^ RotateRight(X, 11) ^ RotateRight(X, 25);
        }

        FORCEINLINE uint32 Gamma0(uint32 X)
        {
            return RotateRight(X, 7) ^ RotateRight(X, 18) ^ (X >> 3);
        }

        FORCEINLINE uint32 Gamma1(uint32 X)
        {
            return RotateRight(X, 17) ^ RotateRight(X, 19) ^ (X >> 10);
        }

        void Transform(FContext& Context, const uint8* Chunk)
        {
            uint32 Message[64];

            for (int32 Index = 0, Offset = 0; Index < 16; ++Index, Offset += 4)
            {
                Message[Index] = (static_cast<uint32>(Chunk[Offset]) << 24) |
                    (static_cast<uint32>(Chunk[Offset + 1]) << 16) |
                    (static_cast<uint32>(Chunk[Offset + 2]) << 8) |
                    (static_cast<uint32>(Chunk[Offset + 3]));
            }

            for (int32 Index = 16; Index < 64; ++Index)
            {
                Message[Index] = Gamma1(Message[Index - 2]) + Message[Index - 7] + Gamma0(Message[Index - 15]) + Message[Index - 16];
            }

            uint32 A = Context.State[0];
            uint32 B = Context.State[1];
            uint32 C = Context.State[2];
            uint32 D = Context.State[3];
            uint32 E = Context.State[4];
            uint32 F = Context.State[5];
            uint32 G = Context.State[6];
            uint32 H = Context.State[7];

            for (int32 Index = 0; Index < 64; ++Index)
            {
                const uint32 Temp1 = H + Sigma1(E) + Choose(E, F, G) + K[Index] + Message[Index];
                const uint32 Temp2 = Sigma0(A) + Majority(A, B, C);
                H = G;
                G = F;
                F = E;
                E = D + Temp1;
                D = C;
                C = B;
                B = A;
                A = Temp1 + Temp2;
            }

            Context.State[0] += A;
            Context.State[1] += B;
            Context.State[2] += C;
            Context.State[3] += D;
            Context.State[4] += E;
            Context.State[5] += F;
            Context.State[6] += G;
            Context.State[7] += H;
        }

        void Initialize(FContext& Context)
        {
            Context.DataLength = 0;
            Context.BitLength = 0;
            Context.State[0] = 0x6a09e667;
            Context.State[1] = 0xbb67ae85;
            Context.State[2] = 0x3c6ef372;
            Context.State[3] = 0xa54ff53a;
            Context.State[4] = 0x510e527f;
            Context.State[5] = 0x9b05688c;
            Context.State[6] = 0x1f83d9ab;
            Context.State[7] = 0x5be0cd19;
        }

        void Update(FContext& Context, const uint8* Data, int32 Length)
        {
            for (int32 Index = 0; Index < Length; ++Index)
            {
                Context.Data[Context.DataLength] = Data[Index];
                ++Context.DataLength;

                if (Context.DataLength == BlockSize)
                {
                    Transform(Context, Context.Data);
                    Context.BitLength += BlockSize * 8ull;
                    Context.DataLength = 0;
                }
            }
        }

        void Final(FContext& Context, uint8 Out[32])
        {
            uint32 Index = Context.DataLength;

            Context.Data[Index++] = 0x80;

            if (Index > BlockSize - 8)
            {
                FMemory::Memset(Context.Data + Index, 0, BlockSize - Index);
                Transform(Context, Context.Data);
                Index = 0;
            }

            FMemory::Memset(Context.Data + Index, 0, BlockSize - 8 - Index);
            Context.BitLength += static_cast<uint64>(Context.DataLength) * 8ull;

            Context.Data[63] = static_cast<uint8>(Context.BitLength);
            Context.Data[62] = static_cast<uint8>(Context.BitLength >> 8);
            Context.Data[61] = static_cast<uint8>(Context.BitLength >> 16);
            Context.Data[60] = static_cast<uint8>(Context.BitLength >> 24);
            Context.Data[59] = static_cast<uint8>(Context.BitLength >> 32);
            Context.Data[58] = static_cast<uint8>(Context.BitLength >> 40);
            Context.Data[57] = static_cast<uint8>(Context.BitLength >> 48);
            Context.Data[56] = static_cast<uint8>(Context.BitLength >> 56);

            Transform(Context, Context.Data);

            for (int32 StateIndex = 0; StateIndex < 8; ++StateIndex)
            {
                Out[StateIndex * 4] = static_cast<uint8>((Context.State[StateIndex] >> 24) & 0xff);
                Out[StateIndex * 4 + 1] = static_cast<uint8>((Context.State[StateIndex] >> 16) & 0xff);
                Out[StateIndex * 4 + 2] = static_cast<uint8>((Context.State[StateIndex] >> 8) & 0xff);
                Out[StateIndex * 4 + 3] = static_cast<uint8>(Context.State[StateIndex] & 0xff);
            }
        }
    }

    void HashSha256(const void* Data, int32 Length, uint8 Out[32])
    {
        Sha256::FContext Context;
        Sha256::Initialize(Context);
        Sha256::Update(Context, static_cast<const uint8*>(Data), Length);
        Sha256::Final(Context, Out);
    }
#endif
}

UKcpComponent::UKcpComponent()
{
    PrimaryComponentTick.bCanEverTick = true;
}

void UKcpComponent::BeginPlay()
{
    Super::BeginPlay();
}

void UKcpComponent::EndPlay(const EEndPlayReason::Type EndPlayReason)
{
    Disconnect();
    Super::EndPlay(EndPlayReason);
}

bool UKcpComponent::Connect(const FString& RemoteIp, int32 RemotePort, int32 LocalPort, int32 ConversationId)
{
    Disconnect();

    bConnectSuccess = false;

    bSendPacketSuccess = false;

    UE_LOG(LogKcpComponent, Log, TEXT("Starting KCP connect to %s:%d (local port %d, conv %d)"), *RemoteIp, RemotePort, LocalPort, ConversationId);

    ISocketSubsystem* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
    if (!SocketSubsystem)
    {
        bConnectSuccess = false;
        UE_LOG(LogKcpComponent, Error, TEXT("Socket subsystem missing"));
        return false;
    }

    Socket = SocketSubsystem->CreateSocket(NAME_DGram, TEXT("KCP"), false);
    if (!Socket)
    {
        bConnectSuccess = false;
        UE_LOG(LogKcpComponent, Error, TEXT("Failed to create UDP socket"));
        return false;
    }

    Socket->SetNonBlocking(true);
    Socket->SetReuseAddr(true);
    Socket->SetBroadcast(false);

    TSharedRef<FInternetAddr> LocalAddr = SocketSubsystem->CreateInternetAddr();
    LocalAddr->SetAnyAddress();
    LocalAddr->SetPort(LocalPort);
    if (!Socket->Bind(*LocalAddr))
    {
        bConnectSuccess = false;
        ShutdownSocket();
        UE_LOG(LogKcpComponent, Error, TEXT("Failed to bind local port %d"), LocalPort);
        return false;
    }

    bool bIsValid = false;
    RemoteAddr = SocketSubsystem->CreateInternetAddr();
    RemoteAddr->SetIp(*RemoteIp, bIsValid);
    RemoteAddr->SetPort(RemotePort);
    if (!bIsValid)
    {
        bConnectSuccess = false;
        ShutdownSocket();
        UE_LOG(LogKcpComponent, Error, TEXT("Remote IP %s is not valid"), *RemoteIp);
        return false;
    }

    CurrentConversationId = ConversationId;
    Kcp = ikcp_create(CurrentConversationId, this);
    if (!Kcp)
    {
        bConnectSuccess = false;
        ShutdownSocket();
        UE_LOG(LogKcpComponent, Error, TEXT("Failed to create KCP control block"));
        return false;
    }

    ikcp_setoutput(Kcp, KcpOutputCallback);
    ikcp_wndsize(Kcp, Settings.SendWindowSize, Settings.ReceiveWindowSize);
    ikcp_nodelay(Kcp, Settings.bNoDelay ? 1 : 0, Settings.IntervalMs, Settings.FastResend, Settings.bDisableCongestionControl ? 1 : 0);

    RebuildEncryptionKey();
    UE_LOG(LogKcpComponent, Log, TEXT("KCP configured (wnd %d/%d, nodelay %s, interval %dms, fastresend %d, no-congestion %s, encryption %s)"),
        Settings.SendWindowSize, Settings.ReceiveWindowSize, Settings.bNoDelay ? TEXT("on") : TEXT("off"), Settings.IntervalMs,
        Settings.FastResend, Settings.bDisableCongestionControl ? TEXT("on") : TEXT("off"),
        Settings.bEnableEncryption ? TEXT("on") : TEXT("off"));

    bConnected = true;
    bConnectSuccess = true;
    UE_LOG(LogKcpComponent, Log, TEXT("KCP connected"));
    return true;
}

void UKcpComponent::Disconnect()
{
    bConnected = false;
    bConnectSuccess = false;
    bSendPacketSuccess = false;

    UE_LOG(LogKcpComponent, Log, TEXT("KCP disconnect requested"));

    if (Kcp)
    {
        ikcp_release(Kcp);
        Kcp = nullptr;
        UE_LOG(LogKcpComponent, Verbose, TEXT("KCP control block released"));
    }

    ShutdownSocket();
    RemoteAddr.Reset();
}

bool UKcpComponent::SendMessage(const TArray<uint8>& Data)
{
    bSendPacketSuccess = false;

    if (!bConnected || !Kcp)
    {
        UE_LOG(LogKcpComponent, Warning, TEXT("SendMessage called while not connected"));
        return false;
    }

    if (Data.Num() == 0)
    {
        UE_LOG(LogKcpComponent, Warning, TEXT("SendMessage called with empty payload"));
        return false;
    }

    const TArray<uint8>* PayloadToSend = &Data;
    TArray<uint8> EncryptedPayload;
    if (Settings.bEnableEncryption)
    {
        if (!EncryptBuffer(Data, EncryptedPayload))
        {
            UE_LOG(LogKcpComponent, Error, TEXT("Failed to encrypt payload"));
            return false;
        }
        PayloadToSend = &EncryptedPayload;
    }

    int32 Result = ikcp_send(Kcp, reinterpret_cast<const char*>(PayloadToSend->GetData()), PayloadToSend->Num());
    bSendPacketSuccess = Result == 0;
    UE_LOG(LogKcpComponent, Log, TEXT("SendMessage result: %s (bytes %d)"), bSendPacketSuccess ? TEXT("success") : TEXT("fail"), PayloadToSend->Num());
    return bSendPacketSuccess;
}

TArray<uint8> UKcpComponent::BuildPacket(const FString& TextPayload, const TArray<uint8>& ExtraBytes)
{
    TArray<uint8> Output;

    FTCHARToUTF8 Converter(*TextPayload);
    Output.Append(reinterpret_cast<const uint8*>(Converter.Get()), Converter.Length());
    Output.Append(ExtraBytes);

    return Output;
}

bool UKcpComponent::IsConnected() const
{
    return bConnected;
}

void UKcpComponent::TickComponent(float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction)
{
    Super::TickComponent(DeltaTime, TickType, ThisTickFunction);

    if (!bConnected || !Kcp || !Socket)
    {
        return;
    }

    FlushIncoming();

    const uint32 CurrentMs = GetMs();
    ikcp_update(Kcp, CurrentMs);

    FlushKcpReceive();
}

void UKcpComponent::ShutdownSocket()
{
    if (Socket)
    {
        Socket->Close();
        ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(Socket);
        Socket = nullptr;
    }
}

void UKcpComponent::FlushIncoming()
{
    if (!Socket || !Kcp)
    {
        return;
    }

    uint32 PendingSize = 0;
    while (Socket->HasPendingData(PendingSize))
    {
        TArray<uint8> Buffer;
        Buffer.SetNumUninitialized(FMath::Min(PendingSize, static_cast<uint32>(65535)));

        int32 BytesRead = 0;
        TSharedRef<FInternetAddr> Sender = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->CreateInternetAddr();
        if (Socket->RecvFrom(Buffer.GetData(), Buffer.Num(), BytesRead, *Sender))
        {
            UE_LOG(LogKcpComponent, Verbose, TEXT("Received %d bytes from %s"), BytesRead, *Sender->ToString(true));
            ikcp_input(Kcp, reinterpret_cast<const char*>(Buffer.GetData()), BytesRead);
        }
    }
}

void UKcpComponent::FlushKcpReceive()
{
    if (!Kcp)
    {
        return;
    }

    int32 PeekSize = ikcp_peeksize(Kcp);
    while (PeekSize > 0)
    {
        TArray<uint8> Buffer;
        Buffer.SetNumUninitialized(PeekSize);

        int32 BytesReceived = ikcp_recv(Kcp, reinterpret_cast<char*>(Buffer.GetData()), Buffer.Num());
        if (BytesReceived > 0)
        {
            Buffer.SetNum(BytesReceived);
            UE_LOG(LogKcpComponent, Verbose, TEXT("KCP delivered %d bytes"), BytesReceived);

            const TArray<uint8>* DataToBroadcast = &Buffer;
            TArray<uint8> DecryptedBuffer;
            if (Settings.bEnableEncryption)
            {
                if (!DecryptBuffer(Buffer, DecryptedBuffer))
                {
                    UE_LOG(LogKcpComponent, Error, TEXT("Failed to decrypt received payload"));
                    break;
                }

                DataToBroadcast = &DecryptedBuffer;
            }

            OnMessageReceived.Broadcast(*DataToBroadcast);
        }

        PeekSize = ikcp_peeksize(Kcp);
    }
}

uint32 UKcpComponent::GetMs() const
{
    return static_cast<uint32>(FPlatformTime::ToMilliseconds64(FPlatformTime::Cycles64()));
}

bool UKcpComponent::HasDerivedEncryptionKey() const
{
    return Settings.bEnableEncryption && DerivedEncryptionKey.Num() > 0;
}

bool UKcpComponent::EncryptBuffer(const TArray<uint8>& InData, TArray<uint8>& OutData) const
{
    if (!HasDerivedEncryptionKey())
    {
        return false;
    }

    OutData = InData;
    const int32 BlockSize = FAES::AESBlockSize;
    const int32 PaddingNeeded = BlockSize - (OutData.Num() % BlockSize);
    if (PaddingNeeded > 0 && PaddingNeeded < BlockSize)
    {
        OutData.AddZeroed(PaddingNeeded);
    }

    const bool bSuccess = EncryptInPlace(OutData, DerivedEncryptionKey);
    if (!bSuccess)
    {
        UE_LOG(LogKcpComponent, Error, TEXT("AES encryption failed"));
    }

    return bSuccess;
}

bool UKcpComponent::DecryptBuffer(const TArray<uint8>& InData, TArray<uint8>& OutData) const
{
    if (!HasDerivedEncryptionKey() || InData.Num() == 0)
    {
        return false;
    }

    OutData = InData;
    if (OutData.Num() % FAES::AESBlockSize != 0)
    {
        UE_LOG(LogKcpComponent, Error, TEXT("Encrypted payload size %d is not aligned to AES block size"), OutData.Num());
        return false;
    }

    const bool bSuccess = DecryptInPlace(OutData, DerivedEncryptionKey);
    if (!bSuccess)
    {
        UE_LOG(LogKcpComponent, Error, TEXT("AES decryption failed"));
    }

    return bSuccess;
}

void UKcpComponent::RebuildEncryptionKey()
{
    DerivedEncryptionKey.Reset();

    if (!Settings.bEnableEncryption || Settings.EncryptionKey.IsEmpty())
    {
        UE_LOG(LogKcpComponent, Log, TEXT("Encryption disabled"));
        return;
    }

    FTCHARToUTF8 Converter(*Settings.EncryptionKey);
    uint8 HashedKey[32];
    HashSha256(Converter.Get(), Converter.Length(), HashedKey);

    DerivedEncryptionKey.Append(HashedKey, 32);
    UE_LOG(LogKcpComponent, Log, TEXT("Encryption key derived (SHA-256)"));
}

FSocket* UKcpComponent::GetSocket() const
{
    return Socket;
}

const TSharedPtr<FInternetAddr>& UKcpComponent::GetRemoteAddr() const
{
    return RemoteAddr;
}
