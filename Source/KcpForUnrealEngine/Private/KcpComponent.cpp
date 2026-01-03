#include "KcpComponent.h"

#include "Sockets.h"
#include "SocketSubsystem.h"
#include "IPAddress.h"
#include "Kcp/ikcp.h"
#include "Misc/SecureHash.h"
#include "Runtime/Launch/Resources/Version.h"

#if UE_VERSION_NEWER_THAN(5, 4, 0)
#include "Crypto/AES.h"
#else
#include "Misc/AES.h"
#endif
#include "Logging/LogMacros.h"
#include "Containers/StringConv.h"

DEFINE_LOG_CATEGORY_STATIC(LogKcpComponent, Log, All);

namespace
{
#if UE_VERSION_NEWER_THAN(5, 4, 0)
    FAES::FAESKey BuildAesKey(const TArray<uint8>& DerivedKey)
    {
        FAES::FAESKey AesKey;
        AesKey.Set(DerivedKey.GetData());
        return AesKey;
    }

    bool EncryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        const FAES::FAESKey AesKey = BuildAesKey(DerivedKey);
        return FAES::EncryptData(Data.GetData(), Data.Num(), AesKey);
    }

    bool DecryptInPlace(TArray<uint8>& Data, const TArray<uint8>& DerivedKey)
    {
        const FAES::FAESKey AesKey = BuildAesKey(DerivedKey);
        return FAES::DecryptData(Data.GetData(), Data.Num(), AesKey);
    }
#else
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
    FSHA256::HashBuffer(Converter.Get(), Converter.Length(), HashedKey);

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
