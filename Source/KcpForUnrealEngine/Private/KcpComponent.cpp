#include "KcpComponent.h"

#include "Sockets.h"
#include "SocketSubsystem.h"
#include "IPAddress.h"
#include "Kcp/ikcp.h"

namespace
{
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

    ISocketSubsystem* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
    if (!SocketSubsystem)
    {
        bConnectSuccess = false;
        return false;
    }

    Socket = SocketSubsystem->CreateSocket(NAME_DGram, TEXT("KCP"), false);
    if (!Socket)
    {
        bConnectSuccess = false;
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
        return false;
    }

    CurrentConversationId = ConversationId;
    Kcp = ikcp_create(CurrentConversationId, this);
    if (!Kcp)
    {
        bConnectSuccess = false;
        ShutdownSocket();
        return false;
    }

    ikcp_setoutput(Kcp, KcpOutputCallback);
    ikcp_wndsize(Kcp, Settings.SendWindowSize, Settings.ReceiveWindowSize);
    ikcp_nodelay(Kcp, Settings.bNoDelay ? 1 : 0, Settings.IntervalMs, Settings.FastResend, Settings.bDisableCongestionControl ? 1 : 0);

    bConnected = true;
    bConnectSuccess = true;
    return true;
}

void UKcpComponent::Disconnect()
{
    bConnected = false;
    bConnectSuccess = false;
    bSendPacketSuccess = false;

    if (Kcp)
    {
        ikcp_release(Kcp);
        Kcp = nullptr;
    }

    ShutdownSocket();
    RemoteAddr.Reset();
}

bool UKcpComponent::SendMessage(const TArray<uint8>& Data)
{
    bSendPacketSuccess = false;

    if (!bConnected || !Kcp)
    {
        return false;
    }

    if (Data.Num() == 0)
    {
        return false;
    }

    int32 Result = ikcp_send(Kcp, reinterpret_cast<const char*>(Data.GetData()), Data.Num());
    bSendPacketSuccess = Result == 0;
    return bSendPacketSuccess;
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
            OnMessageReceived.Broadcast(Buffer);
        }

        PeekSize = ikcp_peeksize(Kcp);
    }
}

uint32 UKcpComponent::GetMs() const
{
    return static_cast<uint32>(FPlatformTime::ToMilliseconds64(FPlatformTime::Cycles64()));
}

FSocket* UKcpComponent::GetSocket() const
{
    return Socket;
}

const TSharedPtr<FInternetAddr>& UKcpComponent::GetRemoteAddr() const
{
    return RemoteAddr;
}
