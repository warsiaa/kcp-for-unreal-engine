#pragma once

#include "CoreMinimal.h"
#include "Components/ActorComponent.h"
#include "KcpComponent.generated.h"

class FSocket;
class FInternetAddr;

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FKcpMessageReceived, const TArray<uint8>&, Data);

USTRUCT(BlueprintType)
struct FKcpSettings
{
    GENERATED_BODY()

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    int32 SendWindowSize = 128;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    int32 ReceiveWindowSize = 128;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    bool bNoDelay = true;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP", meta = (ClampMin = "10", ClampMax = "200"))
    int32 IntervalMs = 20;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    int32 FastResend = 2;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    bool bDisableCongestionControl = true;
};

UCLASS(ClassGroup = (Networking), meta = (BlueprintSpawnableComponent))
class KCPFORUNREALENGINE_API UKcpComponent : public UActorComponent
{
    GENERATED_BODY()

public:
    UKcpComponent();

    UPROPERTY(BlueprintAssignable, Category = "KCP")
    FKcpMessageReceived OnMessageReceived;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP")
    FKcpSettings Settings;

    UFUNCTION(BlueprintCallable, Category = "KCP")
    bool Connect(const FString& RemoteIp, int32 RemotePort, int32 LocalPort, int32 ConversationId);

    UFUNCTION(BlueprintCallable, Category = "KCP")
    void Disconnect();

    UFUNCTION(BlueprintCallable, Category = "KCP")
    bool SendMessage(const TArray<uint8>& Data);

    UFUNCTION(BlueprintCallable, Category = "KCP")
    bool IsConnected() const;

    FSocket* GetSocket() const;
    const TSharedPtr<FInternetAddr>& GetRemoteAddr() const;

protected:
    virtual void BeginPlay() override;
    virtual void EndPlay(const EEndPlayReason::Type EndPlayReason) override;
    virtual void TickComponent(float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction) override;

private:
    void ShutdownSocket();
    void FlushIncoming();
    void FlushKcpReceive();
    uint32 GetMs() const;

    bool bConnected = false;
    int32 CurrentConversationId = 0;

    class FSocket* Socket = nullptr;
    TSharedPtr<class FInternetAddr> RemoteAddr;

    struct IKCPCB* Kcp = nullptr;
};
