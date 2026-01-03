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

    /**
     * KCP_SERVER ile eşleşen şifreleme anahtarı. Boş bırakılırsa şifreleme yapılmaz.
     * Anahtar, AES-256 için 32 byte'a SHA-256 ile dönüştürülür.
     */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP|Encryption")
    FString EncryptionKey;

    /**
     * Şifrelemeyi aç/kapa. Açık olduğunda gönderilen ve alınan tüm paketler AES-256 ile şifrelenir.
     */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "KCP|Encryption")
    bool bEnableEncryption = false;
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

    UPROPERTY(BlueprintReadOnly, Category = "KCP")
    bool bConnectSuccess = false;

    UPROPERTY(BlueprintReadOnly, Category = "KCP")
    bool bSendPacketSuccess = false;

    UFUNCTION(BlueprintCallable, Category = "KCP")
    bool Connect(const FString& RemoteIp, int32 RemotePort, int32 LocalPort, int32 ConversationId);

    UFUNCTION(BlueprintCallable, Category = "KCP")
    void Disconnect();

    UFUNCTION(BlueprintCallable, Category = "KCP")
    bool SendMessage(const TArray<uint8>& Data);

    /**
     * UTF-8 string ve ekstra ham byte ekleriyle paket oluşturmak için yardımcı Blueprint düğümü.
     */
    UFUNCTION(BlueprintCallable, Category = "KCP", meta = (DisplayName = "Build KCP Packet"))
    static TArray<uint8> BuildPacket(const FString& TextPayload, const TArray<uint8>& ExtraBytes);

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

    bool EncryptBuffer(const TArray<uint8>& InData, TArray<uint8>& OutData) const;
    bool DecryptBuffer(const TArray<uint8>& InData, TArray<uint8>& OutData) const;
    bool HasDerivedEncryptionKey() const;
    void RebuildEncryptionKey();

    bool bConnected = false;
    int32 CurrentConversationId = 0;

    TArray<uint8> DerivedEncryptionKey;

    class FSocket* Socket = nullptr;
    TSharedPtr<class FInternetAddr> RemoteAddr;

    struct IKCPCB* Kcp = nullptr;
};
