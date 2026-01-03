using UnrealBuildTool;

public class KcpForUnrealEngine : ModuleRules
{
    public KcpForUnrealEngine(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

        PublicDependencyModuleNames.AddRange(
            new string[]
            {
                "Core",
                "CoreUObject",
                "Engine",
                "Sockets",
                "Networking"
            }
        );

        // UE5.5 kaldırıldığı için Crypto modülünü şart koşmayın
#if !UE_5_5_OR_LATER
        PrivateDependencyModuleNames.AddRange(new string[]
        {
            "Crypto"
        });
#endif

        bEnableUndefinedIdentifierWarnings = false;
    }
}
