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

        PrivateDependencyModuleNames.AddRange(new string[]
        {
            "Crypto"
        });

        bEnableUndefinedIdentifierWarnings = false;
    }
}
