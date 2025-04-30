
<# 
    Outputs Attack Surface Reduction rule status with rule names.
#>

function Get-AttackSurfaceReductionRuleStatus {

    function Get-AsrStatus ($Value) {
        switch ($Value) {
            0 { "Disabled" }
            1 { "Enabled" }
            2 { "Audit" }
            default { "Not configured" }
        }
    }

    # Hashtable for rule IDs to names
    $RuleNames = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication applications from creating child processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
        "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macro"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }

    $Prefs = Get-MpPreference
    if ($null -eq $Prefs.AttackSurfaceReductionRules_Ids) {
        return @()
    } else {
        $results = @()
        for ($i = 0; $i -lt $Prefs.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $RuleId = $Prefs.AttackSurfaceReductionRules_Ids[$i]
            $Status = Get-AsrStatus -Value $Prefs.AttackSurfaceReductionRules_Actions[$i]
            $RuleName = $RuleNames[$RuleId] 
            # If RuleName is not found, set to unknown
            if (-not $RuleName) {
                $RuleName = "UNKNOWN ASR rule name"
            }

            $results += [PSCustomObject]@{
                RuleId   = $RuleId
                RuleName = $RuleName
                Status   = $Status
            }
        }
        return $results
    }
}

Get-AttackSurfaceReductionRuleStatus
