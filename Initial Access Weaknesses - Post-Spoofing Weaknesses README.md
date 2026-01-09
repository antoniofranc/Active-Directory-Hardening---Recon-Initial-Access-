# Initial Access Weaknesses - Post Spoofing Weaknesses

## 🎯 Overview
Even with response spoofing mitigated (LLMNR/NBT-NS/mDNS disabled), attackers can still leverage NTLM relay attacks through authentication coercion. This report covers critical hardening measures: MachineAccountQuota, SMB Signing, LDAP Signing, and LDAP Channel Binding.

## 🔓 What is NTLM Relaying?
NTLM Relaying is a man-in-the-middle (MITM) attack where an attacker:
1. Captures legitimate NTLM authentication traffic
2. Forwards (relays) it to another service (SMB, LDAP, MSSQL)
3. Gains unauthorized access without cracking passwords

## Why It Works
NTLM authentication doesn't bind to a specific endpoint, making it susceptible to redirection.

Attack Examples
```
Target Service                     Attack Outcome
SMB (no signing)           Local admin access on hosts → domain foothold
LDAP (no signing)          Create computer account, dump domain data
LDAP (privileged user)     DCSync, Shadow Credentials, RBCD → domain compromise
AD CS Web Enrollment       Certificate theft → domain compromise
MSSQL                      Operating system command execution
```
## Attack Vectors (Beyond Response Spoofing)
- PrinterBug / PetitPotam (authentication coercion)
- Host compromise with user impersonation
- SQL injection leading to stored procedure abuse

## 🛡️ Defense Strategy: Four Critical Hardening Steps

1. Set MachineAccountQuota to 0

Problem: By default, any domain user can join 10 computers to the domain.

Risk:
- Attackers relay NTLM to LDAP → create attacker-controlled computer account
- Computer accounts have same privileges as domain users
- Used for: BloodHound enumeration, Kerberoasting, AD CS attacks
- No password cracking required!

## Check Current Value:
```
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

# Output:
ms-DS-MachineAccountQuota : 10  # ⚠️ VULNERABLE
```

## Fix:
```
Set-ADDomain -Identity domain.local -Replace @{"ms-DS-MachineAccountQuota"="0"} -Verbose
```

## Verify 
```
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

# Output:
ms-DS-MachineAccountQuota : 0  # ✅ SECURED
```
## 2. Enable & Require SMB Signing
Problem: SMB signing is disabled by default on workstations and servers (enabled on DCs only).

*How SMB Signing Works*:
- Every SMB message contains a cryptographic signature
- Generated using session key + message hash
- If message is tampered with (relay attack), hash won't match → rejected

## Configuration States:
```
Configuration                Vulnerable?
-------------------------------------------------------
Disabled                     ✅ Yes
--------------------------------------------------------
Enabled but not required     ✅ Yes (still vulnerable)
--------------------------------------------------------
Enabled AND required         ❌ No (secured)
```

## Check Status (PowerShell):
```
Get-SmbServerConfiguration | FL RequireSecuritySignature
Get-SmbClientConfiguration | FL RequireSecuritySignature

# Output:
RequireSecuritySignature : False  # ⚠️ VULNERABLE
```
## Check Status (Registry):
```
# SMB Server
$serverKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Get-ItemProperty -Path $serverKey -Name "RequireSecuritySignature"
Get-ItemProperty -Path $serverKey -Name "EnableSecuritySignature"

# SMB Client  
$clientKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Get-ItemProperty -Path $clientKey -Name "RequireSecuritySignature"
Get-ItemProperty -Path $clientKey -Name "EnableSecuritySignature"

# Values: 0 = Disabled/Not Required, 1 = Enabled/Required
```

**Fix via Group Policy (Recommended):**

<img width="700" height="550" alt="image" src="https://github.com/user-attachments/assets/7f94dc4d-43b4-4898-bfeb-926ff651dcf6" />

*Figure 1: Four SMB signing policies that must be enabled*

Navigate to:
```
Computer Configuration → Windows Settings → Security Settings 
→ Local Policies → Security Options
```
## Enable ALL FOUR policies:

1. Microsoft network client: Digitally sign communications (always) = Enabled
2. Microsoft network client: Digitally sign communications (if server agrees) = Enabled
3. Microsoft network server: Digitally sign communications (always) = Enabled
4. Microsoft network server: Digitally sign communications (if client agrees) = Enabled

## Registry Mapping:
```
Group Policy Setting               Registry Key                      Value Name
------------------------------------------------------------------------------------------
Client (always)               LanManWorkstation\Parameters      RequireSecuritySignature
------------------------------------------------------------------------------------------
Client (if server agrees)     LanManWorkstation\Parameters      EnableSecuritySignature
-----------------------------------------------------------------------------------------
Server (always)               LanManServer\Parameters           RequireSecuritySignature
------------------------------------------------------------------------------------------
Server (if client agrees)     LanManServer\Parameters           EnableSecuritySignature
```

## Quick Fix via Registry (for testing):
```
# SMB Server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "EnableSecuritySignature" -Value 1

# SMB Client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnableSecuritySignature" -Value 1
```
## 3. Enable LDAP Signing (Port 389)
Problem: LDAP signing NOT enabled by default on any Windows Server version.

Risk:
- Relay to LDAP → enumerate domain (users, groups, computers, policies)
- Relay to LDAP → create computer account (if MachineAccountQuota ≠ 0)
- Relay privileged user → DCSync attack → domain compromise

How LDAP Signing Works:
- Server rejects LDAP binds that don't request integrity verification
- Prevents replay attacks where tickets are intercepted and reused

## Check Status:
```
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity"

# Output values:
# 0 = Not required (vulnerable)
# 1 = Supported but not required (still vulnerable)
# 2 = Required (secured) ✅
```

**Fix via Group Policy:**

<img width="600" height="533" alt="image" src="https://github.com/user-attachments/assets/e9b89b6d-53dd-4667-bb17-1dd35167924b" />

*Figure 2: LDAP server signing requirements - set to "Require signing"*

Navigate to:
```
Computer Configuration → Policies → Windows Settings → Security Settings 
→ Local Policies → Security Options 
→ Domain controller: LDAP server signing requirements

```
Set to: Require signing

## Verify:
```
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity"

# Output:
ldapserverintegrity : 2  # ✅ SECURED
```
## 4. Enable LDAP Channel Binding (Port 636 - LDAPS)
Problem: Organizations often enable LDAP signing but forget LDAP Channel Binding, leaving port 636 vulnerable

## How LDAP Channel Binding Works:
- Binds TLS tunnel and LDAP application layer together
- Creates unique Channel Binding Token (CBT) fingerprint
- Each authentication requires new TLS tunnel (invalidates old CBT)
- Prevents relayed authentication over LDAPS (port 636)

## Why Both Are Needed:
```
Feature                  Protects                    Port                   Required?
-----------------------------------------------------------------------------------------------------
LDAP Signing             Tampering, some relays      389                    ✅ Yes
-----------------------------------------------------------------------------------------------------
LDAP Channel Binding     MITM/relays over LDAPS      636                    ✅ Yes (if LDAPS enabled
-----------------------------------------------------------------------------------------------------
Both together            All LDAP relay paths      389 + 636                ✅ Recommended
```

## Check Status:
```
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding"

# If not present = Domain controller not updated OR not configured
# If present:
# 0 = Disabled (vulnerable)
# 1 = Compatibility mode (not fully secure)
# 2 = Enforced (secured) ✅
```

**Important:** This setting was added in **March 2020 update** (AVD190023). Older DCs won't have this registry key.

**Fix via Group Policy:**

![LDAP Channel Binding Policy](image3.png)
*Figure 3: LDAP server channel binding token requirements - set to "Always"*

Navigate to:
```
Computer Configuration → Policies → Windows Settings → Security Settings 
→ Local Policies → Security Options 
→ Domain controller: LDAP server channel binding token requirements
```
Set to: Always

## Verify:
```
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding"

# Output:
ldapenforcechannelbinding : 2  # ✅ SECURED
```

## 📊 Complete Hardening Checklist
```
Control                 Default State        Target State        Impact
--------------------------------------------------------------------------------------------------
MachineAccountQuota     10                   0                   Low (users rarely join machines)
--------------------------------------------------------------------------------------------------
SMB Signing             Disabled             Required            Medium (may slow SMB slightly)
-------------------------------------------------------------------------------------------------
LDAP Signing            Disabled             Required            Low-Medium (test with apps)
------------------------------------------------------------------------------------------------
LDAP Channel Binding    Disabled             Always              Low-Medium (test with apps)
```

## 📚 Additional Hardening Measures
Beyond the four controls covered:
- Disable NTLMv1 (use NTLMv2 only)
- Disable NTLM entirely (prefer Kerberos)
- Place privileged users in Protected Users group
- Implement network segmentation
- Block NTLM from untrusted networks

Impact: Critical - Prevents lateral movement and domain compromise
Prevalence: High - 70-90% of environments have at least one gap
Remediation Time: 1-2 weeks (with thorough testing)

------
# Notes: 
## Post Spoofing Weaknesses - Simple Explanation
## What is NTLM Relaying?
After capturing authentication traffic through spoofing attacks, attackers can relay (forward) those credentials to other services like SMB, LDAP, or MSSQL to:
- Gain admin access to hosts
- Create rogue computer accounts
- Dump domain information
- Compromise the entire domain

Key Point: Even if you fix spoofing attacks, relaying can still happen through "coercion attacks" (forcing authentication), so you need defense-in-depth!

## Critical Weaknesses & Fixes

## 1. MachineAccountQuota = 10 (Default)
Problem:
- ANY domain user can create up to 10 computer accounts
- Attackers relay to LDAP → create fake computer account → gain domain foothold
- No password cracking needed!

Fix:
```
Set-ADdomain -Identity wyrmwood.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
```
Set to 0 so only admins can join computers to domain.

## 2. SMB Signing Disabled
Problem:
- SMB traffic isn't verified for authenticity
- Attackers relay authentication to SMB → gain local admin access

Fix via Group Policy: Enable these 4 settings in `Security Options`:
1. Microsoft network client: Digitally sign communications (always) → Enabled
2. Microsoft network client: Digitally sign communications (if server agrees) → Enabled
3. Microsoft network server: Digitally sign communications (always) → Enabled
4. Microsoft network server: Digitally sign communications (if client agrees) → Enabled

Registry Check: Both `RequireSecuritySignature` and `EnableSecuritySignature` must = 1

## 3. LDAP Signing Disabled
Problem:
- Unsigned LDAP traffic (port 389) can be relayed
- Attackers dump domain info or create computer accounts

Fix:
- Group Policy: `Domain controller: LDAP server signing requirements` → Require signing
- Registry value `LDAPServerIntegrity` should = 2

Values:
- 0 = Not required (vulnerable)
- 1 = Supported but not required (still vulnerable)
- 2 = Required (secure) ✅

## 4. LDAP Channel Binding Disabled
Problem:
- LDAPS traffic (port 636) over SSL/TLS can still be relayed
- Even if LDAP Signing is enabled, LDAPS remains vulnerable

Fix:
- Group Policy: `Domain controller: LDAP server channel binding token requirements` → Always
- Registry value `LdapEnforceChannelBinding` should = 2

Values:
- 0 = Disabled (vulnerable)
- 1 = When supported (not fully secure)
- 2 = Always enforced (secure) ✅

## Answers to Questions
Question 1: What is the default value for the MS-DS-Machine-Account-Quota in a new Active Directory setup?

Answer: `10`

(This allows any domain user to create up to 10 computer accounts - should be changed to 0!)

## Question 2: What Registry value can be queried to verify if LDAP Signing is enabled or disabled?
Answer: `LDAPServerIntegrity`

Full path: `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`

Values:

- `0` or `1` = Vulnerable
- `2` = Secure (signing required)

## Defense-in-Depth Strategy
Layer your protections:

1. ✅ Fix response spoofing (LLMNR, NBT-NS, mDNS, IPv6)
2. ✅ Set MachineAccountQuota = 0
3. ✅ Require SMB Signing
4. ✅ Require LDAP Signing
5. ✅ Require LDAP Channel Binding
6. ✅ Use Protected Users group for privileged accounts
7. ✅ Network segmentation
