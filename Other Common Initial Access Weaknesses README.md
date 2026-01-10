# Active Directory Initial Access Vulnerabilities: Common Attack Vectors

## 🎯 Overview
Beyond response spoofing and NTLM relay attacks, several common misconfigurations provide attackers with initial access to Active Directory environments. This report covers password policies, authentication coercion, default credentials, SMB share security, and ASREPRoasting.

## 🔓 Attack Vector #1: Weak Password Policy → Password Spraying
What is Password Spraying?

Attackers attempt one weak password against all domain users (e.g., "Welcome2025!"), staying below the account lockout threshold to avoid detection.

## Vulnerable Password Policy Example (Default AD)
```
Setting                        AD Default              Risk Level
----------------------------------------------------------------------
Minimum password length        7 characters            🔴 High
------------------------------------------------------------------------
Account lockout threshold      0 (disabled)            🔴 Critical
--------------------------------------------------------------------------
Maximum password age           42 days                 🟡 Medium
-------------------------------------------------------------------------
Password complexity            Enabled                 🟢 Good
--------------------------------------------------------------------
```
Problem: With no lockout and 7-char passwords, attackers can spray unlimited attempts.

## Recommended Password Policies

```
Setting             Microsoft Best Practice   NIST Recommendation                 CIS Benchmark
---------------------------------------------------------------------------------------------------
Minimum length         12-14 characters       8+ (encourage passphrases)          14 characters
-------------------------------------------------------------------------------------------------
Maximum age            60-90 days             No expiration                       60 days
--------------------------------------------------------------------------------------------------
Lockout threshold      10 attempts            Avoid (use monitoring)              5-10 attempts
------------------------------------------------------------------------------------------------
Lockout duration       15 minutes             Prefer alerting                     15 minutes
--------------------------------------------------------------------------------------------
Complexity             Enabled                Not required (prefer passphrases)   Enabled
------------------------------------------------------------------------------------------
Reversible encryption  Disabled               Disabled                            Disabled
-----------------------------------------------------------------------------------------
```
Real-World Impact
## Complexity ≠ Security:

- `Passw0rd!` meets complexity but is easily guessed
- `correcthorsebatterystaple` (passphrase) is stronger
- Sequential passwords: `Password1` → `Password2` → `Password3`

## Better Approach:
- Use Fine-Grained Password Policies for privileged accounts (24+ chars, stricter lockout)
- Deploy enterprise password managers
- Enable Microsoft Entra Password Protection (blocks breached passwords)
- Implement MFA wherever possible
- Monitor for password spray attempts (5+ failed logins across many accounts)

## Remediation via Group Policy
Navigate to:
```
Computer Configuration → Policies → Windows Settings → Security Settings 
→ Account Policies → Password Policy
```
Key Settings:
- Minimum password length: 14 characters
- Password complexity: Enabled
- Maximum password age: 60 days

Navigate to:
```
Computer Configuration → Policies → Windows Settings → Security Settings 
→ Account Policies → Account Lockout Policy
```

Key Settings:
- Account lockout threshold: 5-10 attempts
- Account lockout duration: 15 minutes
- Reset lockout counter: 15 minutes

## Reset Weak Passwords (PowerShell):
```
# Set temporary password
$NewPassword = Read-Host -AsSecureString "Enter temporary password"
Set-ADAccountPassword -Identity username -NewPassword $NewPassword -Reset

# Force password change at next login
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

## 🔓 Attack Vector #2: Authentication Coercion (PetitPotam, PrinterBug)
What Are Coercion Attacks?

Attackers force domain controllers to authenticate to attacker-controlled systems, enabling NTLM relay attacks without response spoofing.

## Common Coercion Methods
```
Attack                   Protocol     Requires Authentication?         Impact
-------------------------------------------------------------------------------------------------
PetitPotam (unpatched)   MS-EFSRPC    ❌ No                           Direct domain compromise
-------------------------------------------------------------------------------------------------
PetitPotam (patched)     MS-EFSRPC    ✅ Yes (still works)            NTLM relay with valid creds
--------------------------------------------------------------------------------------------------
PrinterBug               MS-RPRN      ✅ Yes                          Forces DC authentication
----------------------------------------------------------------------------------------------------
WebClient abuse          WebDAV       ✅ Yes                          Credential capture
```

## Remediation: Disable Print Spooler on Domain Controllers
Check Status:
```
Get-Service -Name spooler | Select-Object Status

# Output:
Status
------
Running  # ⚠️ VULNERABLE
```

Disable Print Spooler:
```
Stop-Service spooler -Force
Set-Service spooler -StartupType Disabled -Verbose
```
Verify:
```
(Get-CimInstance -ClassName Win32_Service -Filter "Name='spooler'").StartMode

# Output:
Disabled  # ✅ SECURED
```

## Apply Patches:
- Ensure PetitPotam patch is installed (prevents unauthenticated coercion)
- Keep domain controllers fully patched
- Consider RPC filters for advanced hardening (beyond scope)

## 🔓 Attack Vector #3: Default Credentials & Null Authentication
Common Scenarios
```
Application                   Default Credentials               Impact
------------------------------------------------------------------------------------
Splunk Free                   No auth required                  RCE via malicious app upload
------------------------------------------------------------------------------------------------
ManageEngine products         admin:admin                       Create domain users, run OS commands
------------------------------------------------------------------------------------------------------
Tomcat/Jenkins                admin:admin or tomcat:tomcat      Web shell upload → RCE
------------------------------------------------------------------------------------------------------
WebLogic                      weblogic:weblogic1                Full application compromise
---------------------------------------------------------------------------------------------------
Printers/IoT devices          admin:admin                       LDAP credential leakage
```

## Real-World Example
Scenario: Organization had perfect security hygiene (LLMNR disabled, SMB signing enabled, strong passwords), but a Splunk Enterprise free trial was left running with no authentication. The service ran as Domain Admin.

Attack:
1. Attacker accessed Splunk web interface (no login)
2. Uploaded malicious Splunk app
3. Achieved remote code execution as Domain Admin
4. Instant domain compromise

Remediation
## Policy Requirements:
- Change default credentials immediately upon deployment
- Document all demo/trial software installations
- Establish approval process for new applications
- Quarterly audits of web-based management interfaces

Detection:
```
# Find services running as privileged accounts
Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*admin*"} | 
    Select-Object Name, StartName, State
```

## 🔓 Attack Vector #4: Open/Writable SMB Shares
The Risk
File shares with excessive permissions allow attackers to:

- Place malicious files (SCF, LNK) to capture credentials
- Steal backups containing sensitive data (VMDK files, SAM databases)
- Pivot to other systems using leaked credentials

## Real-World Examples
Example 1: SCF File Attack

- Day 9 of 10-day pentest, no foothold yet
- Found one writable share, placed malicious SCF file
- Privileged user browsed share → NTLMv2 hash captured
- Cracked password → domain compromise

## Example 2: Backup Files

- Anonymous-readable share contained VMDK backups
- Extracted SAM database → dumped local admin hashes
- Local admin password reused across subnet
- Obtained Domain Admin credentials from Registry

## Audit SMB Shares (PowerShell)
```
# List all SMB shares and permissions
$smbShares = Get-SmbShare

foreach ($share in $smbShares) {
    Write-Host "Share Name: $($share.Name)"
    Write-Host "Path: $($share.Path)"
    
    $permissions = Get-SmbShareAccess -Name $share.Name
    
    foreach ($permission in $permissions) {
        Write-Host "  Account: $($permission.AccountName)"
        Write-Host "  Access: $($permission.AccessControlType)"
        Write-Host "  Rights: $($permission.AccessRight)"
        Write-Host ""
    }
    Write-Host "----------------------------------------"
}
```
## Remediation Example: Remove Excessive Permissions
Scenario: Marketing group has Full access to IT share

Verify Current Permissions:
```
Remediation Example: Remove Excessive Permissions
Scenario: Marketing group has Full access to IT share
Verify Current Permissions:
```
## Revoke Marketing Group Access:
```
Revoke-SmbShareAccess -Name "IT" -AccountName "wyrmwood.local\Marketing"
```

Grant Read-Only Access (If Needed): 
```
Grant-SmbShareAccess -Name "IT" -AccountName "wyrmwood\Marketing" -AccessRight Read
```
## Verify Fix:
```
Get-SmbShareAccess -Name "IT"

# Output:
Account: wyrmwood\IT
Access: Allow
Rights: Full

# Marketing group removed ✅
```

## Recommended Tool: PowerHuntShares
What it does:
- Enumerates all domain SMB shares
- Identifies excessive permissions
- Highlights read/write access for Domain Users
- Flags potentially sensitive files
- Generates HTML reports + CSV exports

Best Practice: Run quarterly audits

## 🔓 Attack Vector #5: ASREPRoasting (Kerberos Pre-Authentication Disabled)
What is ASREPRoasting?

When "Do not require Kerberos preauthentication" is enabled, attackers can:
1. Request a Kerberos TGT for the account (no password needed)
2. TGT is encrypted with the account's password
3. Crack TGT offline to recover cleartext password

<img width="404" height="529" alt="image" src="https://github.com/user-attachments/assets/13f01609-6c75-4653-b803-e9a4dcfd93bd" />

Figure 1: "Do not require Kerberos preauthentication" checkbox in AD Users & Computers

## Attack Scenarios
Authenticated Attack:
```
# With valid domain credentials
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10 -request
```

Unauthenticated Attack:
- Requires list of valid usernames (from LLMNR/null sessions/username enumeration)
- Test each username for ASREPRoastable accounts
- No account lockout risk during enumeration


## Identify Vulnerable Accounts (PowerShell)
```
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true }

# Output:
DistinguishedName : CN=svc-backup,OU=CORP,DC=wyrmwood,DC=local
Enabled           : True
Name              : svc-backup
SamAccountName    : svc-backup
```
Remediation
## Option 1: Disable for Single Account
```
Get-ADUser -Identity svc-backup | Set-ADAccountControl -DoesNotRequirePreAuth $false -Verbose

VERBOSE: Performing the operation "Set" on target "CN=svc-backup,OU=CORP,DC=wyrmwood,DC=local".
```

## Option 2: Disable for ALL Accounts
```
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } | 
    Set-ADAccountControl -DoesNotRequirePreAuth $false -Verbose
```
## Option 3: If Setting Required for Business
- Set 24+ character complex password (makes cracking infeasible)
- Monitor for ASREPRoasting attempts
- Implement username enumeration prevention
- Alert on Kerberos AS-REQ failures for these accounts

## 📊 Remediation Priority Matrix
```
Vulnerability          Remediation Difficulty   Business Impact     Priority
----------------------------------------------------------------------------------
Default Credentials    Easy                     Low                 🔴 Critical
--------------------------------------------------------------------------------
Weak Password Policy   Medium                   Medium              🔴 Critical
----------------------------------------------------------------------------------
Open SMB Shares        Medium                   Low-Medium          🟠 High
--------------------------------------------------------------------------------
ASREPRoasting          Easy                     Low                 🟠 High
--------------------------------------------------------------------------------
Print Spooler on DCs   Easy                     Low                 🟡 Medium
```

## 📚 Complete Hardening Checklist
```
# Password Policy
✓ Minimum 14 characters
✓ Lockout threshold: 5-10 attempts
✓ FGPP for privileged accounts (24+ chars)
✓ Password filter (haveibeenpwned integration)

# Authentication Coercion
✓ Disable Print Spooler on DCs
✓ Apply PetitPotam patch
✓ Keep DCs fully patched

# Default Credentials
✓ Audit all web-based management interfaces
✓ Document demo software deployments
✓ Quarterly credential audits

# SMB Shares
✓ Run PowerHuntShares quarterly
✓ Remove Domain Users from sensitive shares
✓ Audit anonymous-accessible shares

# ASREPRoasting
✓ Disable pre-auth unless required
✓ If required: 24+ char passwords
✓ Monitor for AS-REQ anomalies
```

## 📚 Technical Skills Demonstrated
- Active Directory password policy design
- Group Policy configuration and deployment
- PowerShell scripting for security auditing
- SMB share permission management
- Kerberos authentication mechanisms
- Attack path analysis and risk assessment
- Incident response and detection strategy
----
Impact: High - Multiple easy initial access vectors
Prevalence: Critical - Found in 80%+ of environments
Remediation Time: 2-4 weeks (with testing)

----

# Notes: Other Common Initial Access Weaknesses - Simple Explanation
This section covers additional ways attackers gain initial access to Active Directory beyond response spoofing attacks.

## Major Weaknesses & Fixes
1. Weak Password Policy (Password Spraying)
Problem:
- Default AD password policy: 7 characters minimum, no account lockout
- Attackers "spray" common passwords (Welcome2024, Password123) against all users
- If they know the policy, they stay under lockout threshold

## Best Practice Recommendations:
```
Setting	                          AD Default	       Recommended
----------------------------------------------------------------------
Minimum password length	          7 characters	     12-14 characters
----------------------------------------------------------------------------
Account lockout threshold	        0 (disabled)	     5-10 invalid attempts
------------------------------------------------------------------------------
Maximum password age	            42 days           60-90 days
----------------------------------------------------------------------------
Account lockout duration	        N/A	              15 minutes

```

## Additional Protections:
- Use Fine-Grained Password Policies for privileged accounts (stricter rules)
- Implement password filters (block common/breached passwords)
- Enable MFA wherever possible
- Use enterprise password managers
- User training: Don't reuse passwords on external sites!

## 2. Print Spooler Service Running (Coercion Attacks)
Problem:
- Print Spooler on domain controllers enables PrinterBug attacks
- Attackers force the DC to authenticate to them → relay credentials → domain compromise
- Also vulnerable to PetitPotam (if unpatched)

Fix:
```
powershell
# Stop and disable Print Spooler on domain controllers
Stop-Service spooler -Force
Set-Service spooler -StartupType Disabled
```
Verify:
```
powershell(Get-CimInstance -ClassName Win32_Service -Filter "Name='spooler'").StartMode
# Should return: Disabled
```

## 3. Vulnerable Applications/Services (RCE)
Problem:
- Outdated software with known exploits
- Attacker exploits vulnerability → gains SYSTEM access on domain-joined host
- SYSTEM on domain-joined host = computer account = domain user access

## Real-world example:

Exploited vulnerable app → gained SYSTEM → dumped machine account hash → ran BloodHound → Kerberoasted → cracked Domain Admin password

Fix:
- Patch everything regularly
- Inventory all applications
- Remove/disable unused services
------

## 4. Default Credentials / Null Authentication
Problem:
- Applications left with default passwords (admin:admin, admin:password)
- Common in: Tomcat, Jenkins, Splunk, ManageEngine, printers, etc.
- Often from forgotten demo installations

Real-world examples:
- Splunk free version (no auth) → malicious app → RCE
- ManageEngine with admin:admin → create domain users → add to Domain Admins
- Printer LDAP test feature → sends credentials in cleartext

Fix:
- Change ALL default credentials immediately
- Document and track demo software
- Regular audits of web-facing applications

## 5. Open/Writable SMB Shares
Problem:
- File shares with excessive permissions
- Attackers place malicious files (SCF files, LNK files) → users access share → credentials captured
- May contain sensitive data (VM backups, scripts, passwords)

Real-world examples:
```
Found writable share → placed malicious SCF file → privileged user visited → captured NTLMv2 hash → cracked password → domain compromise


Anonymous read on backup share → downloaded VMDK file → extracted local admin hash → used across all systems → found Domain Admin credential
```

Fix:
- Use PowerHuntShares to audit permissions quarterly
- Apply principle of least privilege
- Remove anonymous access
- Review permissions regularly
------

PowerShell to check:
```
powershellGet-SmbShare | Get-SmbShareAccess
```
Revoke excessive access:
```
Revoke-SmbShareAccess -Name "ShareName" -AccountName "Domain\User"
```

## 6. ASREPRoasting (Do Not Require Kerberos Preauthentication)
Problem:
- Setting on user accounts: "Do not require Kerberos preauthentication"
- Attackers request TGT without providing password
- Crack TGT offline to recover password
-Can be done unauthenticated with just a username list

## Check for vulnerable accounts:
```
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true }
```
Fix:
```
# Fix single account
Get-ADUser -Identity svc-backup | Set-ADAccountControl -DoesNotRequirePreAuth $false

# Fix ALL accounts
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } | Set-ADAccountControl -DoesNotRequirePreAuth $false
```

If needed for business:
- Set 24+ character password (makes cracking nearly impossible)
- Monitor for enumeration attempts

## Key Takeaways
Defense-in-Depth Approach:
1. ✅ Strong password policy + MFA + password filters
2. ✅ Disable Print Spooler on domain controllers
3. ✅ Patch all applications/services
4. ✅ Change ALL default credentials
5. ✅ Audit SMB shares quarterly
6. ✅ Disable Kerberos preauthentication (unless absolutely necessary)
7. ✅ User training and monitoring
Remember: Even ONE misconfiguration (like a writable file share or default password) can lead to full domain compromise, even if everything else is hardened perfectly!
