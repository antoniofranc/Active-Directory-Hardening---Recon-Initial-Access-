# Initial Access Weaknesses - Response Spoofing Attacks

## 🎯 Overview
Four network protocol vulnerabilities allow attackers to capture credentials without user interaction through response spoofing. These legacy protocols remain enabled by default in Windows and persist through domain upgrades, making them prevalent in modern environments.

## 🔓 Attack Mechanism: LLMNR/NBT-NS/mDNS Spoofing
<img width="500" height="812" alt="image" src="https://github.com/user-attachments/assets/f1607fb3-a930-4759-ad29-4195df52d3cd" />

Figure 1: How LLMNR/NBT-NS response spoofing works

## Attack Flow
1. User mistypes: Client attempts to connect to `\\fileservr` (typo)
2. DNS fails: DNS server doesn't recognize hostname
3. Fallback broadcast: Client sends LLMNR/NBT-NS broadcast: "Is \fileservr out there?"
4. Attacker responds: Malicious machine answers: "\fileservr is right here!"
5. Credential leak: Client sends NTLMv2 hash to attacker

## Demo Attack
```
sudo responder -I eth0

[SMB] NTLMv2-SSP Client   : 192.168.1.138
[SMB] NTLMv2-SSP Username : wyrmwood.local\svc_sccm
[SMB] NTLMv2-SSP Hash     : svc_sccm::wyrmwood.local:7ba23471...
```

**Result:** Captured NTLMv2 hash can be:
- Cracked offline to recover cleartext password
- Used in NTLM relay attacks for unauthorized access

---

## ⚠️ Common Attack Triggers

| Trigger | Description |
|---------|-------------|
| **User Typos** | Mistyped UNC paths: `\\fileservr` instead of `\\fileserver` |
| **WPAD Discovery** | Windows searches for `wpad.domain.local` - if not in DNS, falls back to LLMNR |
| **Chrome Browser** | Attempts hostname resolution for search terms at startup |
| **Misconfigured Apps** | Applications looking for printers/shares with incorrect DNS records |
| **Legacy Devices** | Unmanaged devices triggering fallback name resolution |
| **DNS Issues** | Client or server DNS misconfigurations |

---

## 🛡️ Defense: Four Attack Vectors to Block

### 1. LLMNR (Link-Local Multicast Name Resolution)

**What it is:** Legacy name resolution protocol that broadcasts requests when DNS fails

<img width="1072" height="408" alt="image" src="https://github.com/user-attachments/assets/b6cd9218-86df-4b5c-8034-f0dcb7ebb39a" />

*Figure 2: Creating a new GPO named "Disable LLMNR"*

**Fix via Group Policy:**

<img width="926" height="556" alt="image" src="https://github.com/user-attachments/assets/abaa0bdc-a057-43c2-b36f-4e80d2a68895" />

*Figure 3: Enable "Turn off multicast name resolution" policy*

1. Create new GPO: `Disable LLMNR`
2. Navigate to:
```
   Computer Configuration → Administrative Templates 
   → Network → DNS Client 
   → Turn off multicast name resolution
```
3. Set to **Enabled**

<img width="820" height="538" alt="image" src="https://github.com/user-attachments/assets/eaa2a701-289c-453f-93d1-54ceb8e34ad1" />

*Figure 4: Link the GPO to Workstations OU*

4. Link GPO to appropriate OUs (Workstations, Servers)
5. Wait for Group Policy update (90 min) or force: `gpupdate /force`

---

### 2. NBT-NS (NetBIOS Name Service)

**What it is:** Even older name resolution protocol that also uses broadcasts

**Challenge:** No native GPO setting - must be configured per network adapter
<img width="370" height="251" alt="image" src="https://github.com/user-attachments/assets/7f53d91e-b6cc-4a68-ab35-8e4457457f6c" />


*Figure 5: Access network adapter properties*

**Manual Method:**
1. Open Network Connections
2. Right-click adapter → Properties

<img width="349" height="460" alt="image" src="https://github.com/user-attachments/assets/752696c4-6806-4350-8636-5d083faceb70" />

*Figure 6: Select Internet Protocol Version 4*

3. Select `Internet Protocol Version 4 (TCP/IPv4)` → Properties
4. Click `Advanced...`

<img width="384" height="479" alt="image" src="https://github.com/user-attachments/assets/385ea87e-8850-4c9b-b75a-015d902fd566" />

*Figure 7: Disable NetBIOS over TCP/IP in WINS tab*

5. Navigate to **WINS** tab
6. Select `Disable NetBIOS over TCP/IP`

**Automated Method via GPO:**

Registry key location:
```
HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces
```

<img width="828" height="181" alt="image" src="https://github.com/user-attachments/assets/0e2ea368-bab8-4778-90c8-1476478179bf" />

Figure 8: NetbiosOptions registry value (0=Default, 2=Disabled)

## PowerShell Script:
```
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object { 
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```

<img width="764" height="177" alt="image" src="https://github.com/user-attachments/assets/2d32d1c5-e743-4e7c-ac89-b427d50fac06" />

*Figure 9: Save script to domain controller SYSVOL share*

**Deploy via GPO Startup Script:**

<img width="777" height="549" alt="image" src="https://github.com/user-attachments/assets/27b04766-41d6-4ea6-b376-013160e58333" />

*Figure 10: Configure startup script in GPO*

1. Create new GPO: `Disable NetBIOS`
2. Edit GPO:
```
   Computer Configuration → Policies → Windows Settings 
   → Scripts (Startup/Shutdown) → Startup
```

<img width="393" height="449" alt="image" src="https://github.com/user-attachments/assets/56cc791e-abb7-4ffc-a7d2-8ac64f55e187" />

Figure 11: Add PowerShell script to startup

Select PowerShell Scripts tab
Add script from: \\domain.local\SYSVOL\domain.local\scripts\
Link GPO to target OUs
Reboot systems

## Validation:
```
Invoke-Command -ComputerName "MS01" -ScriptBlock {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" |
    ForEach-Object {
        $netbios = Get-ItemProperty -Path $_.PSPath -Name NetbiosOptions
        [PSCustomObject]@{
            Adapter = $_.PSChildName
            NetbiosOptions = $netbios.NetbiosOptions
        }
    }
}

# Output: NetbiosOptions = 2 means disabled ✅
```

## 3. mDNS (Multicast DNS)
What it is: Apple's Bonjour protocol, introduced in Windows 10 1703, used by smart devices

Challenge: Multiple applications have their own mDNS stacks (Chrome, Zoom, TeamViewer)

## Why it's complicated:
```
# Check processes listening on UDP 5353
Get-NetUDPEndpoint -LocalPort 5353 | 
    Select-Object LocalAddress, LocalPort, OwningProcess,
    @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess).Name}}

# Multiple processes use mDNS simultaneously:
# - svchost.exe (Windows DNS cache)
# - chrome.exe
# - zoom.exe
# - teams.exe
```

## Microsoft's Recommendation: Windows Defender Firewall
Remediation Options:
```
Option                                                 Impact                       Use Case 
Block inbound mDNS (ALL profiles)             May break remote workers      High-security environments
Block inbound mDNS (Domain profile only)      Protects corporate network     Recommended for most orgs
Block outbound mDNS                           Highest security             Only where absolutely necessary
```

## Implementation:
```
# Block inbound mDNS on Domain profile
New-NetFirewallRule -DisplayName "Block mDNS Inbound" `
    -Direction Inbound -Protocol UDP -LocalPort 5353 `
    -Action Block -Profile Domain
```

**Reality Check:** 
- mDNS is used by **many** legitimate services (AirPlay, Chromecast, printers)
- Full blocking may impact productivity
- Consider: Application whitelisting, SMB Signing, LDAP Signing, network segmentation

---

### 4. IPv6 DNS Spoofing (DHCPv6 Spoofing)

**What it is:** Attacker responds to DHCPv6 broadcasts, provides rogue DNS server address

**Why it works:**
- IPv6 enabled by default in Windows
- Windows **prefers** IPv6 over IPv4
- Most organizations don't use/configure IPv6
- Attackers can hijack DNS resolution entirely

**Attack Flow:**
1. Client broadcasts DHCPv6 request
2. Attacker responds with IPv6 configuration + rogue DNS server
3. All DNS queries go through attacker's DNS
4. Attacker redirects clients to malicious services (ntlmrelayx)
5. NTLMv2 hashes captured or relayed

**Fix: Disable IPv6**

<img width="599" height="555" alt="image" src="https://github.com/user-attachments/assets/07b8e8f7-a465-491b-8868-be6bde62df46" />

*Figure 12: Create registry item via Group Policy Preferences*

**Registry Method:**
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
DisabledComponents = 0xFF (255 decimal)
```
## PowerShell Check:
```
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$key = "DisabledComponents"

try {
    $val = Get-ItemProperty -Path $regPath -Name $key -ErrorAction Stop
    if ($val.$key -eq 0xFF) {
        Write-Host "✅ IPv6 is fully disabled" -ForegroundColor Green
    } else {
        Write-Host "⚠️ IPv6 is partially enabled" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ IPv6 is fully enabled (not remediated)" -ForegroundColor Yellow
}
```
## PowerShell Fix:
```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
    -Name "DisabledComponents" -Value 0xFF
Write-Host "$env:COMPUTERNAME - IPv6 disabled. REBOOT REQUIRED."
```

**Group Policy Method (Recommended):**
1. Create new GPO: `Disable IPv6`
2. Navigate to:
```
   Computer Configuration → Preferences → Windows Settings → Registry
```
3. Right-click → New → Registry Item:
- Action: Update
- Hive: HKEY_LOCAL_MACHINE
- Key Path: `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
- Value Name: `DisabledComponents`
- Value Type: REG_DWORD
- Value Data: `255` (decimal) or `0xFF` (hex)
4. Link to OUs
5. Reboot systems for changes to take effect

## ⚠️ Microsoft's Warning:
"I don't recommend that you disable IPv6... some Windows components might not function."

Mitigation Alternatives (if IPv6 required):
- Set `MachineAccountQuota` = 0
- Enable SMB Signing
- Enable LDAP Signing + Channel Binding
- Network segmentation

## 🔗 Next Steps
After remediating response spoofing:

- Enable SMB Signing (prevents NTLM relay attacks)
- Enable LDAP Signing + Channel Binding
- Implement strong password policy
- Set MachineAccountQuota = 0
- Deploy network segmentation
---

# Notes: 
## Response Spoofing Attacks - Simple Explanation

## What Are Response Spoofing Attacks?
Attackers listen on the network for name resolution requests (when computers try to find other computers). When a request fails, the attacker responds pretending to be the target, and the victim sends their password hash to the attacker.

## Four Main Attack Types
1. LLMNR/NBT-NS Spoofing (Most Common)
- When DNS fails, Windows uses LLMNR and NBT-NS as fallback
- Attacker uses tool like Responder to capture NTLMv2 password hashes
- Can crack hashes offline or relay them to gain access

Fix:
- LLMNR: Disable via GPO → "Turn off multicast name resolution"
- NBT-NS: Set registry key NetbiosOptions = 2 (via script + GPO)

---
2. mDNS Spoofing (Introduced in Windows 10)
- Used by smart devices, Chrome, printers, etc. (UDP port 5353)
- Can't fully disable because apps like Chrome implement their own mDNS
- Harder to fix without breaking functionality

Fix:
- Block inbound mDNS via Windows Defender Firewall
- Apply defense-in-depth: SMB signing, LDAP signing, strong passwords

----
3. DNS Spoofing over IPv6 (Often Overlooked!)
- IPv6 is enabled by default but rarely configured
- Attacker responds to DHCPv6 requests and becomes the DNS server
- Works even if LLMNR/NBT-NS/mDNS are disabled

Fix:
- Disable IPv6 by setting registry: `DisabledComponents = 0xFF (255)`
- Or use mitigating controls (SMB/LDAP signing, lower MachineAccountQuota)

---
Question 1: What Registry key can be used to enable/disable NetBIOS over TCP/IP?
Answer: `NetbiosOptions`

(Full path: `HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces)`

Question 2: What should the value of NetbiosOptions be to disable NetBIOS via the Registry?
Answer: `2`
Values explanation:

- `0` = Default (uses DHCP setting or enables if no DHCP)
- `1` = Enable NetBIOS over TCP/IP
- `2` = Disable NetBIOS over TCP/IP ✅
