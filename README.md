# About SharpRBCD
An executable that streamlines adding the msds-AllowedToActOnBehalfOfOtherIdentity attribute for RBCD attacks. This tool was created as an alternative way of writing to the msDS-AllowedToActOnBehalfOfOtherIdentity without using powershell. After setting the delegation, use Rubeus or impacket-getST to request a silver ticket for the desired resource.

# Compiling Details
Open project in Visual Studio and 'Build the Solution'

# Usage

```
# View the current value of the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
SharpRBCD.exe -action read -delegateTo SRV01$
# Setting the delegation
SharpRBCD.exe -action write -delegateFrom WK1$ -delegateTo SRV01$ -dc dc.company.local
# Clear the attribute
SharpRBCD.exe -action clear -delegateTo SRV01$

```
![Screenshot 2025-03-09 141549](https://github.com/user-attachments/assets/1a11f7d9-2d2d-4c55-a83e-e1460f8f12d8)

# Command-Line
![Screenshot 2025-03-09 011356](https://github.com/user-attachments/assets/9fe897b8-0377-459e-b623-d106fa0e7340)
# C2 Compatibility
Fully compatibile with Cobalt Strike's execute-assembly command.
## Read Attribute
![Screenshot 2025-03-09 142100](https://github.com/user-attachments/assets/cc628051-4894-4f12-a4ab-8fb125165af6)
## Write Attribute
![Screenshot 2025-03-09 142142](https://github.com/user-attachments/assets/e00b2374-836e-4571-9d51-16e111181e9e)
## Clear Attribute
![Screenshot 2025-03-09 142202](https://github.com/user-attachments/assets/a51afeae-57ae-4a8f-80dc-042899a831c8)

# Technical Details
### 1. LDAP Binding and Target Identification

The tool connects to Active Directory over LDAP, typically using Kerberos/Negotiate authentication, which leverages the operator’s current session or provided credentials.
It then locates the target computer object (the one on which delegation will be enabled) by searching for its sAMAccountName (e.g., DC-2$).
### 2. Retrieving the “Delegate-From” SID

A separate computer account—often attacker-controlled or otherwise vulnerable—is the “delegate-from” host (e.g., WKSTN-2$).
The application queries AD to find this machine’s objectSid (a binary representation of the SID).
### 3. Constructing a Security Descriptor

Once the tool has the SID of the “delegate-from” machine, it builds a Security Descriptor in SDDL form (commonly: O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<delegateFrom-SID>)).
This SDDL string grants the “delegate-from” SID the right to perform Kerberos delegation (via S4U2Proxy) on behalf of other users to the “delegate-to” resource.
### 4. Writing msDS-AllowedToActOnBehalfOfOtherIdentity

The tool converts the SDDL into a binary security descriptor.
Using an LDAP “modify” operation, it replaces the target machine’s msDS-AllowedToActOnBehalfOfOtherIdentity attribute with this new descriptor.
This effectively grants the specified SID (the “delegate-from” machine) the right to impersonate arbitrary users to the “delegate-to” service.
### 5. Abusing Constrained Delegation

With that attribute set, an operator controlling the “delegate-from” computer can use Kerberos protocol transitions (S4U2Self / S4U2Proxy) to request service tickets in the name of any user.
In other words, they can impersonate privileged accounts (also not marked as sensitive) to the “delegate-to” service, obtaining “silver tickets” for lateral movement or local privilege escalation.

### 6. Additional Actions (Read / Clear)

In reading mode, the application can simply fetch and parse the existing msDS-AllowedToActOnBehalfOfOtherIdentity value, outputting the current security descriptor as SDDL or Base64.
In clearing mode, it removes the attribute entirely, reverting the target object to a state with no resource-based delegation rights assigned.

# References/Inspiration
 Impacket-RBCD - https://github.com/fortra/impacket/blob/master/examples/rbcd.py
 SharpAllowedToAct - https://github.com/pkb1s/SharpAllowedToAct/tree/master
 StandIn - https://github.com/FuzzySecurity/StandIn
