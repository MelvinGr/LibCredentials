using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using LibCredentials.PInvoke;

namespace LibCredentials.Targets
{
    public class CredEnumerate : Target
    {
        protected override void _GetCredentials(List<Credential> credentials)
        {
            int count;
            IntPtr pCredentials;
            if (!Advapi32.CredEnumerate(null, 0, out count, out pCredentials))
                return;

            for (var n = 0; n < count; n++)
            {
                var pointer = Marshal.ReadIntPtr(pCredentials, n*Marshal.SizeOf(typeof(IntPtr)));
                var cred = (Advapi32.CREDENTIAL) Marshal.PtrToStructure(pointer, typeof(Advapi32.CREDENTIAL));

                if (cred.CredentialBlobSize > 0)
                {
                    var creden = new Credential(TargetTypes.CredEnumerate)
                    {
                        Username = cred.UserName,
                        Password = Marshal.PtrToStringAuto(cred.CredentialBlob),
                        Extra =
                            "targetName: " + cred.TargetName + " | " +
                            "targetAlias: " + cred.TargetAlias + " | " +
                            "type: " + cred.type + " | " +
                            "comment: " + cred.Comment
                    };

                    var data = Crypt32.CryptUnprotectData(cred.CredentialBlob, (int) cred.CredentialBlobSize);
                    if (data != null)
                        creden.Password += " (Decrypted: " + Encoding.Unicode.GetString(data) + ")";

                    credentials.Add(creden);
                }
            }
        }
    }
}