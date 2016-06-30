using System;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace LibCredentials.PInvoke
{
    internal static class Advapi32
    {
        public enum CRED_FLAG : uint
        {
            CredFlagsPromptNow = 2,
            CredFlagsUsernameTarget = 4
        }

        public enum CRED_TYPE : uint
        {
            CredTypeGeneric = 1,
            CredTypeDomainPassword = 2,
            CredTypeDomainCertificate = 3,
            CredTypeDomainVisiblePassword = 4,
            CredTypeMaximum = 5 // Maximum supported cred type
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [StructLayout(LayoutKind.Sequential)]
        public struct CREDENTIAL
        {
            public CRED_FLAG Flags;
            public CRED_TYPE type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr CredAttribute;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }
    }
}