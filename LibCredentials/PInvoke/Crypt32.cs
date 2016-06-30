using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LibCredentials.PInvoke
{
    internal static class Crypt32
    {
        [Flags]
        public enum CryptProtectFlags
        {
            // for remote-access situations where ui is not an option
            // if UI was specified on protect or unprotect operation, the call
            // will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
            CryptprotectUiForbidden = 0x1,

            // per machine protected data -- any user on machine where CryptProtectData
            // took place may CryptUnprotectData
            CryptprotectLocalMachine = 0x4,

            // force credential synchronize during CryptProtectData()
            // Synchronize is only operation that occurs during this operation
            CryptprotectCredSync = 0x8,

            // Generate an Audit on protect and unprotect operations
            CryptprotectAudit = 0x10,

            // Protect data with a non-recoverable key
            CryptprotectNoRecovery = 0x20,


            // Verify the protection of a protected blob
            CryptprotectVerifyProtection = 0x40
        }

        [Flags]
        public enum CryptProtectPromptFlags
        {
            // prompt on unprotect
            CryptprotectPromptOnUnprotect = 0x1,

            // prompt on protect
            CryptprotectPromptOnProtect = 0x2
        }

        public static readonly IntPtr HwndTopmost = new IntPtr(-1);
        public static readonly IntPtr HwndNotopmost = new IntPtr(-2);
        public static readonly IntPtr HwndTop = new IntPtr(0);
        public static readonly IntPtr HwndBottom = new IntPtr(1);

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            StringBuilder szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut
        );

        public static byte[] CryptUnprotectData(byte[] bytes)
        {
            var unmanagedPointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, unmanagedPointer, bytes.Length);

            var data = CryptUnprotectData(unmanagedPointer, bytes.Length);
            Marshal.FreeHGlobal(unmanagedPointer);
            return data;
        }

        public static byte[] CryptUnprotectData(IntPtr bytes, int datalength)
        {
            byte[] data = null;
            IntPtr output;
            int outputlen;
            if (CryptUnprotectData(bytes, datalength, out output, out outputlen))
            {
                data = new byte[outputlen];
                Marshal.Copy(output, data, 0, outputlen);
            }

            return data;
        }

        public static bool CryptUnprotectData(IntPtr bytes, int datalength, out IntPtr outdata, out int outlength)
        {
            var dataIn = new DATA_BLOB
            {
                PbData = bytes,
                CbData = datalength
            };

            var dataOut = new DATA_BLOB();
            var entrophyBlob = default(DATA_BLOB);
            var promptBlob = default(CRYPTPROTECT_PROMPTSTRUCT);
            if (CryptUnprotectData(ref dataIn, null, ref entrophyBlob, IntPtr.Zero, ref promptBlob, 0,
                ref dataOut))
            {
                outdata = dataOut.PbData;
                outlength = dataOut.CbData;
                return true;
            }

            outdata = IntPtr.Zero;
            outlength = 0;
            return false;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public readonly int CbSize;
            public readonly CryptProtectPromptFlags DwPromptFlags;
            public readonly IntPtr HwndApp;
            public readonly string SzPrompt;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DATA_BLOB
        {
            public int CbData;
            public IntPtr PbData;
        }
    }
}