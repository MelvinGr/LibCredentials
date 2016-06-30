using System;
using System.Runtime.InteropServices;
using PInvoke;

namespace LibCredentials.PInvoke
{
    internal static class Wlanapi
    {
        public enum WLAN_INTERFACE_STATE
        {
            // wlan_interface_state_not_ready -> 0
            /// <summary>
            /// </summary>
            WlanInterfaceStateNotReady = 0,

            // wlan_interface_state_connected -> 1
            /// <summary>
            /// </summary>
            WlanInterfaceStateConnected = 1,

            // wlan_interface_state_ad_hoc_network_formed -> 2
            /// <summary>
            /// </summary>
            WlanInterfaceStateAdHocNetworkFormed = 2,

            // wlan_interface_state_disconnecting -> 3
            /// <summary>
            /// </summary>
            WlanInterfaceStateDisconnecting = 3,

            // wlan_interface_state_disconnected -> 4
            /// <summary>
            /// </summary>
            WlanInterfaceStateDisconnected = 4,

            // wlan_interface_state_associating -> 5
            /// <summary>
            /// </summary>
            WlanInterfaceStateAssociating = 5,

            // wlan_interface_state_discovering -> 6
            /// <summary>
            /// </summary>
            WlanInterfaceStateDiscovering = 6,

            // wlan_interface_state_authenticating -> 7
            /// <summary>
            /// </summary>
            WlanInterfaceStateAuthenticating = 7
        }

        public const uint WlanProfileGetPlaintextKey = 4;

        [DllImport("Wlanapi.dll")]
        public static extern Win32ErrorCode WlanOpenHandle(
            uint dwClientVersion,
            IntPtr pReserved, //not in MSDN but required
            [Out] out uint pdwNegotiatedVersion,
            ref IntPtr clientHandle);

        [DllImport("Wlanapi.dll", EntryPoint = "WlanFreeMemory")]
        public static extern void WlanFreeMemory([In] IntPtr pMemory);

        [DllImport("Wlanapi.dll", EntryPoint = "WlanEnumInterfaces")]
        public static extern Win32ErrorCode WlanEnumInterfaces(IntPtr hClientHandle,
            IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern uint WlanGetProfileList(
            [In] IntPtr clientHandle,
            [In] [MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
            [In] IntPtr pReserved,
            [Out] out IntPtr profileList
        );

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern Win32ErrorCode WlanGetProfile(IntPtr hClientHandle, ref Guid pInterfaceGuid,
            string strProfileName,
            IntPtr pReserved, ref string pstrProfileXml, ref uint pdwFlags, ref uint pdwGrantedAccess);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            /// GUID->_GUID
            public Guid InterfaceGuid;

            /// WCHAR[256]
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string StrInterfaceDescription;

            /// WLAN_INTERFACE_STATE->_WLAN_INTERFACE_STATE
            public WLAN_INTERFACE_STATE IsState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {
            // Length of <see cref="InterfaceInfo" /> array
            /// <summary>
            /// </summary>
            public int DwNumberOfItems;

            // This member is not used by the wireless service. Applications can use this member when processing individual
            // interfaces.
            /// <summary>
            /// </summary>
            public int DwIndex;

            // Array of WLAN interfaces.
            /// <summary>
            /// </summary>
            public WLAN_INTERFACE_INFO[] InterfaceInfo;

            // Constructor for WLAN_INTERFACE_INFO_LIST.
            // Constructor is needed because the InterfaceInfo member varies based on how many adapters are in the system.
            /// <summary>
            /// </summary>
            /// <param name="pList">the unmanaged pointer containing the list.</param>
            public WLAN_INTERFACE_INFO_LIST(IntPtr pList)
            {
                // The first 4 bytes are the number of WLAN_INTERFACE_INFO structures.
                DwNumberOfItems = Marshal.ReadInt32(pList, 0);

                // The next 4 bytes are the index of the current item in the unmanaged API.
                DwIndex = Marshal.ReadInt32(pList, 4);

                // Construct the array of WLAN_INTERFACE_INFO structures.
                InterfaceInfo = new WLAN_INTERFACE_INFO[DwNumberOfItems];

                for (var i = 0; i <= DwNumberOfItems - 1; i++)
                {
                    // The offset of the array of structures is 8 bytes past the beginning.
                    // Then, take the index and multiply it by the number of bytes in the
                    // structure.
                    // The length of the WLAN_INTERFACE_INFO structure is 532 bytes - this
                    // was determined by doing a Marshall.SizeOf(WLAN_INTERFACE_INFO) 
                    var pItemList = new IntPtr(pList.ToInt64() + i*532 + 8);

                    // Construct the WLAN_INTERFACE_INFO structure, marshal the unmanaged
                    // structure into it, then copy it to the array of structures.
                    InterfaceInfo[i] =
                        (WLAN_INTERFACE_INFO) Marshal.PtrToStructure(pItemList, typeof(WLAN_INTERFACE_INFO));
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_PROFILE_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string StrProfileName;
            public uint DwFlags;
        }

        public struct WLAN_PROFILE_INFO_LIST
        {
            public uint DwIndex;
            public uint DwNumberOfItems;
            public WLAN_PROFILE_INFO[] ProfileInfo;

            public WLAN_PROFILE_INFO_LIST(IntPtr ppProfileList)
            {
                DwNumberOfItems = (uint) Marshal.ReadInt32(ppProfileList);
                DwIndex = (uint) Marshal.ReadInt32(ppProfileList, 4);
                ProfileInfo = new WLAN_PROFILE_INFO[DwNumberOfItems];
                var ppProfileListTemp = new IntPtr(ppProfileList.ToInt64() + 8);

                for (var i = 0; i < DwNumberOfItems; i++)
                {
                    ppProfileList =
                        new IntPtr(ppProfileListTemp.ToInt64() + i*Marshal.SizeOf(typeof(WLAN_PROFILE_INFO)));
                    ProfileInfo[i] =
                        (WLAN_PROFILE_INFO) Marshal.PtrToStructure(ppProfileList, typeof(WLAN_PROFILE_INFO));
                }
            }
        }
    }
}