using System.Runtime.Serialization;

namespace LibCredentials
{
    [DataContract]
    public class Credential
    {
        public Credential()
        {
        }

        public Credential(TargetTypes type)
            : this()
        {
            Type = type;
        }

        [DataMember]
        public string Extra { get; set; }

        [DataMember]
        public string Password { get; set; }

        [DataMember]
        public TargetTypes Type { get; set; }

        //[DataMember]
        //public string TypeStr => Type.ToString();

        [DataMember]
        public string Username { get; set; }

        public override string ToString() =>
            "Type: " + Type +
            "\tUsername: " + Username +
            "\tPassword: " + Password +
            "\tExtra: " + Extra;
    }
}