namespace ClassLibrary1.Models
{
    public class LDAPAppSetting
    {
        public bool IsBypass { get; set; }
        public string Domain { get; set; }
        public string Server { get; set; }
        public int Port { get; set; }
        public string BaseDn { get; set; }
    }
}
