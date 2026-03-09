public class AgentOptions
{
    public string ApiBaseUrl { get; set; } = "http://127.0.0.1:8000";
    public string Hostname { get; set; } = Environment.MachineName;
    public int SyncSeconds { get; set; } = 15;
    public bool AuditOnly { get; set; } = false;
    public bool DefaultAllowIfNoSerial { get; set; } = false;
}

public class PolicyResponse
{
    public int version { get; set; }
    public bool audit_only { get; set; }
    public bool default_allow_if_no_serial { get; set; }
    public List<string> hashes { get; set; } = new();
}