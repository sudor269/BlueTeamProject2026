using System.Net.Http.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IHttpClientFactory _httpFactory;
    private readonly DriverComm _driver;
    private readonly AgentOptions _opts;

    private int _lastPolicyVersion = -1;

    public Worker(
        ILogger<Worker> logger,
        IHttpClientFactory httpFactory,
        DriverComm driver,
        IOptions<AgentOptions> opts)
    {
        _logger = logger;
        _httpFactory = httpFactory;
        _driver = driver;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("UsbGuardAgent started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SyncPolicy(stoppingToken);
                await SendHeartbeat(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Sync loop failed");
            }

            await Task.Delay(TimeSpan.FromSeconds(_opts.SyncSeconds), stoppingToken);
        }
    }

    private async Task SyncPolicy(CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("api");
        client.BaseAddress = new Uri(_opts.ApiBaseUrl);

        var url = $"/agent/policy?host={Uri.EscapeDataString(_opts.Hostname)}";
        var policy = await client.GetFromJsonAsync<PolicyResponse>(url, ct);
        if (policy == null)
        {
            _logger.LogWarning("Policy is null");
            return;
        }

        if (policy.version == _lastPolicyVersion)
            return;

        _logger.LogInformation("New policy version {Version}, hashes={Count}", policy.version, policy.hashes.Count);

        var hashes = policy.hashes.Select(DriverComm.ParseHex64).ToList();

        _driver.SetPolicy(policy.audit_only, policy.default_allow_if_no_serial);
        _driver.SetWhitelist((ulong)policy.version, hashes);

        var status = _driver.GetStatus();
        _logger.LogInformation("Driver status: WlCount={Count}, WlVersion={Ver}", status.WlCount, status.WlVersion);

        _lastPolicyVersion = policy.version;
    }

    private async Task SendHeartbeat(CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("api");
        client.BaseAddress = new Uri(_opts.ApiBaseUrl);

        var body = new
        {
            host = _opts.Hostname,
            ts = DateTimeOffset.UtcNow,
            status = "ok"
        };

        using var resp = await client.PostAsJsonAsync("/agent/heartbeat", body, ct);
        resp.EnsureSuccessStatusCode();
    }
}