using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

Host.CreateDefaultBuilder(args)
    .UseWindowsService()
    .ConfigureServices((ctx, services) =>
    {
        services.Configure<AgentOptions>(ctx.Configuration.GetSection("Agent"));
        services.AddHttpClient("api");
        services.AddSingleton<DriverComm>();
        services.AddHostedService<Worker>();
    })
    .Build()
    .Run();