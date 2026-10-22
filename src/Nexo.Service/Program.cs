using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nexo.Service;

// Como servicio de Windows (SCM) o, ejecutado a mano, como aplicacion de consola.
// AddWindowsService detecta cual de los dos es.
HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "NexoService");
builder.Services.AddHostedService<NexoWorker>();
// El SCM da 5 s para parar (Salida 0, §3): el pipe se cierra en menos de 4 s.
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(4));

await builder.Build().RunAsync();
