using Microsoft.AspNetCore.Builder;
using Above.Fix;
using Volo.Abp.AspNetCore.TestBase;

var builder = WebApplication.CreateBuilder();
await builder.RunAbpModuleAsync<FixWebTestModule>();

public partial class Program
{
}
