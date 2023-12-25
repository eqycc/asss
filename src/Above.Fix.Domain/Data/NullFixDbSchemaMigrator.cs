using System.Threading.Tasks;
using Volo.Abp.DependencyInjection;

namespace Above.Fix.Data;

/* This is used if database provider does't define
 * IFixDbSchemaMigrator implementation.
 */
public class NullFixDbSchemaMigrator : IFixDbSchemaMigrator, ITransientDependency
{
    public Task MigrateAsync()
    {
        return Task.CompletedTask;
    }
}
