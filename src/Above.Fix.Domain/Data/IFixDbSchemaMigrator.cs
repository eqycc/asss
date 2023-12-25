using System.Threading.Tasks;

namespace Above.Fix.Data;

public interface IFixDbSchemaMigrator
{
    Task MigrateAsync();
}
