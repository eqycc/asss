using Above.Fix.EntityFrameworkCore;
using Volo.Abp.Autofac;
using Volo.Abp.Modularity;

namespace Above.Fix.DbMigrator;

[DependsOn(
    typeof(AbpAutofacModule),
    typeof(FixEntityFrameworkCoreModule),
    typeof(FixApplicationContractsModule)
    )]
public class FixDbMigratorModule : AbpModule
{
}
