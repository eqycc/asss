using Volo.Abp.Modularity;

namespace Above.Fix;

[DependsOn(
    typeof(FixDomainModule),
    typeof(FixTestBaseModule)
)]
public class FixDomainTestModule : AbpModule
{

}
