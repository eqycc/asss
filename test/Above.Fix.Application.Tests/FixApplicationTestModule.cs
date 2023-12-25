using Volo.Abp.Modularity;

namespace Above.Fix;

[DependsOn(
    typeof(FixApplicationModule),
    typeof(FixDomainTestModule)
)]
public class FixApplicationTestModule : AbpModule
{

}
