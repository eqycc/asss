using Volo.Abp.Modularity;

namespace Above.Fix;

public abstract class FixApplicationTestBase<TStartupModule> : FixTestBase<TStartupModule>
    where TStartupModule : IAbpModule
{

}
