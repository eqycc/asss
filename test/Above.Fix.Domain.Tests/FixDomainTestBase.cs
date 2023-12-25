using Volo.Abp.Modularity;

namespace Above.Fix;

/* Inherit from this class for your domain layer tests. */
public abstract class FixDomainTestBase<TStartupModule> : FixTestBase<TStartupModule>
    where TStartupModule : IAbpModule
{

}
