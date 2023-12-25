using Xunit;

namespace Above.Fix.EntityFrameworkCore;

[CollectionDefinition(FixTestConsts.CollectionDefinitionName)]
public class FixEntityFrameworkCoreCollection : ICollectionFixture<FixEntityFrameworkCoreFixture>
{

}
