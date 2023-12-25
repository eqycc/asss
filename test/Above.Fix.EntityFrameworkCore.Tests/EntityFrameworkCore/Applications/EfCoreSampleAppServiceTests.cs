using Above.Fix.Samples;
using Xunit;

namespace Above.Fix.EntityFrameworkCore.Applications;

[Collection(FixTestConsts.CollectionDefinitionName)]
public class EfCoreSampleAppServiceTests : SampleAppServiceTests<FixEntityFrameworkCoreTestModule>
{

}
