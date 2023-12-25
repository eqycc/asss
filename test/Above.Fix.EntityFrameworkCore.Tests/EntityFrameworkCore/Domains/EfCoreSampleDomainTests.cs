using Above.Fix.Samples;
using Xunit;

namespace Above.Fix.EntityFrameworkCore.Domains;

[Collection(FixTestConsts.CollectionDefinitionName)]
public class EfCoreSampleDomainTests : SampleDomainTests<FixEntityFrameworkCoreTestModule>
{

}
