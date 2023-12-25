using System.Threading.Tasks;
using Shouldly;
using Xunit;

namespace Above.Fix.Pages;

public class Index_Tests : FixWebTestBase
{
    [Fact]
    public async Task Welcome_Page()
    {
        var response = await GetResponseAsStringAsync("/");
        response.ShouldNotBeNull();
    }
}
