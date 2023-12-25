using Volo.Abp.Ui.Branding;
using Volo.Abp.DependencyInjection;

namespace Above.Fix.Web;

[Dependency(ReplaceServices = true)]
public class FixBrandingProvider : DefaultBrandingProvider
{
    public override string AppName => "Fix";
}
