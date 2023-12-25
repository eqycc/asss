using Above.Fix.Localization;
using Volo.Abp.AspNetCore.Mvc;

namespace Above.Fix.Controllers;

/* Inherit your controllers from this class.
 */
public abstract class FixController : AbpControllerBase
{
    protected FixController()
    {
        LocalizationResource = typeof(FixResource);
    }
}
