using Above.Fix.Localization;
using Volo.Abp.AspNetCore.Mvc.UI.RazorPages;

namespace Above.Fix.Web.Pages;

/* Inherit your PageModel classes from this class.
 */
public abstract class FixPageModel : AbpPageModel
{
    protected FixPageModel()
    {
        LocalizationResourceType = typeof(FixResource);
    }
}
