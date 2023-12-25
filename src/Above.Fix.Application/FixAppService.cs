using System;
using System.Collections.Generic;
using System.Text;
using Above.Fix.Localization;
using Volo.Abp.Application.Services;

namespace Above.Fix;

/* Inherit your application services from this class.
 */
public abstract class FixAppService : ApplicationService
{
    protected FixAppService()
    {
        LocalizationResource = typeof(FixResource);
    }
}
