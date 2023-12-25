using Volo.Abp.Settings;

namespace Above.Fix.Settings;

public class FixSettingDefinitionProvider : SettingDefinitionProvider
{
    public override void Define(ISettingDefinitionContext context)
    {
        //Define your own settings here. Example:
        //context.Add(new SettingDefinition(FixSettings.MySetting1));
    }
}
