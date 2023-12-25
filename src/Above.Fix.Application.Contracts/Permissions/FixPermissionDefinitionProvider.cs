using Above.Fix.Localization;
using Volo.Abp.Authorization.Permissions;
using Volo.Abp.Localization;

namespace Above.Fix.Permissions;

public class FixPermissionDefinitionProvider : PermissionDefinitionProvider
{
    public override void Define(IPermissionDefinitionContext context)
    {
        var myGroup = context.AddGroup(FixPermissions.GroupName);
        //Define your own permissions here. Example:
        //myGroup.AddPermission(FixPermissions.MyPermission1, L("Permission:MyPermission1"));
    }

    private static LocalizableString L(string name)
    {
        return LocalizableString.Create<FixResource>(name);
    }
}
