namespace Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210
{
    using static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Extensions;

    /// <summary>The target VM tags.</summary>
    public partial class VMwareCbtUpdateMigrationItemInputTargetVmtags :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMwareCbtUpdateMigrationItemInputTargetVmtags,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMwareCbtUpdateMigrationItemInputTargetVmtagsInternal
    {

        /// <summary>
        /// Creates an new <see cref="VMwareCbtUpdateMigrationItemInputTargetVmtags" /> instance.
        /// </summary>
        public VMwareCbtUpdateMigrationItemInputTargetVmtags()
        {

        }
    }
    /// The target VM tags.
    public partial interface IVMwareCbtUpdateMigrationItemInputTargetVmtags :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IJsonSerializable,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IAssociativeArray<string>
    {

    }
    /// The target VM tags.
    internal partial interface IVMwareCbtUpdateMigrationItemInputTargetVmtagsInternal

    {

    }
}