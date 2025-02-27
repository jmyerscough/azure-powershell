namespace Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210
{
    using static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Extensions;

    /// <summary>Reprotect agent details.</summary>
    public partial class ReprotectAgentDetails :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetails,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal
    {

        /// <summary>Backing field for <see cref="BiosId" /> property.</summary>
        private string _biosId;

        /// <summary>The reprotect agent Bios Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string BiosId { get => this._biosId; }

        /// <summary>Backing field for <see cref="FabricObjectId" /> property.</summary>
        private string _fabricObjectId;

        /// <summary>The fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string FabricObjectId { get => this._fabricObjectId; }

        /// <summary>Backing field for <see cref="Fqdn" /> property.</summary>
        private string _fqdn;

        /// <summary>The reprotect agent Fqdn.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string Fqdn { get => this._fqdn; }

        /// <summary>Backing field for <see cref="Health" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth? _health;

        /// <summary>The health of the reprotect agent.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth? Health { get => this._health; }

        /// <summary>Backing field for <see cref="HealthError" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError[] _healthError;

        /// <summary>The health errors.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError[] HealthError { get => this._healthError; }

        /// <summary>Backing field for <see cref="Id" /> property.</summary>
        private string _id;

        /// <summary>The reprotect agent Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string Id { get => this._id; }

        /// <summary>Backing field for <see cref="LastHeartbeatUtc" /> property.</summary>
        private global::System.DateTime? _lastHeartbeatUtc;

        /// <summary>The last heartbeat received from the reprotect agent.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public global::System.DateTime? LastHeartbeatUtc { get => this._lastHeartbeatUtc; }

        /// <summary>Internal Acessors for BiosId</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.BiosId { get => this._biosId; set { {_biosId = value;} } }

        /// <summary>Internal Acessors for FabricObjectId</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.FabricObjectId { get => this._fabricObjectId; set { {_fabricObjectId = value;} } }

        /// <summary>Internal Acessors for Fqdn</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.Fqdn { get => this._fqdn; set { {_fqdn = value;} } }

        /// <summary>Internal Acessors for Health</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth? Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.Health { get => this._health; set { {_health = value;} } }

        /// <summary>Internal Acessors for HealthError</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError[] Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.HealthError { get => this._healthError; set { {_healthError = value;} } }

        /// <summary>Internal Acessors for Id</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.Id { get => this._id; set { {_id = value;} } }

        /// <summary>Internal Acessors for LastHeartbeatUtc</summary>
        global::System.DateTime? Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.LastHeartbeatUtc { get => this._lastHeartbeatUtc; set { {_lastHeartbeatUtc = value;} } }

        /// <summary>Internal Acessors for Name</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.Name { get => this._name; set { {_name = value;} } }

        /// <summary>Internal Acessors for Version</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReprotectAgentDetailsInternal.Version { get => this._version; set { {_version = value;} } }

        /// <summary>Backing field for <see cref="Name" /> property.</summary>
        private string _name;

        /// <summary>The reprotect agent name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string Name { get => this._name; }

        /// <summary>Backing field for <see cref="Version" /> property.</summary>
        private string _version;

        /// <summary>The version.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string Version { get => this._version; }

        /// <summary>Creates an new <see cref="ReprotectAgentDetails" /> instance.</summary>
        public ReprotectAgentDetails()
        {

        }
    }
    /// Reprotect agent details.
    public partial interface IReprotectAgentDetails :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IJsonSerializable
    {
        /// <summary>The reprotect agent Bios Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The reprotect agent Bios Id.",
        SerializedName = @"biosId",
        PossibleTypes = new [] { typeof(string) })]
        string BiosId { get;  }
        /// <summary>The fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The fabric object Id.",
        SerializedName = @"fabricObjectId",
        PossibleTypes = new [] { typeof(string) })]
        string FabricObjectId { get;  }
        /// <summary>The reprotect agent Fqdn.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The reprotect agent Fqdn.",
        SerializedName = @"fqdn",
        PossibleTypes = new [] { typeof(string) })]
        string Fqdn { get;  }
        /// <summary>The health of the reprotect agent.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The health of the reprotect agent.",
        SerializedName = @"health",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth? Health { get;  }
        /// <summary>The health errors.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The health errors.",
        SerializedName = @"healthErrors",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError[] HealthError { get;  }
        /// <summary>The reprotect agent Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The reprotect agent Id.",
        SerializedName = @"id",
        PossibleTypes = new [] { typeof(string) })]
        string Id { get;  }
        /// <summary>The last heartbeat received from the reprotect agent.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The last heartbeat received from the reprotect agent.",
        SerializedName = @"lastHeartbeatUtc",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? LastHeartbeatUtc { get;  }
        /// <summary>The reprotect agent name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The reprotect agent name.",
        SerializedName = @"name",
        PossibleTypes = new [] { typeof(string) })]
        string Name { get;  }
        /// <summary>The version.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The version.",
        SerializedName = @"version",
        PossibleTypes = new [] { typeof(string) })]
        string Version { get;  }

    }
    /// Reprotect agent details.
    internal partial interface IReprotectAgentDetailsInternal

    {
        /// <summary>The reprotect agent Bios Id.</summary>
        string BiosId { get; set; }
        /// <summary>The fabric object Id.</summary>
        string FabricObjectId { get; set; }
        /// <summary>The reprotect agent Fqdn.</summary>
        string Fqdn { get; set; }
        /// <summary>The health of the reprotect agent.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.ProtectionHealth? Health { get; set; }
        /// <summary>The health errors.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IHealthError[] HealthError { get; set; }
        /// <summary>The reprotect agent Id.</summary>
        string Id { get; set; }
        /// <summary>The last heartbeat received from the reprotect agent.</summary>
        global::System.DateTime? LastHeartbeatUtc { get; set; }
        /// <summary>The reprotect agent name.</summary>
        string Name { get; set; }
        /// <summary>The version.</summary>
        string Version { get; set; }

    }
}