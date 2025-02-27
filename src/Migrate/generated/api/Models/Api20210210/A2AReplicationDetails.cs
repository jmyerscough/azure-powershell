namespace Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210
{
    using static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Extensions;

    /// <summary>A2A provider specific settings.</summary>
    public partial class A2AReplicationDetails :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetails,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IValidates
    {
        /// <summary>
        /// Backing field for Inherited model <see cref= "Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettings"
        /// />
        /// </summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettings __replicationProviderSpecificSettings = new Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.ReplicationProviderSpecificSettings();

        /// <summary>Backing field for <see cref="AgentCertificateExpiryDate" /> property.</summary>
        private global::System.DateTime? _agentCertificateExpiryDate;

        /// <summary>Agent certificate expiry date.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public global::System.DateTime? AgentCertificateExpiryDate { get => this._agentCertificateExpiryDate; }

        /// <summary>Backing field for <see cref="AgentExpiryDate" /> property.</summary>
        private global::System.DateTime? _agentExpiryDate;

        /// <summary>Agent expiry date.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public global::System.DateTime? AgentExpiryDate { get => this._agentExpiryDate; set => this._agentExpiryDate = value; }

        /// <summary>Backing field for <see cref="AgentVersion" /> property.</summary>
        private string _agentVersion;

        /// <summary>The agent version.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string AgentVersion { get => this._agentVersion; set => this._agentVersion = value; }

        /// <summary>Backing field for <see cref="AutoProtectionOfDataDisk" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.AutoProtectionOfDataDisk? _autoProtectionOfDataDisk;

        /// <summary>A value indicating whether the auto protection is enabled.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.AutoProtectionOfDataDisk? AutoProtectionOfDataDisk { get => this._autoProtectionOfDataDisk; set => this._autoProtectionOfDataDisk = value; }

        /// <summary>Backing field for <see cref="FabricObjectId" /> property.</summary>
        private string _fabricObjectId;

        /// <summary>The fabric specific object Id of the virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string FabricObjectId { get => this._fabricObjectId; set => this._fabricObjectId = value; }

        /// <summary>Backing field for <see cref="InitialPrimaryFabricLocation" /> property.</summary>
        private string _initialPrimaryFabricLocation;

        /// <summary>The initial primary fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string InitialPrimaryFabricLocation { get => this._initialPrimaryFabricLocation; }

        /// <summary>Backing field for <see cref="InitialPrimaryZone" /> property.</summary>
        private string _initialPrimaryZone;

        /// <summary>The initial primary availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string InitialPrimaryZone { get => this._initialPrimaryZone; }

        /// <summary>Backing field for <see cref="InitialRecoveryFabricLocation" /> property.</summary>
        private string _initialRecoveryFabricLocation;

        /// <summary>The initial recovery fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string InitialRecoveryFabricLocation { get => this._initialRecoveryFabricLocation; }

        /// <summary>Backing field for <see cref="InitialRecoveryZone" /> property.</summary>
        private string _initialRecoveryZone;

        /// <summary>The initial recovery availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string InitialRecoveryZone { get => this._initialRecoveryZone; }

        /// <summary>Gets the Instance type.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Inherited)]
        public string InstanceType { get => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettingsInternal)__replicationProviderSpecificSettings).InstanceType; }

        /// <summary>
        /// Backing field for <see cref="IsReplicationAgentCertificateUpdateRequired" /> property.
        /// </summary>
        private bool? _isReplicationAgentCertificateUpdateRequired;

        /// <summary>A value indicating whether agent certificate update is required.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public bool? IsReplicationAgentCertificateUpdateRequired { get => this._isReplicationAgentCertificateUpdateRequired; set => this._isReplicationAgentCertificateUpdateRequired = value; }

        /// <summary>Backing field for <see cref="IsReplicationAgentUpdateRequired" /> property.</summary>
        private bool? _isReplicationAgentUpdateRequired;

        /// <summary>A value indicating whether replication agent update is required.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public bool? IsReplicationAgentUpdateRequired { get => this._isReplicationAgentUpdateRequired; set => this._isReplicationAgentUpdateRequired = value; }

        /// <summary>Backing field for <see cref="LastHeartbeat" /> property.</summary>
        private global::System.DateTime? _lastHeartbeat;

        /// <summary>The last heartbeat received from the source server.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public global::System.DateTime? LastHeartbeat { get => this._lastHeartbeat; set => this._lastHeartbeat = value; }

        /// <summary>Backing field for <see cref="LastRpoCalculatedTime" /> property.</summary>
        private global::System.DateTime? _lastRpoCalculatedTime;

        /// <summary>The time (in UTC) when the last RPO value was calculated by Protection Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public global::System.DateTime? LastRpoCalculatedTime { get => this._lastRpoCalculatedTime; set => this._lastRpoCalculatedTime = value; }

        /// <summary>Backing field for <see cref="LifecycleId" /> property.</summary>
        private string _lifecycleId;

        /// <summary>
        /// An id associated with the PE that survives actions like switch protection which change the backing PE/CPE objects internally.The
        /// lifecycle id gets carried forward to have a link/continuity in being able to have an Id that denotes the "same" protected
        /// item even though other internal Ids/ARM Id might be changing.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string LifecycleId { get => this._lifecycleId; set => this._lifecycleId = value; }

        /// <summary>Backing field for <see cref="ManagementId" /> property.</summary>
        private string _managementId;

        /// <summary>The management Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string ManagementId { get => this._managementId; set => this._managementId = value; }

        /// <summary>Internal Acessors for AgentCertificateExpiryDate</summary>
        global::System.DateTime? Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.AgentCertificateExpiryDate { get => this._agentCertificateExpiryDate; set { {_agentCertificateExpiryDate = value;} } }

        /// <summary>Internal Acessors for InitialPrimaryFabricLocation</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.InitialPrimaryFabricLocation { get => this._initialPrimaryFabricLocation; set { {_initialPrimaryFabricLocation = value;} } }

        /// <summary>Internal Acessors for InitialPrimaryZone</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.InitialPrimaryZone { get => this._initialPrimaryZone; set { {_initialPrimaryZone = value;} } }

        /// <summary>Internal Acessors for InitialRecoveryFabricLocation</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.InitialRecoveryFabricLocation { get => this._initialRecoveryFabricLocation; set { {_initialRecoveryFabricLocation = value;} } }

        /// <summary>Internal Acessors for InitialRecoveryZone</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.InitialRecoveryZone { get => this._initialRecoveryZone; set { {_initialRecoveryZone = value;} } }

        /// <summary>Internal Acessors for RecoveryAzureGeneration</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.RecoveryAzureGeneration { get => this._recoveryAzureGeneration; set { {_recoveryAzureGeneration = value;} } }

        /// <summary>Internal Acessors for VMEncryptionType</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType? Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.VMEncryptionType { get => this._vMEncryptionType; set { {_vMEncryptionType = value;} } }

        /// <summary>Internal Acessors for VMSyncedConfigDetail</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetails Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AReplicationDetailsInternal.VMSyncedConfigDetail { get => (this._vMSyncedConfigDetail = this._vMSyncedConfigDetail ?? new Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.AzureToAzureVMSyncedConfigDetails()); set { {_vMSyncedConfigDetail = value;} } }

        /// <summary>Internal Acessors for InstanceType</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettingsInternal.InstanceType { get => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettingsInternal)__replicationProviderSpecificSettings).InstanceType; set => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettingsInternal)__replicationProviderSpecificSettings).InstanceType = value; }

        /// <summary>Backing field for <see cref="MonitoringJobType" /> property.</summary>
        private string _monitoringJobType;

        /// <summary>
        /// The type of the monitoring job. The progress is contained in MonitoringPercentageCompletion property.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string MonitoringJobType { get => this._monitoringJobType; set => this._monitoringJobType = value; }

        /// <summary>Backing field for <see cref="MonitoringPercentageCompletion" /> property.</summary>
        private int? _monitoringPercentageCompletion;

        /// <summary>
        /// The percentage of the monitoring job. The type of the monitoring job is defined by MonitoringJobType property.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public int? MonitoringPercentageCompletion { get => this._monitoringPercentageCompletion; set => this._monitoringPercentageCompletion = value; }

        /// <summary>Backing field for <see cref="MultiVMGroupCreateOption" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.MultiVMGroupCreateOption? _multiVMGroupCreateOption;

        /// <summary>Whether Multi VM group is auto created or specified by user.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.MultiVMGroupCreateOption? MultiVMGroupCreateOption { get => this._multiVMGroupCreateOption; set => this._multiVMGroupCreateOption = value; }

        /// <summary>Backing field for <see cref="MultiVMGroupId" /> property.</summary>
        private string _multiVMGroupId;

        /// <summary>The multi vm group Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string MultiVMGroupId { get => this._multiVMGroupId; set => this._multiVMGroupId = value; }

        /// <summary>Backing field for <see cref="MultiVMGroupName" /> property.</summary>
        private string _multiVMGroupName;

        /// <summary>The multi vm group name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string MultiVMGroupName { get => this._multiVMGroupName; set => this._multiVMGroupName = value; }

        /// <summary>Backing field for <see cref="OSType" /> property.</summary>
        private string _oSType;

        /// <summary>The type of operating system.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string OSType { get => this._oSType; set => this._oSType = value; }

        /// <summary>Backing field for <see cref="PrimaryAvailabilityZone" /> property.</summary>
        private string _primaryAvailabilityZone;

        /// <summary>The primary availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string PrimaryAvailabilityZone { get => this._primaryAvailabilityZone; set => this._primaryAvailabilityZone = value; }

        /// <summary>Backing field for <see cref="PrimaryFabricLocation" /> property.</summary>
        private string _primaryFabricLocation;

        /// <summary>Primary fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string PrimaryFabricLocation { get => this._primaryFabricLocation; set => this._primaryFabricLocation = value; }

        /// <summary>Backing field for <see cref="ProtectedDisk" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedDiskDetails[] _protectedDisk;

        /// <summary>The list of protected disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedDiskDetails[] ProtectedDisk { get => this._protectedDisk; set => this._protectedDisk = value; }

        /// <summary>Backing field for <see cref="ProtectedManagedDisk" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedManagedDiskDetails[] _protectedManagedDisk;

        /// <summary>The list of protected managed disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedManagedDiskDetails[] ProtectedManagedDisk { get => this._protectedManagedDisk; set => this._protectedManagedDisk = value; }

        /// <summary>Backing field for <see cref="RecoveryAvailabilitySet" /> property.</summary>
        private string _recoveryAvailabilitySet;

        /// <summary>The recovery availability set.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAvailabilitySet { get => this._recoveryAvailabilitySet; set => this._recoveryAvailabilitySet = value; }

        /// <summary>Backing field for <see cref="RecoveryAvailabilityZone" /> property.</summary>
        private string _recoveryAvailabilityZone;

        /// <summary>The recovery availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAvailabilityZone { get => this._recoveryAvailabilityZone; set => this._recoveryAvailabilityZone = value; }

        /// <summary>Backing field for <see cref="RecoveryAzureGeneration" /> property.</summary>
        private string _recoveryAzureGeneration;

        /// <summary>The recovery azure generation.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAzureGeneration { get => this._recoveryAzureGeneration; }

        /// <summary>Backing field for <see cref="RecoveryAzureResourceGroupId" /> property.</summary>
        private string _recoveryAzureResourceGroupId;

        /// <summary>The recovery resource group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAzureResourceGroupId { get => this._recoveryAzureResourceGroupId; set => this._recoveryAzureResourceGroupId = value; }

        /// <summary>Backing field for <see cref="RecoveryAzureVMName" /> property.</summary>
        private string _recoveryAzureVMName;

        /// <summary>The name of recovery virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAzureVMName { get => this._recoveryAzureVMName; set => this._recoveryAzureVMName = value; }

        /// <summary>Backing field for <see cref="RecoveryAzureVMSize" /> property.</summary>
        private string _recoveryAzureVMSize;

        /// <summary>The size of recovery virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryAzureVMSize { get => this._recoveryAzureVMSize; set => this._recoveryAzureVMSize = value; }

        /// <summary>Backing field for <see cref="RecoveryBootDiagStorageAccountId" /> property.</summary>
        private string _recoveryBootDiagStorageAccountId;

        /// <summary>The recovery boot diagnostic storage account Arm Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryBootDiagStorageAccountId { get => this._recoveryBootDiagStorageAccountId; set => this._recoveryBootDiagStorageAccountId = value; }

        /// <summary>Backing field for <see cref="RecoveryCloudService" /> property.</summary>
        private string _recoveryCloudService;

        /// <summary>The recovery cloud service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryCloudService { get => this._recoveryCloudService; set => this._recoveryCloudService = value; }

        /// <summary>Backing field for <see cref="RecoveryFabricLocation" /> property.</summary>
        private string _recoveryFabricLocation;

        /// <summary>The recovery fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryFabricLocation { get => this._recoveryFabricLocation; set => this._recoveryFabricLocation = value; }

        /// <summary>Backing field for <see cref="RecoveryFabricObjectId" /> property.</summary>
        private string _recoveryFabricObjectId;

        /// <summary>The recovery fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryFabricObjectId { get => this._recoveryFabricObjectId; set => this._recoveryFabricObjectId = value; }

        /// <summary>Backing field for <see cref="RecoveryProximityPlacementGroupId" /> property.</summary>
        private string _recoveryProximityPlacementGroupId;

        /// <summary>The recovery proximity placement group Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryProximityPlacementGroupId { get => this._recoveryProximityPlacementGroupId; set => this._recoveryProximityPlacementGroupId = value; }

        /// <summary>Backing field for <see cref="RecoveryVirtualMachineScaleSetId" /> property.</summary>
        private string _recoveryVirtualMachineScaleSetId;

        /// <summary>The recovery virtual machine scale set id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string RecoveryVirtualMachineScaleSetId { get => this._recoveryVirtualMachineScaleSetId; set => this._recoveryVirtualMachineScaleSetId = value; }

        /// <summary>Backing field for <see cref="RpoInSecond" /> property.</summary>
        private long? _rpoInSecond;

        /// <summary>The last RPO value in seconds.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public long? RpoInSecond { get => this._rpoInSecond; set => this._rpoInSecond = value; }

        /// <summary>Backing field for <see cref="SelectedRecoveryAzureNetworkId" /> property.</summary>
        private string _selectedRecoveryAzureNetworkId;

        /// <summary>The recovery virtual network.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string SelectedRecoveryAzureNetworkId { get => this._selectedRecoveryAzureNetworkId; set => this._selectedRecoveryAzureNetworkId = value; }

        /// <summary>Backing field for <see cref="SelectedTfoAzureNetworkId" /> property.</summary>
        private string _selectedTfoAzureNetworkId;

        /// <summary>The test failover virtual network.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string SelectedTfoAzureNetworkId { get => this._selectedTfoAzureNetworkId; set => this._selectedTfoAzureNetworkId = value; }

        /// <summary>Backing field for <see cref="TestFailoverRecoveryFabricObjectId" /> property.</summary>
        private string _testFailoverRecoveryFabricObjectId;

        /// <summary>The test failover fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string TestFailoverRecoveryFabricObjectId { get => this._testFailoverRecoveryFabricObjectId; set => this._testFailoverRecoveryFabricObjectId = value; }

        /// <summary>Backing field for <see cref="TfoAzureVMName" /> property.</summary>
        private string _tfoAzureVMName;

        /// <summary>The test failover vm name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string TfoAzureVMName { get => this._tfoAzureVMName; set => this._tfoAzureVMName = value; }

        /// <summary>Backing field for <see cref="UnprotectedDisk" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AUnprotectedDiskDetails[] _unprotectedDisk;

        /// <summary>The list of unprotected disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AUnprotectedDiskDetails[] UnprotectedDisk { get => this._unprotectedDisk; set => this._unprotectedDisk = value; }

        /// <summary>Backing field for <see cref="VMEncryptionType" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType? _vMEncryptionType;

        /// <summary>The encryption type of the VM.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType? VMEncryptionType { get => this._vMEncryptionType; }

        /// <summary>Backing field for <see cref="VMNic" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMNicDetails[] _vMNic;

        /// <summary>The virtual machine nic details.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMNicDetails[] VMNic { get => this._vMNic; set => this._vMNic = value; }

        /// <summary>Backing field for <see cref="VMProtectionState" /> property.</summary>
        private string _vMProtectionState;

        /// <summary>The protection state for the vm.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string VMProtectionState { get => this._vMProtectionState; set => this._vMProtectionState = value; }

        /// <summary>Backing field for <see cref="VMProtectionStateDescription" /> property.</summary>
        private string _vMProtectionStateDescription;

        /// <summary>The protection state description for the vm.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        public string VMProtectionStateDescription { get => this._vMProtectionStateDescription; set => this._vMProtectionStateDescription = value; }

        /// <summary>Backing field for <see cref="VMSyncedConfigDetail" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetails _vMSyncedConfigDetail;

        /// <summary>The synced configuration details.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Owned)]
        internal Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetails VMSyncedConfigDetail { get => (this._vMSyncedConfigDetail = this._vMSyncedConfigDetail ?? new Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.AzureToAzureVMSyncedConfigDetails()); set => this._vMSyncedConfigDetail = value; }

        /// <summary>The Azure VM input endpoints.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Inlined)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInputEndpoint[] VMSyncedConfigDetailInputEndpoint { get => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsInternal)VMSyncedConfigDetail).InputEndpoint; set => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsInternal)VMSyncedConfigDetail).InputEndpoint = value ?? null /* arrayOf */; }

        /// <summary>The Azure VM tags.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Origin(Microsoft.Azure.PowerShell.Cmdlets.Migrate.PropertyOrigin.Inlined)]
        public Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsTags VMSyncedConfigDetailTag { get => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsInternal)VMSyncedConfigDetail).Tag; set => ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsInternal)VMSyncedConfigDetail).Tag = value ?? null /* model class */; }

        /// <summary>Creates an new <see cref="A2AReplicationDetails" /> instance.</summary>
        public A2AReplicationDetails()
        {

        }

        /// <summary>Validates that this object meets the validation criteria.</summary>
        /// <param name="eventListener">an <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IEventListener" /> instance that will receive validation
        /// events.</param>
        /// <returns>
        /// A < see cref = "global::System.Threading.Tasks.Task" /> that will be complete when validation is completed.
        /// </returns>
        public async global::System.Threading.Tasks.Task Validate(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IEventListener eventListener)
        {
            await eventListener.AssertNotNull(nameof(__replicationProviderSpecificSettings), __replicationProviderSpecificSettings);
            await eventListener.AssertObjectIsValid(nameof(__replicationProviderSpecificSettings), __replicationProviderSpecificSettings);
        }
    }
    /// A2A provider specific settings.
    public partial interface IA2AReplicationDetails :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.IJsonSerializable,
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettings
    {
        /// <summary>Agent certificate expiry date.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Agent certificate expiry date.",
        SerializedName = @"agentCertificateExpiryDate",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? AgentCertificateExpiryDate { get;  }
        /// <summary>Agent expiry date.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"Agent expiry date.",
        SerializedName = @"agentExpiryDate",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? AgentExpiryDate { get; set; }
        /// <summary>The agent version.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The agent version.",
        SerializedName = @"agentVersion",
        PossibleTypes = new [] { typeof(string) })]
        string AgentVersion { get; set; }
        /// <summary>A value indicating whether the auto protection is enabled.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"A value indicating whether the auto protection is enabled.",
        SerializedName = @"autoProtectionOfDataDisk",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.AutoProtectionOfDataDisk) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.AutoProtectionOfDataDisk? AutoProtectionOfDataDisk { get; set; }
        /// <summary>The fabric specific object Id of the virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The fabric specific object Id of the virtual machine.",
        SerializedName = @"fabricObjectId",
        PossibleTypes = new [] { typeof(string) })]
        string FabricObjectId { get; set; }
        /// <summary>The initial primary fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The initial primary fabric location.",
        SerializedName = @"initialPrimaryFabricLocation",
        PossibleTypes = new [] { typeof(string) })]
        string InitialPrimaryFabricLocation { get;  }
        /// <summary>The initial primary availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The initial primary availability zone.",
        SerializedName = @"initialPrimaryZone",
        PossibleTypes = new [] { typeof(string) })]
        string InitialPrimaryZone { get;  }
        /// <summary>The initial recovery fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The initial recovery fabric location.",
        SerializedName = @"initialRecoveryFabricLocation",
        PossibleTypes = new [] { typeof(string) })]
        string InitialRecoveryFabricLocation { get;  }
        /// <summary>The initial recovery availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The initial recovery availability zone.",
        SerializedName = @"initialRecoveryZone",
        PossibleTypes = new [] { typeof(string) })]
        string InitialRecoveryZone { get;  }
        /// <summary>A value indicating whether agent certificate update is required.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"A value indicating whether agent certificate update is required.",
        SerializedName = @"isReplicationAgentCertificateUpdateRequired",
        PossibleTypes = new [] { typeof(bool) })]
        bool? IsReplicationAgentCertificateUpdateRequired { get; set; }
        /// <summary>A value indicating whether replication agent update is required.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"A value indicating whether replication agent update is required.",
        SerializedName = @"isReplicationAgentUpdateRequired",
        PossibleTypes = new [] { typeof(bool) })]
        bool? IsReplicationAgentUpdateRequired { get; set; }
        /// <summary>The last heartbeat received from the source server.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The last heartbeat received from the source server.",
        SerializedName = @"lastHeartbeat",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? LastHeartbeat { get; set; }
        /// <summary>The time (in UTC) when the last RPO value was calculated by Protection Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The time (in UTC) when the last RPO value was calculated by Protection Service.",
        SerializedName = @"lastRpoCalculatedTime",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? LastRpoCalculatedTime { get; set; }
        /// <summary>
        /// An id associated with the PE that survives actions like switch protection which change the backing PE/CPE objects internally.The
        /// lifecycle id gets carried forward to have a link/continuity in being able to have an Id that denotes the "same" protected
        /// item even though other internal Ids/ARM Id might be changing.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"An id associated with the PE that survives actions like switch protection which change the backing PE/CPE objects internally.The lifecycle id gets carried forward to have a link/continuity in being able to have an Id that denotes the ""same"" protected item even though other internal Ids/ARM Id might be changing.",
        SerializedName = @"lifecycleId",
        PossibleTypes = new [] { typeof(string) })]
        string LifecycleId { get; set; }
        /// <summary>The management Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The management Id.",
        SerializedName = @"managementId",
        PossibleTypes = new [] { typeof(string) })]
        string ManagementId { get; set; }
        /// <summary>
        /// The type of the monitoring job. The progress is contained in MonitoringPercentageCompletion property.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The type of the monitoring job. The progress is contained in MonitoringPercentageCompletion property.",
        SerializedName = @"monitoringJobType",
        PossibleTypes = new [] { typeof(string) })]
        string MonitoringJobType { get; set; }
        /// <summary>
        /// The percentage of the monitoring job. The type of the monitoring job is defined by MonitoringJobType property.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The percentage of the monitoring job. The type of the monitoring job is defined by MonitoringJobType property.",
        SerializedName = @"monitoringPercentageCompletion",
        PossibleTypes = new [] { typeof(int) })]
        int? MonitoringPercentageCompletion { get; set; }
        /// <summary>Whether Multi VM group is auto created or specified by user.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"Whether Multi VM group is auto created or specified by user.",
        SerializedName = @"multiVmGroupCreateOption",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.MultiVMGroupCreateOption) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.MultiVMGroupCreateOption? MultiVMGroupCreateOption { get; set; }
        /// <summary>The multi vm group Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The multi vm group Id.",
        SerializedName = @"multiVmGroupId",
        PossibleTypes = new [] { typeof(string) })]
        string MultiVMGroupId { get; set; }
        /// <summary>The multi vm group name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The multi vm group name.",
        SerializedName = @"multiVmGroupName",
        PossibleTypes = new [] { typeof(string) })]
        string MultiVMGroupName { get; set; }
        /// <summary>The type of operating system.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The type of operating system.",
        SerializedName = @"osType",
        PossibleTypes = new [] { typeof(string) })]
        string OSType { get; set; }
        /// <summary>The primary availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The primary availability zone.",
        SerializedName = @"primaryAvailabilityZone",
        PossibleTypes = new [] { typeof(string) })]
        string PrimaryAvailabilityZone { get; set; }
        /// <summary>Primary fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"Primary fabric location.",
        SerializedName = @"primaryFabricLocation",
        PossibleTypes = new [] { typeof(string) })]
        string PrimaryFabricLocation { get; set; }
        /// <summary>The list of protected disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of protected disks.",
        SerializedName = @"protectedDisks",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedDiskDetails) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedDiskDetails[] ProtectedDisk { get; set; }
        /// <summary>The list of protected managed disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of protected managed disks.",
        SerializedName = @"protectedManagedDisks",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedManagedDiskDetails) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedManagedDiskDetails[] ProtectedManagedDisk { get; set; }
        /// <summary>The recovery availability set.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery availability set.",
        SerializedName = @"recoveryAvailabilitySet",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAvailabilitySet { get; set; }
        /// <summary>The recovery availability zone.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery availability zone.",
        SerializedName = @"recoveryAvailabilityZone",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAvailabilityZone { get; set; }
        /// <summary>The recovery azure generation.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The recovery azure generation.",
        SerializedName = @"recoveryAzureGeneration",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAzureGeneration { get;  }
        /// <summary>The recovery resource group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery resource group.",
        SerializedName = @"recoveryAzureResourceGroupId",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAzureResourceGroupId { get; set; }
        /// <summary>The name of recovery virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The name of recovery virtual machine.",
        SerializedName = @"recoveryAzureVMName",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAzureVMName { get; set; }
        /// <summary>The size of recovery virtual machine.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The size of recovery virtual machine.",
        SerializedName = @"recoveryAzureVMSize",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryAzureVMSize { get; set; }
        /// <summary>The recovery boot diagnostic storage account Arm Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery boot diagnostic storage account Arm Id.",
        SerializedName = @"recoveryBootDiagStorageAccountId",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryBootDiagStorageAccountId { get; set; }
        /// <summary>The recovery cloud service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery cloud service.",
        SerializedName = @"recoveryCloudService",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryCloudService { get; set; }
        /// <summary>The recovery fabric location.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery fabric location.",
        SerializedName = @"recoveryFabricLocation",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryFabricLocation { get; set; }
        /// <summary>The recovery fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery fabric object Id.",
        SerializedName = @"recoveryFabricObjectId",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryFabricObjectId { get; set; }
        /// <summary>The recovery proximity placement group Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery proximity placement group Id.",
        SerializedName = @"recoveryProximityPlacementGroupId",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryProximityPlacementGroupId { get; set; }
        /// <summary>The recovery virtual machine scale set id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery virtual machine scale set id.",
        SerializedName = @"recoveryVirtualMachineScaleSetId",
        PossibleTypes = new [] { typeof(string) })]
        string RecoveryVirtualMachineScaleSetId { get; set; }
        /// <summary>The last RPO value in seconds.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The last RPO value in seconds.",
        SerializedName = @"rpoInSeconds",
        PossibleTypes = new [] { typeof(long) })]
        long? RpoInSecond { get; set; }
        /// <summary>The recovery virtual network.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The recovery virtual network.",
        SerializedName = @"selectedRecoveryAzureNetworkId",
        PossibleTypes = new [] { typeof(string) })]
        string SelectedRecoveryAzureNetworkId { get; set; }
        /// <summary>The test failover virtual network.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The test failover virtual network.",
        SerializedName = @"selectedTfoAzureNetworkId",
        PossibleTypes = new [] { typeof(string) })]
        string SelectedTfoAzureNetworkId { get; set; }
        /// <summary>The test failover fabric object Id.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The test failover fabric object Id.",
        SerializedName = @"testFailoverRecoveryFabricObjectId",
        PossibleTypes = new [] { typeof(string) })]
        string TestFailoverRecoveryFabricObjectId { get; set; }
        /// <summary>The test failover vm name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The test failover vm name.",
        SerializedName = @"tfoAzureVMName",
        PossibleTypes = new [] { typeof(string) })]
        string TfoAzureVMName { get; set; }
        /// <summary>The list of unprotected disks.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of unprotected disks.",
        SerializedName = @"unprotectedDisks",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AUnprotectedDiskDetails) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AUnprotectedDiskDetails[] UnprotectedDisk { get; set; }
        /// <summary>The encryption type of the VM.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The encryption type of the VM.",
        SerializedName = @"vmEncryptionType",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType? VMEncryptionType { get;  }
        /// <summary>The virtual machine nic details.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The virtual machine nic details.",
        SerializedName = @"vmNics",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMNicDetails) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMNicDetails[] VMNic { get; set; }
        /// <summary>The protection state for the vm.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The protection state for the vm.",
        SerializedName = @"vmProtectionState",
        PossibleTypes = new [] { typeof(string) })]
        string VMProtectionState { get; set; }
        /// <summary>The protection state description for the vm.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The protection state description for the vm.",
        SerializedName = @"vmProtectionStateDescription",
        PossibleTypes = new [] { typeof(string) })]
        string VMProtectionStateDescription { get; set; }
        /// <summary>The Azure VM input endpoints.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The Azure VM input endpoints.",
        SerializedName = @"inputEndpoints",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInputEndpoint) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInputEndpoint[] VMSyncedConfigDetailInputEndpoint { get; set; }
        /// <summary>The Azure VM tags.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The Azure VM tags.",
        SerializedName = @"tags",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsTags) })]
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsTags VMSyncedConfigDetailTag { get; set; }

    }
    /// A2A provider specific settings.
    internal partial interface IA2AReplicationDetailsInternal :
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IReplicationProviderSpecificSettingsInternal
    {
        /// <summary>Agent certificate expiry date.</summary>
        global::System.DateTime? AgentCertificateExpiryDate { get; set; }
        /// <summary>Agent expiry date.</summary>
        global::System.DateTime? AgentExpiryDate { get; set; }
        /// <summary>The agent version.</summary>
        string AgentVersion { get; set; }
        /// <summary>A value indicating whether the auto protection is enabled.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.AutoProtectionOfDataDisk? AutoProtectionOfDataDisk { get; set; }
        /// <summary>The fabric specific object Id of the virtual machine.</summary>
        string FabricObjectId { get; set; }
        /// <summary>The initial primary fabric location.</summary>
        string InitialPrimaryFabricLocation { get; set; }
        /// <summary>The initial primary availability zone.</summary>
        string InitialPrimaryZone { get; set; }
        /// <summary>The initial recovery fabric location.</summary>
        string InitialRecoveryFabricLocation { get; set; }
        /// <summary>The initial recovery availability zone.</summary>
        string InitialRecoveryZone { get; set; }
        /// <summary>A value indicating whether agent certificate update is required.</summary>
        bool? IsReplicationAgentCertificateUpdateRequired { get; set; }
        /// <summary>A value indicating whether replication agent update is required.</summary>
        bool? IsReplicationAgentUpdateRequired { get; set; }
        /// <summary>The last heartbeat received from the source server.</summary>
        global::System.DateTime? LastHeartbeat { get; set; }
        /// <summary>The time (in UTC) when the last RPO value was calculated by Protection Service.</summary>
        global::System.DateTime? LastRpoCalculatedTime { get; set; }
        /// <summary>
        /// An id associated with the PE that survives actions like switch protection which change the backing PE/CPE objects internally.The
        /// lifecycle id gets carried forward to have a link/continuity in being able to have an Id that denotes the "same" protected
        /// item even though other internal Ids/ARM Id might be changing.
        /// </summary>
        string LifecycleId { get; set; }
        /// <summary>The management Id.</summary>
        string ManagementId { get; set; }
        /// <summary>
        /// The type of the monitoring job. The progress is contained in MonitoringPercentageCompletion property.
        /// </summary>
        string MonitoringJobType { get; set; }
        /// <summary>
        /// The percentage of the monitoring job. The type of the monitoring job is defined by MonitoringJobType property.
        /// </summary>
        int? MonitoringPercentageCompletion { get; set; }
        /// <summary>Whether Multi VM group is auto created or specified by user.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.MultiVMGroupCreateOption? MultiVMGroupCreateOption { get; set; }
        /// <summary>The multi vm group Id.</summary>
        string MultiVMGroupId { get; set; }
        /// <summary>The multi vm group name.</summary>
        string MultiVMGroupName { get; set; }
        /// <summary>The type of operating system.</summary>
        string OSType { get; set; }
        /// <summary>The primary availability zone.</summary>
        string PrimaryAvailabilityZone { get; set; }
        /// <summary>Primary fabric location.</summary>
        string PrimaryFabricLocation { get; set; }
        /// <summary>The list of protected disks.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedDiskDetails[] ProtectedDisk { get; set; }
        /// <summary>The list of protected managed disks.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AProtectedManagedDiskDetails[] ProtectedManagedDisk { get; set; }
        /// <summary>The recovery availability set.</summary>
        string RecoveryAvailabilitySet { get; set; }
        /// <summary>The recovery availability zone.</summary>
        string RecoveryAvailabilityZone { get; set; }
        /// <summary>The recovery azure generation.</summary>
        string RecoveryAzureGeneration { get; set; }
        /// <summary>The recovery resource group.</summary>
        string RecoveryAzureResourceGroupId { get; set; }
        /// <summary>The name of recovery virtual machine.</summary>
        string RecoveryAzureVMName { get; set; }
        /// <summary>The size of recovery virtual machine.</summary>
        string RecoveryAzureVMSize { get; set; }
        /// <summary>The recovery boot diagnostic storage account Arm Id.</summary>
        string RecoveryBootDiagStorageAccountId { get; set; }
        /// <summary>The recovery cloud service.</summary>
        string RecoveryCloudService { get; set; }
        /// <summary>The recovery fabric location.</summary>
        string RecoveryFabricLocation { get; set; }
        /// <summary>The recovery fabric object Id.</summary>
        string RecoveryFabricObjectId { get; set; }
        /// <summary>The recovery proximity placement group Id.</summary>
        string RecoveryProximityPlacementGroupId { get; set; }
        /// <summary>The recovery virtual machine scale set id.</summary>
        string RecoveryVirtualMachineScaleSetId { get; set; }
        /// <summary>The last RPO value in seconds.</summary>
        long? RpoInSecond { get; set; }
        /// <summary>The recovery virtual network.</summary>
        string SelectedRecoveryAzureNetworkId { get; set; }
        /// <summary>The test failover virtual network.</summary>
        string SelectedTfoAzureNetworkId { get; set; }
        /// <summary>The test failover fabric object Id.</summary>
        string TestFailoverRecoveryFabricObjectId { get; set; }
        /// <summary>The test failover vm name.</summary>
        string TfoAzureVMName { get; set; }
        /// <summary>The list of unprotected disks.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IA2AUnprotectedDiskDetails[] UnprotectedDisk { get; set; }
        /// <summary>The encryption type of the VM.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VMEncryptionType? VMEncryptionType { get; set; }
        /// <summary>The virtual machine nic details.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IVMNicDetails[] VMNic { get; set; }
        /// <summary>The protection state for the vm.</summary>
        string VMProtectionState { get; set; }
        /// <summary>The protection state description for the vm.</summary>
        string VMProtectionStateDescription { get; set; }
        /// <summary>The synced configuration details.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetails VMSyncedConfigDetail { get; set; }
        /// <summary>The Azure VM input endpoints.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInputEndpoint[] VMSyncedConfigDetailInputEndpoint { get; set; }
        /// <summary>The Azure VM tags.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IAzureToAzureVMSyncedConfigDetailsTags VMSyncedConfigDetailTag { get; set; }

    }
}