namespace Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210
{
    using Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.PowerShell;

    /// <summary>InMageRcm protected disk details.</summary>
    [System.ComponentModel.TypeConverter(typeof(InMageRcmProtectedDiskDetailsTypeConverter))]
    public partial class InMageRcmProtectedDiskDetails
    {

        /// <summary>
        /// <c>AfterDeserializeDictionary</c> will be called after the deserialization has finished, allowing customization of the
        /// object before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>

        partial void AfterDeserializeDictionary(global::System.Collections.IDictionary content);

        /// <summary>
        /// <c>AfterDeserializePSObject</c> will be called after the deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>

        partial void AfterDeserializePSObject(global::System.Management.Automation.PSObject content);

        /// <summary>
        /// <c>BeforeDeserializeDictionary</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializeDictionary(global::System.Collections.IDictionary content, ref bool returnNow);

        /// <summary>
        /// <c>BeforeDeserializePSObject</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializePSObject(global::System.Management.Automation.PSObject content, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmProtectedDiskDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetails"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetails DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new InMageRcmProtectedDiskDetails(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmProtectedDiskDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetails"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetails DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new InMageRcmProtectedDiskDetails(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="InMageRcmProtectedDiskDetails" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="className" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetails FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmProtectedDiskDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal InMageRcmProtectedDiskDetails(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetail = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmSyncDetails) content.GetValueForProperty("IrDetail",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetail, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmSyncDetailsTypeConverter.ConvertFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetail = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmSyncDetails) content.GetValueForProperty("ResyncDetail",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetail, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmSyncDetailsTypeConverter.ConvertFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskId = (string) content.GetValueForProperty("DiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskName = (string) content.GetValueForProperty("DiskName",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsOSDisk = (string) content.GetValueForProperty("IsOSDisk",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsOSDisk, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).CapacityInByte = (long?) content.GetValueForProperty("CapacityInByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).CapacityInByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).LogStorageAccountId = (string) content.GetValueForProperty("LogStorageAccountId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).LogStorageAccountId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskEncryptionSetId = (string) content.GetValueForProperty("DiskEncryptionSetId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskEncryptionSetId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).SeedManagedDiskId = (string) content.GetValueForProperty("SeedManagedDiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).SeedManagedDiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).TargetManagedDiskId = (string) content.GetValueForProperty("TargetManagedDiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).TargetManagedDiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskType = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskAccountType?) content.GetValueForProperty("DiskType",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskType, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskAccountType.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingInLogDataStoreInMb = (double?) content.GetValueForProperty("DataPendingInLogDataStoreInMb",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingInLogDataStoreInMb, (__y)=> (double) global::System.Convert.ChangeType(__y, typeof(double)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingAtSourceAgentInMb = (double?) content.GetValueForProperty("DataPendingAtSourceAgentInMb",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingAtSourceAgentInMb, (__y)=> (double) global::System.Convert.ChangeType(__y, typeof(double)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsInitialReplicationComplete = (string) content.GetValueForProperty("IsInitialReplicationComplete",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsInitialReplicationComplete, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressHealth = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth?) content.GetValueForProperty("IrDetailProgressHealth",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressHealth, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailTransferredByte = (long?) content.GetValueForProperty("IrDetailTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLast15MinutesTransferredByte = (long?) content.GetValueForProperty("IrDetailLast15MinutesTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLast15MinutesTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastDataTransferTimeUtc = (string) content.GetValueForProperty("IrDetailLastDataTransferTimeUtc",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastDataTransferTimeUtc, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProcessedByte = (long?) content.GetValueForProperty("IrDetailProcessedByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProcessedByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailStartTime = (string) content.GetValueForProperty("IrDetailStartTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailStartTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastRefreshTime = (string) content.GetValueForProperty("IrDetailLastRefreshTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastRefreshTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressPercentage = (int?) content.GetValueForProperty("IrDetailProgressPercentage",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressPercentage, (__y)=> (int) global::System.Convert.ChangeType(__y, typeof(int)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressHealth = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth?) content.GetValueForProperty("ResyncDetailProgressHealth",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressHealth, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailTransferredByte = (long?) content.GetValueForProperty("ResyncDetailTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLast15MinutesTransferredByte = (long?) content.GetValueForProperty("ResyncDetailLast15MinutesTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLast15MinutesTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastDataTransferTimeUtc = (string) content.GetValueForProperty("ResyncDetailLastDataTransferTimeUtc",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastDataTransferTimeUtc, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProcessedByte = (long?) content.GetValueForProperty("ResyncDetailProcessedByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProcessedByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailStartTime = (string) content.GetValueForProperty("ResyncDetailStartTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailStartTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastRefreshTime = (string) content.GetValueForProperty("ResyncDetailLastRefreshTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastRefreshTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressPercentage = (int?) content.GetValueForProperty("ResyncDetailProgressPercentage",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressPercentage, (__y)=> (int) global::System.Convert.ChangeType(__y, typeof(int)));
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmProtectedDiskDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal InMageRcmProtectedDiskDetails(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetail = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmSyncDetails) content.GetValueForProperty("IrDetail",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetail, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmSyncDetailsTypeConverter.ConvertFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetail = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmSyncDetails) content.GetValueForProperty("ResyncDetail",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetail, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.InMageRcmSyncDetailsTypeConverter.ConvertFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskId = (string) content.GetValueForProperty("DiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskName = (string) content.GetValueForProperty("DiskName",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsOSDisk = (string) content.GetValueForProperty("IsOSDisk",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsOSDisk, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).CapacityInByte = (long?) content.GetValueForProperty("CapacityInByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).CapacityInByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).LogStorageAccountId = (string) content.GetValueForProperty("LogStorageAccountId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).LogStorageAccountId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskEncryptionSetId = (string) content.GetValueForProperty("DiskEncryptionSetId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskEncryptionSetId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).SeedManagedDiskId = (string) content.GetValueForProperty("SeedManagedDiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).SeedManagedDiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).TargetManagedDiskId = (string) content.GetValueForProperty("TargetManagedDiskId",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).TargetManagedDiskId, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskType = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskAccountType?) content.GetValueForProperty("DiskType",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DiskType, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskAccountType.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingInLogDataStoreInMb = (double?) content.GetValueForProperty("DataPendingInLogDataStoreInMb",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingInLogDataStoreInMb, (__y)=> (double) global::System.Convert.ChangeType(__y, typeof(double)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingAtSourceAgentInMb = (double?) content.GetValueForProperty("DataPendingAtSourceAgentInMb",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).DataPendingAtSourceAgentInMb, (__y)=> (double) global::System.Convert.ChangeType(__y, typeof(double)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsInitialReplicationComplete = (string) content.GetValueForProperty("IsInitialReplicationComplete",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IsInitialReplicationComplete, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressHealth = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth?) content.GetValueForProperty("IrDetailProgressHealth",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressHealth, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailTransferredByte = (long?) content.GetValueForProperty("IrDetailTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLast15MinutesTransferredByte = (long?) content.GetValueForProperty("IrDetailLast15MinutesTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLast15MinutesTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastDataTransferTimeUtc = (string) content.GetValueForProperty("IrDetailLastDataTransferTimeUtc",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastDataTransferTimeUtc, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProcessedByte = (long?) content.GetValueForProperty("IrDetailProcessedByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProcessedByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailStartTime = (string) content.GetValueForProperty("IrDetailStartTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailStartTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastRefreshTime = (string) content.GetValueForProperty("IrDetailLastRefreshTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailLastRefreshTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressPercentage = (int?) content.GetValueForProperty("IrDetailProgressPercentage",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).IrDetailProgressPercentage, (__y)=> (int) global::System.Convert.ChangeType(__y, typeof(int)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressHealth = (Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth?) content.GetValueForProperty("ResyncDetailProgressHealth",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressHealth, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.DiskReplicationProgressHealth.CreateFrom);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailTransferredByte = (long?) content.GetValueForProperty("ResyncDetailTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLast15MinutesTransferredByte = (long?) content.GetValueForProperty("ResyncDetailLast15MinutesTransferredByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLast15MinutesTransferredByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastDataTransferTimeUtc = (string) content.GetValueForProperty("ResyncDetailLastDataTransferTimeUtc",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastDataTransferTimeUtc, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProcessedByte = (long?) content.GetValueForProperty("ResyncDetailProcessedByte",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProcessedByte, (__y)=> (long) global::System.Convert.ChangeType(__y, typeof(long)));
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailStartTime = (string) content.GetValueForProperty("ResyncDetailStartTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailStartTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastRefreshTime = (string) content.GetValueForProperty("ResyncDetailLastRefreshTime",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailLastRefreshTime, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressPercentage = (int?) content.GetValueForProperty("ResyncDetailProgressPercentage",((Microsoft.Azure.PowerShell.Cmdlets.Migrate.Models.Api20210210.IInMageRcmProtectedDiskDetailsInternal)this).ResyncDetailProgressPercentage, (__y)=> (int) global::System.Convert.ChangeType(__y, typeof(int)));
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Migrate.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// InMageRcm protected disk details.
    [System.ComponentModel.TypeConverter(typeof(InMageRcmProtectedDiskDetailsTypeConverter))]
    public partial interface IInMageRcmProtectedDiskDetails

    {

    }
}