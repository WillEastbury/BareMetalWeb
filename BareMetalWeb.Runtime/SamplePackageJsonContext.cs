using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Source-generated JSON context for AOT-safe deserialization of sample gallery packages.
/// </summary>
[JsonSerializable(typeof(SamplePackage))]
[JsonSerializable(typeof(List<SamplePackage>))]
[JsonSerializable(typeof(SampleReport))]
[JsonSerializable(typeof(SampleRole))]
[JsonSerializable(typeof(SamplePermission))]
[JsonSerializable(typeof(EntityDefinition))]
[JsonSerializable(typeof(FieldDefinition))]
[JsonSerializable(typeof(IndexDefinition))]
[JsonSerializable(typeof(ActionDefinition))]
[JsonSerializable(typeof(ActionCommandDefinition))]
[JsonSerializable(typeof(AggregationDefinition))]
[JsonSerializable(typeof(ScheduledActionDefinition))]
[JsonSerializable(typeof(DomainEventSubscription))]
[JsonSerializable(typeof(List<EntityDefinition>))]
[JsonSerializable(typeof(List<FieldDefinition>))]
[JsonSerializable(typeof(List<IndexDefinition>))]
[JsonSerializable(typeof(List<ActionDefinition>))]
[JsonSerializable(typeof(List<ActionCommandDefinition>))]
[JsonSerializable(typeof(List<SampleReport>))]
[JsonSerializable(typeof(List<SampleRole>))]
[JsonSerializable(typeof(List<SamplePermission>))]
[JsonSerializable(typeof(List<AggregationDefinition>))]
[JsonSerializable(typeof(List<ScheduledActionDefinition>))]
[JsonSerializable(typeof(List<DomainEventSubscription>))]
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class SamplePackageJsonContext : JsonSerializerContext { }
