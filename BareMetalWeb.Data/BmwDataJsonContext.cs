using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BareMetalWeb.Data;

// Source-generated JSON context for AOT-safe serialization.
// All types serialized/deserialized via JsonSerializer in the Data project
// must be registered here.

[JsonSerializable(typeof(SchemaDefinitionFile))]
[JsonSerializable(typeof(MemberSignatureFile))]
[JsonSerializable(typeof(List<MemberSignatureFile>))]
[JsonSerializable(typeof(List<FieldChange>))]
[JsonSerializable(typeof(FieldChange))]
[JsonSerializable(typeof(List<DashboardTile>))]
[JsonSerializable(typeof(DashboardTile))]
[JsonSerializable(typeof(List<ReportJoin>))]
[JsonSerializable(typeof(List<ReportColumn>))]
[JsonSerializable(typeof(List<ReportFilter>))]
[JsonSerializable(typeof(List<ReportParameter>))]
[JsonSerializable(typeof(ReportJoin))]
[JsonSerializable(typeof(ReportColumn))]
[JsonSerializable(typeof(ReportFilter))]
[JsonSerializable(typeof(ReportParameter))]
[JsonSerializable(typeof(List<ViewProjection>))]
[JsonSerializable(typeof(List<ViewJoinDefinition>))]
[JsonSerializable(typeof(List<ViewFilterDefinition>))]
[JsonSerializable(typeof(List<ViewSortDefinition>))]
[JsonSerializable(typeof(ViewProjection))]
[JsonSerializable(typeof(ViewJoinDefinition))]
[JsonSerializable(typeof(ViewFilterDefinition))]
[JsonSerializable(typeof(ViewSortDefinition))]
[JsonSerializable(typeof(TenantOptions))]
[JsonSerializable(typeof(List<Dictionary<string, string>>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, object?>))]
[JsonSerializable(typeof(List<Dictionary<string, object?>>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(double))]
[JsonSerializable(typeof(PrincipalRole))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class BmwDataJsonContext : JsonSerializerContext { }
