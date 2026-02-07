using System.Text.Json.Serialization;

namespace BareMetalWeb.Data;

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(User))]
[JsonSerializable(typeof(UserSession))]
[JsonSerializable(typeof(MfaChallenge))]
[JsonSerializable(typeof(SchemaDefinitionFile))]
[JsonSerializable(typeof(MemberSignatureFile))]
internal partial class BareMetalJsonContext : JsonSerializerContext
{
}
