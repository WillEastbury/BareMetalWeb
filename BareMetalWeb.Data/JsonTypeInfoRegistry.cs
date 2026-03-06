using System;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace BareMetalWeb.Data;

/// <summary>
/// Registry for JSON type info resolution. Uses a configurable <see cref="IJsonTypeInfoResolver"/>
/// so callers can supply a source-generated context for AOT-safe operation.
/// Falls back to <see cref="DefaultJsonTypeInfoResolver"/> when no custom resolver is set
/// (acceptable when <c>JsonSerializerIsReflectionEnabledByDefault</c> is <c>true</c>).
/// </summary>
internal static class JsonTypeInfoRegistry
{
	private static readonly ConcurrentDictionary<Type, JsonTypeInfo> TypeInfoByType = new();
	private static JsonSerializerOptions _options = CreateDefaultOptions();

	/// <summary>
	/// Replaces the type-info resolver used for all subsequent lookups.
	/// Call at startup with a <c>[JsonSerializable]</c>-attributed source-generated context
	/// for full AOT / trim safety.
	/// </summary>
	public static void SetResolver(IJsonTypeInfoResolver resolver)
	{
		TypeInfoByType.Clear();
		_options = new JsonSerializerOptions { TypeInfoResolver = resolver };
	}

	public static JsonTypeInfo<T> GetTypeInfo<T>() where T : BaseDataObject
	{
		var info = TypeInfoByType.GetOrAdd(typeof(T), static type => _options.GetTypeInfo(type));
		return (JsonTypeInfo<T>)info;
	}

	public static JsonTypeInfo GetTypeInfo(Type type)
	{
		return TypeInfoByType.GetOrAdd(type, static resolved => _options.GetTypeInfo(resolved));
	}

	private static JsonSerializerOptions CreateDefaultOptions()
	{
		// Project sets JsonSerializerIsReflectionEnabledByDefault=true in csproj,
		// so DefaultJsonTypeInfoResolver is safe at runtime. For full AOT, call
		// SetResolver() with a source-generated context at startup.
		#pragma warning disable IL2026, IL3050 // Reflection-based JSON is intentionally enabled
		return new JsonSerializerOptions { TypeInfoResolver = new DefaultJsonTypeInfoResolver() };
		#pragma warning restore IL2026, IL3050
	}
}
