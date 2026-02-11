using System;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace BareMetalWeb.Data;

internal static class JsonTypeInfoRegistry
{
	private static readonly ConcurrentDictionary<Type, JsonTypeInfo> TypeInfoByType = new();

	private static readonly JsonSerializerOptions ReflectionOptions = new()
	{
		TypeInfoResolver = new DefaultJsonTypeInfoResolver()
	};

	public static JsonTypeInfo<T> GetTypeInfo<T>() where T : BaseDataObject
	{
		var info = TypeInfoByType.GetOrAdd(typeof(T), static type => ReflectionOptions.GetTypeInfo(type));
		return (JsonTypeInfo<T>)info;
	}

	public static JsonTypeInfo GetTypeInfo(Type type)
	{
		return TypeInfoByType.GetOrAdd(type, static resolved => ReflectionOptions.GetTypeInfo(resolved));
	}
}
