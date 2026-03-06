using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Service for evaluating calculated field expressions and managing dependencies.
/// </summary>
public static class CalculatedFieldService
{
    private static readonly ConcurrentDictionary<string, ExpressionNode> _compiledExpressions = new();
    private const int MaxExpressionCacheSize = 4096;
    private static readonly ConcurrentDictionary<Type, List<CalculatedFieldInfo>> _calculatedFieldsByType = new();
    private static readonly ConcurrentDictionary<Type, Dictionary<string, HashSet<string>>> _dependencyGraph = new();
    // Cached context-builder delegates for unregistered types (avoids per-call GetProperties reflection).
    private static readonly ConcurrentDictionary<Type, (string Name, Func<object, object?> Getter)[]> _contextGettersCache = new();

    private sealed record CalculatedFieldInfo(
        string FieldName,
        Type PropertyType,
        Action<object, object?> SetValue,
        CalculatedFieldAttribute Attribute,
        ExpressionNode Expression,
        HashSet<string> Dependencies
    );

    /// <summary>
    /// Gets the parsed expression tree for an expression string (cached).
    /// </summary>
    public static ExpressionNode GetCompiledExpression(string expression)
    {
        if (_compiledExpressions.TryGetValue(expression, out var cached))
            return cached;

        var parser = new ExpressionParser();
        var node = parser.Parse(expression);

        // Evict half the cache when it exceeds the max size
        if (_compiledExpressions.Count >= MaxExpressionCacheSize)
        {
            int count = 0;
            int target = MaxExpressionCacheSize / 2;
            var keysToRemove = new List<string>(target);
            foreach (var key in _compiledExpressions.Keys)
            {
                keysToRemove.Add(key);
                if (++count >= target) break;
            }
            foreach (var key in keysToRemove)
                _compiledExpressions.TryRemove(key, out _);
        }

        _compiledExpressions[expression] = node;
        return node;
    }

    /// <summary>
    /// Evaluates all calculated fields on an entity instance.
    /// </summary>
    public static void EvaluateCalculatedFields(BaseDataObject instance)
    {
        var type = instance.GetType();
        var calculatedFields = GetCalculatedFields(type);

        if (calculatedFields.Count == 0)
            return;

        var context = BuildContext(instance, type);

        foreach (var fieldInfo in GetCalculatedFieldsInDependencyOrder(type))
        {
            try
            {
                var result = fieldInfo.Expression.Evaluate(context);
                fieldInfo.SetValue(instance, ConvertToPropertyType(result, fieldInfo.PropertyType));

                context[fieldInfo.FieldName] = result;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Error evaluating calculated field '{fieldInfo.FieldName}' with expression '{fieldInfo.Attribute.Expression}': {ex.Message}",
                    ex);
            }
        }
    }

    /// <summary>
    /// Async version of EvaluateCalculatedFields that supports relationship traversal
    /// via <see cref="ILookupResolver"/>. Use this for expressions containing
    /// dot-access (e.g., CustomerId.DiscountLevel), RelatedLookup(), QueryLookup(),
    /// LookupMultiLevel(), or multi-level chains (e.g., CustomerId.RegionId.TaxRate).
    /// </summary>
    /// <param name="instance">The entity being evaluated.</param>
    /// <param name="entitySlug">The slug of the entity type being evaluated.</param>
    /// <param name="resolver">Optional lookup resolver; defaults to <see cref="ServerLookupResolver.Instance"/>.</param>
    /// <param name="parentContext">
    /// Optional field values of the parent entity. When provided, fields are accessible in
    /// expressions via <c>Parent.FieldName</c> (e.g., <c>Parent.CustomerId</c>).
    /// Use this when evaluating child entities (e.g., OrderLine) that need to reference
    /// their parent entity's fields (e.g., Order.CustomerId).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask EvaluateCalculatedFieldsAsync(
        BaseDataObject instance,
        string entitySlug,
        ILookupResolver? resolver = null,
        IReadOnlyDictionary<string, object?>? parentContext = null,
        CancellationToken cancellationToken = default)
    {
        var type = instance.GetType();
        var calculatedFields = GetCalculatedFields(type);

        if (calculatedFields.Count == 0)
            return;

        var context = BuildContext(instance, type);
        context["__entitySlug"] = entitySlug;

        // Expose parent fields under "Parent.<FieldName>" so expressions like Parent.CustomerId work.
        if (parentContext != null)
        {
            foreach (var kvp in parentContext)
                context["Parent." + kvp.Key] = kvp.Value;
        }

        resolver ??= ServerLookupResolver.Instance;

        foreach (var fieldInfo in GetCalculatedFieldsInDependencyOrder(type))
        {
            try
            {
                var result = await fieldInfo.Expression.EvaluateAsync(context, resolver, cancellationToken);
                fieldInfo.SetValue(instance, ConvertToPropertyType(result, fieldInfo.PropertyType));
                context[fieldInfo.FieldName] = result;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Error evaluating calculated field '{fieldInfo.FieldName}' with expression '{fieldInfo.Attribute.Expression}': {ex.Message}",
                    ex);
            }
        }
    }

    /// <summary>
    /// Generates JavaScript code for calculated field evaluation.
    /// </summary>
    public static string GenerateJavaScript(Type entityType)
    {
        var calculatedFields = GetCalculatedFields(entityType);
        if (calculatedFields.Count == 0)
            return string.Empty;

        var orderedFields = GetCalculatedFieldsInDependencyOrder(entityType);
        var jsLines = new List<string>();

        foreach (var fieldInfo in orderedFields)
        {
            var fieldName = fieldInfo.FieldName;
            var jsExpression = fieldInfo.Expression.ToJavaScript();
            jsLines.Add($"    updateCalculatedField('{fieldName}', {jsExpression});");
        }

        return string.Join("\n", jsLines);
    }

    /// <summary>
    /// Gets the dependencies for a calculated field.
    /// </summary>
    public static HashSet<string> GetDependencies(Type entityType, string fieldName)
    {
        var graph = GetDependencyGraph(entityType);
        return graph.TryGetValue(fieldName, out var deps) ? deps : new HashSet<string>();
    }

    /// <summary>
    /// Detects circular dependencies in calculated fields.
    /// </summary>
    public static void ValidateNoCycles(Type entityType)
    {
        var graph = GetDependencyGraph(entityType);
        var visited = new HashSet<string>();
        var recursionStack = new HashSet<string>();

        foreach (var field in graph.Keys)
        {
            if (HasCycle(field, graph, visited, recursionStack))
            {
                throw new InvalidOperationException(
                    $"Circular dependency detected in calculated fields for type {entityType.Name} involving field '{field}'");
            }
        }
    }

    private static List<CalculatedFieldInfo> GetCalculatedFields(Type type)
    {
        return _calculatedFieldsByType.GetOrAdd(type, t =>
        {
            var fields = new List<CalculatedFieldInfo>();

            // Check metadata registry first (preferred — no per-type reflection).
            var meta = DataScaffold.GetEntityByType(t);
            if (meta != null)
            {
                foreach (var fieldMeta in meta.Fields)
                {
                    if (fieldMeta.Calculated == null || string.IsNullOrWhiteSpace(fieldMeta.CalculatedExpression))
                        continue;

                    var expression = GetCompiledExpression(fieldMeta.CalculatedExpression!);
                    var dependencies = ExtractDependencies(expression);
                    fields.Add(new CalculatedFieldInfo(fieldMeta.Name, fieldMeta.ClrType, fieldMeta.SetValueFn, fieldMeta.Calculated, expression, dependencies));
                }
                return fields;
            }

            // Fallback for types not registered in DataScaffold (startup cost only).
            foreach (var prop in t.GetProperties())
            {
                var attr = prop.GetCustomAttribute<CalculatedFieldAttribute>();
                if (attr == null || string.IsNullOrWhiteSpace(attr.Expression))
                    continue;

                var expression = GetCompiledExpression(attr.Expression);
                var dependencies = ExtractDependencies(expression);
                fields.Add(new CalculatedFieldInfo(prop.Name, prop.PropertyType, PropertyAccessorFactory.BuildSetter(prop), attr, expression, dependencies));
            }

            return fields;
        });
    }

    private static List<CalculatedFieldInfo> GetCalculatedFieldsInDependencyOrder(Type type)
    {
        var fields = GetCalculatedFields(type);
        var graph = GetDependencyGraph(type);
        var fieldMap = new Dictionary<string, CalculatedFieldInfo>(fields.Count);
        foreach (var f in fields) fieldMap[f.FieldName] = f;

        var sorted = new List<CalculatedFieldInfo>();
        var visited = new HashSet<string>();

        void Visit(string fieldName)
        {
            if (visited.Contains(fieldName))
                return;

            visited.Add(fieldName);

            if (graph.TryGetValue(fieldName, out var dependencies))
            {
                foreach (var dep in dependencies)
                {
                    if (graph.ContainsKey(dep))
                    {
                        Visit(dep);
                    }
                }
            }

            if (fieldMap.TryGetValue(fieldName, out var fieldInfo))
            {
                sorted.Add(fieldInfo);
            }
        }

        foreach (var field in fields)
        {
            Visit(field.FieldName);
        }

        return sorted;
    }

    private static Dictionary<string, HashSet<string>> GetDependencyGraph(Type type)
    {
        return _dependencyGraph.GetOrAdd(type, t =>
        {
            var graph = new Dictionary<string, HashSet<string>>();
            var fields = GetCalculatedFields(t);

            foreach (var field in fields)
            {
                graph[field.FieldName] = field.Dependencies;
            }

            return graph;
        });
    }

    private static HashSet<string> ExtractDependencies(ExpressionNode node)
    {
        var dependencies = new HashSet<string>();

        void Visit(ExpressionNode n)
        {
            switch (n)
            {
                case FieldNode fieldNode:
                    dependencies.Add(fieldNode.FieldName);
                    break;
                case BinaryOpNode binaryOp:
                    Visit(binaryOp.Left);
                    Visit(binaryOp.Right);
                    break;
                case UnaryOpNode unaryOp:
                    Visit(unaryOp.Operand);
                    break;
                case FunctionNode function:
                    foreach (var arg in function.Arguments)
                    {
                        Visit(arg);
                    }
                    break;
            }
        }

        Visit(node);
        return dependencies;
    }

    private static Dictionary<string, object?> BuildContext(BaseDataObject instance, Type type)
    {
        // Use compiled layout for efficient field access when available
        var meta = DataScaffold.GetEntityByType(type);
        if (meta != null)
        {
            var layout = EntityLayoutCompiler.GetOrCompile(meta);
            var context = new Dictionary<string, object?>(layout.Fields.Length + 4);
            context["Key"] = instance.Key;
            foreach (var field in layout.Fields)
            {
                try { context[field.Name] = field.Getter(instance); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"CalculatedFieldService: field '{field.Name}' getter failed: {ex.Message}"); context[field.Name] = null; }
            }
            return context;
        }

        // Fallback for unregistered types: use cached compiled getter delegates (built once per type).
        var getters = _contextGettersCache.GetOrAdd(type, static t =>
        {
            var props = t.GetProperties();
            var result = new (string Name, Func<object, object?>)[props.Length];
            for (int i = 0; i < props.Length; i++)
                result[i] = (props[i].Name, PropertyAccessorFactory.BuildGetter(props[i]));
            return result;
        });

        var ctx = new Dictionary<string, object?>(getters.Length + 1);
        foreach (var (name, getter) in getters)
            ctx[name] = getter(instance);
        return ctx;
    }

    private static bool HasCycle(
        string field,
        Dictionary<string, HashSet<string>> graph,
        HashSet<string> visited,
        HashSet<string> recursionStack)
    {
        if (recursionStack.Contains(field))
            return true;

        if (visited.Contains(field))
            return false;

        visited.Add(field);
        recursionStack.Add(field);

        if (graph.TryGetValue(field, out var dependencies))
        {
            foreach (var dep in dependencies)
            {
                if (graph.ContainsKey(dep) && HasCycle(dep, graph, visited, recursionStack))
                {
                    return true;
                }
            }
        }

        recursionStack.Remove(field);
        return false;
    }

    private static object? ConvertToPropertyType(object? value, Type targetType)
    {
        if (value == null)
        {
            if (Nullable.GetUnderlyingType(targetType) != null || !targetType.IsValueType)
                return null;

            // AOT-safe default values for known value types (no Activator.CreateInstance).
            if (targetType == typeof(int)) return 0;
            if (targetType == typeof(long)) return 0L;
            if (targetType == typeof(decimal)) return 0m;
            if (targetType == typeof(double)) return 0.0;
            if (targetType == typeof(float)) return 0f;
            if (targetType == typeof(bool)) return false;
            if (targetType == typeof(uint)) return 0u;
            if (targetType == typeof(DateTime)) return default(DateTime);
            if (targetType == typeof(DateTimeOffset)) return default(DateTimeOffset);
            if (targetType == typeof(Guid)) return Guid.Empty;
            if (targetType == typeof(byte)) return (byte)0;
            if (targetType == typeof(short)) return (short)0;
            if (targetType == typeof(TimeSpan)) return TimeSpan.Zero;

            // Fallback for unknown value types — still needed for user-defined structs.
            return RuntimeHelpers.GetUninitializedObject(targetType);
        }

        var underlyingType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (underlyingType == typeof(string))
            return value.ToString();

        if (underlyingType == typeof(decimal))
            return Convert.ToDecimal(value);

        if (underlyingType == typeof(int))
            return Convert.ToInt32(value);

        if (underlyingType == typeof(long))
            return Convert.ToInt64(value);

        if (underlyingType == typeof(double))
            return Convert.ToDouble(value);

        if (underlyingType == typeof(float))
            return Convert.ToSingle(value);

        if (underlyingType == typeof(bool))
            return Convert.ToBoolean(value);

        return Convert.ChangeType(value, underlyingType);
    }
}
