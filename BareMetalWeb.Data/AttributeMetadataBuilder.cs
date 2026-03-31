using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Core;

/// <summary>
/// Reflection-based metadata builder — used at startup to construct
/// <see cref="DataEntityMetadata"/> from C# attributes on compiled entity types.
/// All reflection usage is isolated here; <see cref="DataScaffold"/> itself is reflection-free.
/// </summary>
internal static class AttributeMetadataBuilder
{
    private static readonly NullabilityInfoContext NullabilityContext = new();

    /// <summary>
    /// Builds <see cref="DataEntityMetadata"/> by scanning <typeparamref name="T"/>'s
    /// attributes via reflection. Called once per entity type at startup.
    /// Also pre-registers collection/instance factories used by child list deserialization,
    /// eliminating runtime <c>MakeGenericType</c> calls from the hot path.
    /// </summary>
    internal static DataEntityMetadata? BuildEntityMetadata<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] T>() where T : BaseDataObject, new()
    {
        var type = typeof(T);
        if (type.IsAbstract)
            return null;

        var entityAttribute = type.GetCustomAttribute<DataEntityAttribute>();
        if (entityAttribute == null)
            return null;

        // Read entity-level validation rules at registration time (no runtime reflection)
        List<ValidationRuleAttribute>? entityValidationRules = null;
        foreach (var attr in type.GetCustomAttributes(false))
        {
            if (attr is ValidationRuleAttribute vr)
            {
                entityValidationRules ??= new List<ValidationRuleAttribute>();
                entityValidationRules.Add(vr);
            }
        }

        var fields = new List<DataFieldMetadata>();
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        // Read ordinal mapping from entity's field lookup table (zero reflection)
        var ordinalMap = new Dictionary<string, int>(32, StringComparer.Ordinal);
        var probe = new T();
        foreach (var slot in probe.GetFieldMap())
            ordinalMap[slot.Name] = slot.Ordinal;

        for (int i = 0; i < properties.Length; i++)
        {
            var prop = properties[i];
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            // Batch-read all custom attributes once per property
            var allAttrs = prop.GetCustomAttributes(false);
            DataFieldAttribute? fieldAttribute = null;
            FileFieldAttribute? fileFieldAttribute = null;
            ImageFieldAttribute? imageFieldAttribute = null;
            DataLookupAttribute? lookupAttribute = null;
            IdGenerationAttribute? idGenAttribute = null;
            ComputedFieldAttribute? computedAttribute = null;
            CalculatedFieldAttribute? calculatedAttribute = null;
            DataIndexAttribute? dataIndexAttribute = null;
            RelatedDocumentAttribute? relatedDocAttribute = null;
            SingletonFlagAttribute? singletonFlagAttribute = null;
            List<ValidationAttribute>? validationAttrs = null;
            List<ValidationRuleAttribute>? fieldExprRules = null;
            for (int j = 0; j < allAttrs.Length; j++)
            {
                switch (allAttrs[j])
                {
                    case DataFieldAttribute a: fieldAttribute = a; break;
                    case FileFieldAttribute a: fileFieldAttribute = a; break;
                    case ImageFieldAttribute a: imageFieldAttribute = a; break;
                    case DataLookupAttribute a: lookupAttribute = a; break;
                    case IdGenerationAttribute a: idGenAttribute = a; break;
                    case ComputedFieldAttribute a: computedAttribute = a; break;
                    case CalculatedFieldAttribute a: calculatedAttribute = a; break;
                    case DataIndexAttribute a: dataIndexAttribute = a; break;
                    case RelatedDocumentAttribute a: relatedDocAttribute = a; break;
                    case SingletonFlagAttribute a: singletonFlagAttribute = a; break;
                    case ValidationAttribute va:
                        validationAttrs ??= new List<ValidationAttribute>();
                        validationAttrs.Add(va);
                        break;
                    case ValidationRuleAttribute vr:
                        fieldExprRules ??= new List<ValidationRuleAttribute>();
                        fieldExprRules.Add(vr);
                        break;
                }
            }

            if (IsCoreDataObjectProperty(prop))
            {
                if (fieldAttribute == null && idGenAttribute == null)
                    continue;
            }

            var hasSingletonFlag = prop.PropertyType == typeof(bool) && singletonFlagAttribute != null;
            if (fieldAttribute == null && imageFieldAttribute == null && fileFieldAttribute == null)
                continue;

            var fieldType = imageFieldAttribute != null
                ? FormFieldType.Image
                : fileFieldAttribute != null
                    ? FormFieldType.File
                    : fieldAttribute?.FieldType == FormFieldType.Unknown || fieldAttribute == null
                        ? DataScaffold.MapFieldType(prop.PropertyType)
                        : fieldAttribute.FieldType;
            var label = imageFieldAttribute?.Label
                ?? fileFieldAttribute?.Label
                ?? fieldAttribute?.Label
                ?? DataScaffold.DeCamelcase(prop.Name);
            var required = imageFieldAttribute?.Required
                ?? fileFieldAttribute?.Required
                ?? fieldAttribute?.Required
                ?? (!IsNullable(prop) || !HasDefaultValue(probe, prop));
            var order = imageFieldAttribute?.Order
                ?? fileFieldAttribute?.Order
                ?? fieldAttribute?.Order
                ?? (i + 1);
            DataLookupConfig? lookup = null;
            if (lookupAttribute != null)
            {
                lookup = new DataLookupConfig(
                    lookupAttribute.TargetType,
                    lookupAttribute.ValueField,
                    lookupAttribute.DisplayField,
                    lookupAttribute.QueryField,
                    lookupAttribute.QueryOperator,
                    lookupAttribute.QueryValue,
                    lookupAttribute.SortField,
                    lookupAttribute.SortDirection,
                    TimeSpan.FromSeconds(Math.Max(0, lookupAttribute.CacheSeconds))
                );
            }

            ComputedFieldConfig? computed = null;
            if (computedAttribute != null)
            {
                computed = new ComputedFieldConfig(
                    computedAttribute.SourceEntity,
                    computedAttribute.SourceField,
                    computedAttribute.ForeignKeyField,
                    computedAttribute.ChildCollectionProperty,
                    computedAttribute.Strategy,
                    computedAttribute.Trigger,
                    computedAttribute.Aggregate,
                    TimeSpan.FromSeconds(Math.Max(0, computedAttribute.CacheSeconds))
                );
            }

            UploadFieldConfig? upload = null;
            if (imageFieldAttribute != null)
            {
                upload = new UploadFieldConfig(
                    imageFieldAttribute.MaxFileSizeBytes,
                    imageFieldAttribute.AllowedMimeTypes,
                    imageFieldAttribute.MaxWidth > 0 ? imageFieldAttribute.MaxWidth : null,
                    imageFieldAttribute.MaxHeight > 0 ? imageFieldAttribute.MaxHeight : null,
                    imageFieldAttribute.GenerateThumbnail
                );
            }
            else if (fileFieldAttribute != null)
            {
                upload = new UploadFieldConfig(
                    fileFieldAttribute.MaxFileSizeBytes,
                    fileFieldAttribute.AllowedMimeTypes,
                    null,
                    null,
                    false
                );
            }

            RelatedDocumentConfig? relatedDoc = relatedDocAttribute != null
                ? new RelatedDocumentConfig(relatedDocAttribute.TargetType, relatedDocAttribute.DisplayField)
                : null;

            fields.Add(new DataFieldMetadata(
                prop.PropertyType,
                prop.Name,
                label,
                fieldType,
                order,
                required,
                imageFieldAttribute?.List ?? fileFieldAttribute?.List ?? fieldAttribute?.List ?? true,
                imageFieldAttribute?.View ?? fileFieldAttribute?.View ?? fieldAttribute?.View ?? true,
                imageFieldAttribute?.Edit ?? fileFieldAttribute?.Edit ?? fieldAttribute?.Edit ?? true,
                imageFieldAttribute?.Create ?? fileFieldAttribute?.Create ?? fieldAttribute?.Create ?? true,
                (imageFieldAttribute?.ReadOnly ?? fileFieldAttribute?.ReadOnly ?? fieldAttribute?.ReadOnly ?? false) || (computed != null) || (calculatedAttribute != null),
                imageFieldAttribute?.Placeholder ?? fileFieldAttribute?.Placeholder ?? fieldAttribute?.Placeholder,
                lookup,
                idGenAttribute?.Strategy ?? IdGenerationStrategy.None,
                computed,
                upload,
                calculatedAttribute,
                BuildValidationConfigInline(validationAttrs, fieldExprRules),
                dataIndexAttribute != null,
                relatedDoc,
                DataIndex: dataIndexAttribute,
                HasSingletonFlag: hasSingletonFlag,
                StorageOrdinal: ordinalMap.TryGetValue(prop.Name, out var storageOrd) ? storageOrd : -1
            ));

            // Pre-register child list factories at startup (avoids MakeGenericType at runtime)
            if (DataScaffold.IsChildListType(prop.PropertyType, out var childListType))
            {
                PreRegisterChildFactories(childListType);
            }
        }

        var name = entityAttribute?.Name ?? DataScaffold.Pluralize(DataScaffold.DeCamelcase(type.Name));
        var slug = string.IsNullOrWhiteSpace(entityAttribute?.Slug)
            ? DataScaffold.ToSlug(name)
            : entityAttribute!.Slug!.Trim().ToLowerInvariant();
        var permissions = string.IsNullOrWhiteSpace(entityAttribute?.Permissions)
            ? name
            : entityAttribute!.Permissions;
        var showOnNav = entityAttribute?.ShowOnNav ?? false;
        var navGroup = entityAttribute?.NavGroup ?? "Admin";
        var navOrder = entityAttribute?.NavOrder ?? 0;
        var idGeneration = entityAttribute?.IdGeneration ?? AutoIdStrategy.Sequential;
        var defaultSortField = string.IsNullOrWhiteSpace(entityAttribute?.DefaultSortField) ? null : entityAttribute.DefaultSortField;
        var defaultSortDirection = entityAttribute?.DefaultSortDirection ?? SortDirection.Asc;

        // Detect view type and self-referencing parent field
        var viewTypeAttribute = type.GetCustomAttribute<DataViewTypeAttribute>();
        var viewType = viewTypeAttribute?.ViewType ?? ViewType.Table;
        DataFieldMetadata? parentField = null;
        
        foreach (var field in fields)
        {
            if (field.Lookup != null && field.Lookup.TargetType == type)
            {
                parentField = field;
                break;
            }
        }

        var handlers = new DataEntityHandlers(
            static () => new T(),
            DataScaffold.LoadTypedAsync<T>,
            DataScaffold.SaveTypedAsync<T>,
            DataScaffold.DeleteTypedAsync<T>,
            DataScaffold.QueryTypedAsync<T>,
            DataScaffold.CountTypedAsync<T>
        );

        // Discover [RemoteCommand] methods and pre-compile typed invoker delegates.
        var commands = new List<RemoteCommandMetadata>();
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        foreach (var method in methods)
        {
            var cmdAttr = method.GetCustomAttribute<RemoteCommandAttribute>();
            if (cmdAttr == null) continue;
            var returnType = method.ReturnType;

            Func<object, ValueTask<RemoteCommandResult>> invoker;
            if (returnType == typeof(RemoteCommandResult))
            {
                var d = (Func<T, RemoteCommandResult>)Delegate.CreateDelegate(typeof(Func<T, RemoteCommandResult>), method);
                invoker = obj => new ValueTask<RemoteCommandResult>(d((T)obj));
            }
            else if (returnType == typeof(Task<RemoteCommandResult>))
            {
                var d = (Func<T, Task<RemoteCommandResult>>)Delegate.CreateDelegate(typeof(Func<T, Task<RemoteCommandResult>>), method);
                invoker = obj => new ValueTask<RemoteCommandResult>(d((T)obj));
            }
            else if (returnType == typeof(ValueTask<RemoteCommandResult>))
            {
                var d = (Func<T, ValueTask<RemoteCommandResult>>)Delegate.CreateDelegate(typeof(Func<T, ValueTask<RemoteCommandResult>>), method);
                invoker = obj => d((T)obj);
            }
            else
            {
                continue;
            }

            commands.Add(new RemoteCommandMetadata(
                invoker,
                method.Name,
                cmdAttr.Label ?? DataScaffold.DeCamelcase(method.Name),
                cmdAttr.Icon,
                cmdAttr.ConfirmMessage,
                cmdAttr.Destructive,
                cmdAttr.Permission,
                cmdAttr.OverrideEntityPermissions,
                cmdAttr.Order
            ));
        }

        fields.Sort((a, b) => a.Order.CompareTo(b.Order));
        commands.Sort((a, b) => a.Order.CompareTo(b.Order));
        var docRelFields = new List<DataFieldMetadata>();
        foreach (var f in fields)
        {
            if (f.RelatedDocument != null)
                docRelFields.Add(f);
        }

        return new DataEntityMetadata(
            type,
            name,
            slug,
            permissions,
            showOnNav,
            navGroup,
            navOrder,
            idGeneration,
            viewType,
            parentField,
            fields,
            handlers,
            commands,
            defaultSortField,
            defaultSortDirection,
            docRelFields,
            entityValidationRules
        );
    }

    private static bool IsCoreDataObjectProperty(PropertyInfo property)
    {
        return property.DeclaringType == typeof(BaseDataObject)
            || property.Name == nameof(BaseDataObject.Key)
            || property.Name == nameof(BaseDataObject.CreatedOnUtc)
            || property.Name == nameof(BaseDataObject.UpdatedOnUtc)
            || property.Name == nameof(BaseDataObject.CreatedBy)
            || property.Name == nameof(BaseDataObject.UpdatedBy)
            || property.Name == nameof(BaseDataObject.ETag);
    }

    internal static ValidationConfig? BuildValidationConfigInline(
        List<ValidationAttribute>? validators, List<ValidationRuleAttribute>? expressionRules)
    {
        if ((validators == null || validators.Count == 0) && (expressionRules == null || expressionRules.Count == 0))
            return null;

        int? minLength = null;
        int? maxLength = null;
        double? rangeMin = null;
        double? rangeMax = null;
        string? regexPattern = null;
        string? regexMessage = null;
        bool isEmail = false;
        bool isUrl = false;
        bool isPhone = false;

        if (validators != null)
        {
            foreach (var v in validators)
            {
                switch (v)
                {
                    case MinLengthAttribute ml: minLength = ml.Length; break;
                    case MaxLengthAttribute mx: maxLength = mx.Length; break;
                    case RangeAttribute r: rangeMin = r.Min; rangeMax = r.Max; break;
                    case RegexPatternAttribute rp: regexPattern = rp.Pattern; regexMessage = rp.ErrorMessage; break;
                    case EmailAddressAttribute: isEmail = true; break;
                    case UrlAttribute: isUrl = true; break;
                    case PhoneAttribute: isPhone = true; break;
                }
            }
        }

        return new ValidationConfig(
            minLength, maxLength, rangeMin, rangeMax,
            regexPattern, regexMessage,
            isEmail, isUrl, isPhone,
            (IReadOnlyList<ValidationAttribute>?)validators ?? Array.Empty<ValidationAttribute>(),
            (IReadOnlyList<ValidationRuleAttribute>?)expressionRules ?? Array.Empty<ValidationRuleAttribute>()
        );
    }

    private static bool IsNullable(PropertyInfo property)
    {
        if (Nullable.GetUnderlyingType(property.PropertyType) != null)
            return true;
        if (property.PropertyType.IsValueType)
            return false;

        var nullability = NullabilityContext.Create(property);
        return nullability.ReadState == NullabilityState.Nullable
            || nullability.WriteState == NullabilityState.Nullable;
    }

    private static bool HasDefaultValue(object defaultInstance, PropertyInfo property)
    {
        object? value;
        try
        {
            value = property.GetValue(defaultInstance);
        }
        catch
        {
            return false;
        }

        return !DataScaffold.IsDefaultValue(value, property.PropertyType);
    }

    private static Func<object> CompileFactory([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type type)
    {
        return () => Activator.CreateInstance(type)!;
    }

    private static void PreRegisterChildFactories([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type childType)
    {
        var listFactory = CompileFactory(typeof(List<>).MakeGenericType(childType));
        var instanceFactory = CompileFactory(childType);
        DataScaffold.PreRegisterChildFactories(childType, listFactory, instanceFactory);
    }
}
