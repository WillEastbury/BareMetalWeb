using BareMetalWeb.Data;

namespace BareMetalWeb.Core;

public sealed record DataLookupConfig(
    Type TargetType,
    string ValueField,
    string DisplayField,
    string? QueryField,
    QueryOperator QueryOperator,
    string? QueryValue,
    string? SortField,
    SortDirection SortDirection,
    TimeSpan CacheTtl
);


