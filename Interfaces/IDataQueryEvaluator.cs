using System.Collections.Generic;
using BareMetalWeb.Data;

namespace BareMetalWeb.Interfaces;

public interface IDataQueryEvaluator
{
    bool Matches(object obj, QueryDefinition? query);
    IEnumerable<T> ApplySorts<T>(IEnumerable<T> source, QueryDefinition? query);
}
