using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Classifies user input into tool intents using keyword matching.
/// </summary>
public sealed class KeywordIntentClassifier : IIntentClassifier
{
    private readonly IReadOnlyList<IntentDefinition> _intents;

    public KeywordIntentClassifier(IReadOnlyList<IntentDefinition> intents)
    {
        _intents = intents ?? throw new ArgumentNullException(nameof(intents));
    }

    public IntentResult Classify(ReadOnlySpan<char> query)
    {
        var best = default(IntentResult);
        foreach (var intent in _intents)
        {
            int hits = 0;
            foreach (var kw in intent.Keywords)
            {
                if (query.Contains(kw.AsSpan(), StringComparison.OrdinalIgnoreCase))
                    hits++;
            }
            if (intent.Keywords.Count == 0) continue;
            float confidence = (float)hits / intent.Keywords.Count;
            if (confidence > best.Confidence)
                best = new IntentResult(intent.Name, confidence, query.ToString().AsMemory());
        }
        return best;
    }
}
