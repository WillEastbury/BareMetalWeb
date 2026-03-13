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
        // Count distinct words in the query for precision-based scoring
        int queryWordCount = CountWords(query);
        if (queryWordCount == 0)
            return default(IntentResult);

        var best = default(IntentResult);
        foreach (var intent in _intents)
        {
            if (intent.Keywords.Count == 0) continue;
            int hits = 0;
            foreach (var kw in intent.Keywords)
            {
                if (ContainsWholeWord(query, kw.AsSpan()))
                    hits++;
            }
            if (hits == 0) continue;

            // Precision-based confidence: fraction of query words matching intent keywords.
            // This approach favours specificity: a single-word query like "help" scores 100%
            // when "help" is a keyword, while a multi-word query like "describe the fields
            // of this entity" scores 3/6=50% (3 keywords hit, 6 query words).
            //
            // Intentional design choice over recall-based (hits/totalKeywords):
            // recall would score "help"→1/7=14% (below IsMatch threshold),
            // making single-word disambiguation impossible.
            float confidence = (float)hits / queryWordCount;
            if (confidence > best.Confidence)
                best = new IntentResult(intent.Name, confidence, query.ToString().AsMemory());
        }
        return best;
    }

    /// <summary>
    /// Returns true if <paramref name="query"/> contains <paramref name="keyword"/>
    /// as a whole word (surrounded by whitespace or at string boundaries).
    /// Case-insensitive.
    /// </summary>
    private static bool ContainsWholeWord(ReadOnlySpan<char> query, ReadOnlySpan<char> keyword)
    {
        int start = 0;
        while (start <= query.Length - keyword.Length)
        {
            int idx = query.Slice(start).IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return false;

            int pos = start + idx;
            bool leftOk  = pos == 0              || char.IsWhiteSpace(query[pos - 1]);
            bool rightOk = pos + keyword.Length == query.Length
                           || char.IsWhiteSpace(query[pos + keyword.Length]);

            if (leftOk && rightOk)
                return true;

            start = pos + 1;
        }
        return false;
    }

    /// <summary>Counts whitespace-delimited words in a span.</summary>
    private static int CountWords(ReadOnlySpan<char> text)
    {
        int count = 0;
        bool inWord = false;
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                inWord = false;
            }
            else if (!inWord)
            {
                inWord = true;
                count++;
            }
        }
        return count;
    }
}
