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

            // Precision: fraction of query words that matched an intent keyword.
            // This scores single-word queries ("help", "create") at 100% if the
            // word is a keyword, and naturally penalises false-positive noise words.
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
