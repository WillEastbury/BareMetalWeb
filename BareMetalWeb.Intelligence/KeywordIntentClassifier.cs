using System.Runtime.CompilerServices;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// TF-IDF-style keyword intent classifier using cosine similarity.
/// No external dependencies — pure integer/float math on pre-computed vectors.
/// Interface-compatible with a future ONNX embedding model drop-in.
/// </summary>
public sealed class KeywordIntentClassifier : IIntentClassifier
{
    private readonly IntentEntry[] _intents;
    private readonly string[] _vocabulary;
    private readonly float[] _idf;

    public KeywordIntentClassifier(IReadOnlyList<IntentDefinition> intents)
    {
        // Build vocabulary from all intent keywords
        var vocabSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var intent in intents)
        {
            foreach (var kw in intent.Keywords)
                vocabSet.Add(kw.ToLowerInvariant());
        }
        _vocabulary = vocabSet.ToArray();

        // Compute IDF: log(N / df) where df = number of intents containing the term
        int n = intents.Count;
        _idf = new float[_vocabulary.Length];
        for (int v = 0; v < _vocabulary.Length; v++)
        {
            int df = 0;
            for (int d = 0; d < n; d++)
            {
                if (ContainsKeyword(intents[d].Keywords, _vocabulary[v]))
                    df++;
            }
            _idf[v] = MathF.Log((float)(n + 1) / (df + 1)) + 1.0f;
        }

        // Pre-compute TF-IDF vectors for each intent
        _intents = new IntentEntry[intents.Count];
        for (int i = 0; i < intents.Count; i++)
        {
            float[] vec = ComputeVector(intents[i].Keywords);
            Normalize(vec);
            _intents[i] = new IntentEntry(intents[i].Name, intents[i].Description, vec);
        }
    }

    public IntentResult Classify(ReadOnlySpan<char> query)
    {
        // Tokenise query into words
        var queryTokens = TokenizeQuery(query);
        if (queryTokens.Count == 0)
            return new IntentResult("unknown", 0f, ReadOnlyMemory<char>.Empty);

        // Compute query TF-IDF vector
        float[] queryVec = ComputeVector(queryTokens);
        Normalize(queryVec);

        // Find best cosine similarity match
        string bestIntent = "unknown";
        float bestScore = -1f;

        for (int i = 0; i < _intents.Length; i++)
        {
            float sim = CosineSimilarity(queryVec, _intents[i].Vector);
            if (sim > bestScore)
            {
                bestScore = sim;
                bestIntent = _intents[i].Name;
            }
        }

        return new IntentResult(bestIntent, bestScore, query.ToString().AsMemory());
    }

    private float[] ComputeVector(IReadOnlyList<string> tokens)
    {
        float[] vec = new float[_vocabulary.Length];
        for (int v = 0; v < _vocabulary.Length; v++)
        {
            int tf = 0;
            for (int t = 0; t < tokens.Count; t++)
            {
                if (string.Equals(tokens[t], _vocabulary[v], StringComparison.OrdinalIgnoreCase))
                    tf++;
            }
            vec[v] = tf * _idf[v];
        }
        return vec;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float CosineSimilarity(float[] a, float[] b)
    {
        float dot = 0f, normA = 0f, normB = 0f;
        int len = Math.Min(a.Length, b.Length);

        for (int i = 0; i < len; i++)
        {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        float denom = MathF.Sqrt(normA) * MathF.Sqrt(normB);
        return denom > 1e-8f ? dot / denom : 0f;
    }

    private static void Normalize(float[] vec)
    {
        float norm = 0f;
        for (int i = 0; i < vec.Length; i++)
            norm += vec[i] * vec[i];

        norm = MathF.Sqrt(norm);
        if (norm < 1e-8f) return;

        for (int i = 0; i < vec.Length; i++)
            vec[i] /= norm;
    }

    private static List<string> TokenizeQuery(ReadOnlySpan<char> query)
    {
        var tokens = new List<string>(16);
        int start = -1;

        for (int i = 0; i <= query.Length; i++)
        {
            bool isSep = i == query.Length || !char.IsLetterOrDigit(query[i]);
            if (isSep)
            {
                if (start >= 0)
                {
                    tokens.Add(query[start..i].ToString().ToLowerInvariant());
                    start = -1;
                }
            }
            else if (start < 0)
            {
                start = i;
            }
        }

        return tokens;
    }

    private static bool ContainsKeyword(IReadOnlyList<string> keywords, string term)
    {
        for (int i = 0; i < keywords.Count; i++)
        {
            if (string.Equals(keywords[i], term, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private readonly struct IntentEntry
    {
        public readonly string Name;
        public readonly string Description;
        public readonly float[] Vector;

        public IntentEntry(string name, string description, float[] vector)
        {
            Name = name;
            Description = description;
            Vector = vector;
        }
    }
}

/// <summary>
/// Defines an intent with its matching keywords.
/// </summary>
public sealed record IntentDefinition(
    string Name,
    string Description,
    IReadOnlyList<string> Keywords
);
