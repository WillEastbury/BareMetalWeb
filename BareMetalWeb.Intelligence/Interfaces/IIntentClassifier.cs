namespace BareMetalWeb.Intelligence.Interfaces;

/// <summary>
/// Classifies user input into a tool intent with confidence score.
/// </summary>
public interface IIntentClassifier
{
    /// <summary>
    /// Classify a user query into the best-matching intent.
    /// </summary>
    IntentResult Classify(ReadOnlySpan<char> query);
}

/// <summary>
/// Result of intent classification.
/// </summary>
public readonly record struct IntentResult(
    string IntentName,
    float Confidence,
    ReadOnlyMemory<char> OriginalQuery
)
{
    public bool IsHighConfidence => Confidence >= 0.70f;
    public bool IsMatch => Confidence >= 0.40f;
}
