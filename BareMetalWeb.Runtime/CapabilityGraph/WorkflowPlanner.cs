using System.Text;

namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// Generates executable <see cref="WorkflowPlan"/>s from natural language intent
/// by parsing user statements, mapping them to <see cref="MetadataCapabilityGraph"/>
/// nodes, and chaining step outputs as downstream inputs.
///
/// Zero external dependencies — pure keyword matching and graph traversal.
/// </summary>
public sealed class WorkflowPlanner
{
    private readonly MetadataCapabilityGraph _graph;

    // ── Verb → StepType classification ──────────────────────────────────────
    private static readonly (string[] Verbs, StepType Type)[] VerbMap =
    [
        (["find", "query", "search", "get", "fetch", "list", "show", "retrieve", "filter", "look", "count"], StepType.Query),
        (["create", "add", "new", "insert", "register", "make", "generate", "open"], StepType.Create),
        (["update", "modify", "change", "edit", "set", "alter", "adjust", "mark"], StepType.Update),
        (["delete", "remove", "destroy", "drop", "erase", "wipe", "purge"], StepType.Delete),
        (["send", "email", "notify", "alert", "message", "sms", "post"], StepType.RunAction),
        (["schedule", "run", "execute", "invoke", "trigger", "process", "start", "launch", "kick"], StepType.RunAction),
    ];

    // Words that signal a condition clause
    private static readonly string[] ConditionMarkers = ["who", "where", "that", "with", "having", "when", "whose", "which"];

    // Noise words to skip during entity matching
    private static readonly HashSet<string> NoiseWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "a", "an", "the", "all", "them", "their", "those", "these", "and", "or",
        "to", "for", "from", "in", "on", "at", "of", "by", "is", "are", "was",
        "be", "it", "up", "out", "off", "then", "next", "also", "please", "now"
    };

    public WorkflowPlanner(MetadataCapabilityGraph graph)
    {
        _graph = graph;
    }

    /// <summary>
    /// Parse natural language intent into an executable workflow plan.
    /// Each line or sentence becomes a step; outputs chain automatically.
    /// </summary>
    public WorkflowPlan GeneratePlan(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new WorkflowPlan([], input, ["Empty input — provide one or more statements describing the workflow."]);

        var lines = SplitIntoStatements(input);
        var steps = new List<WorkflowStep>();
        var errors = new List<string>();
        int stepOrder = 0;
        string? previousOutput = null;
        string? previousEntitySlug = null;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;

            var tokens = Tokenize(trimmed);
            if (tokens.Count == 0) continue;

            // 1. Classify the action verb
            var (stepType, verbIndex) = ClassifyVerb(tokens);

            // 2. Identify the target entity
            var (entitySlug, entityName) = FindEntity(tokens);

            // If no entity found, try to inherit from previous step
            if (entitySlug == null && previousEntitySlug != null && stepType == StepType.RunAction)
                entitySlug = previousEntitySlug;

            if (entitySlug == null)
            {
                errors.Add($"Step {stepOrder + 1}: Could not identify entity in \"{trimmed}\"");
                continue;
            }

            // 3. Extract condition (text after condition markers)
            var condition = ExtractCondition(tokens, verbIndex);

            // 4. Extract action name for RunAction/RunWorkflow steps
            string? actionName = null;
            if (stepType == StepType.RunAction)
                actionName = InferActionName(tokens, entitySlug);

            // 5. Map to capability graph node
            int nodeId = FindCapabilityNode(stepType, entitySlug, actionName);

            // 6. Generate output variable
            string outputVar = GenerateOutputVariable(stepType, entitySlug, stepOrder);

            // 7. Wire input from previous step if applicable
            string? inputVar = null;
            if (stepOrder > 0 && previousOutput != null)
                inputVar = previousOutput;

            steps.Add(new WorkflowStep(
                stepOrder++,
                stepType,
                entitySlug,
                outputVar,
                nodeId,
                condition,
                actionName,
                inputVar));

            previousOutput = outputVar;
            previousEntitySlug = entitySlug;
        }

        // Validate the plan
        Validate(steps, errors);

        return new WorkflowPlan(
            steps.ToArray(),
            input,
            errors.Count > 0 ? errors.ToArray() : null);
    }

    /// <summary>
    /// Renders a human-readable preview of a workflow plan.
    /// </summary>
    public static string FormatPlan(WorkflowPlan plan)
    {
        var sb = new StringBuilder(512);

        if (!plan.IsValid && plan.Steps.Length == 0)
        {
            sb.AppendLine("⚠ Could not generate a workflow plan.");
            foreach (var err in plan.ValidationErrors)
                sb.Append("  • ").AppendLine(err);
            return sb.ToString();
        }

        sb.AppendLine($"Workflow Plan ({plan.Steps.Length} steps):");
        sb.AppendLine();

        foreach (var step in plan.Steps)
        {
            string icon = step.Type switch
            {
                StepType.Query => "🔍",
                StepType.Create => "➕",
                StepType.Update => "✏️",
                StepType.Delete => "🗑️",
                StepType.RunAction => "⚡",
                StepType.RunWorkflow => "🔄",
                StepType.Traverse => "🔗",
                _ => "•"
            };

            sb.Append($"  {icon} Step {step.Order + 1}: {step.Type} ");
            if (step.ActionName != null)
                sb.Append($"action \"{step.ActionName}\" on ");
            sb.Append(step.EntitySlug);
            if (step.Condition != null)
                sb.Append($" (filter: {step.Condition})");
            sb.Append($" → ${step.OutputVariable}");
            if (step.InputVariable != null)
                sb.Append($"  [input: ${step.InputVariable}]");
            if (step.CapabilityNodeId < 0)
                sb.Append("  ⚠ unresolved");
            sb.AppendLine();
        }

        if (plan.ValidationErrors.Length > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Warnings:");
            foreach (var err in plan.ValidationErrors)
                sb.Append("  • ").AppendLine(err);
        }

        return sb.ToString();
    }

    // ── Parsing helpers ─────────────────────────────────────────────────────

    private static List<string> SplitIntoStatements(string input)
    {
        var statements = new List<string>(8);
        // Split on newlines first
        foreach (var line in input.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;

            // Also split on sentence-ending punctuation
            int start = 0;
            for (int i = 0; i < trimmed.Length; i++)
            {
                if (trimmed[i] == '.' || trimmed[i] == ';')
                {
                    var segment = trimmed[start..(i + 1)].Trim();
                    if (segment.Length > 1) // skip lone punctuation
                        statements.Add(segment);
                    start = i + 1;
                }
            }
            if (start < trimmed.Length)
            {
                var remainder = trimmed[start..].Trim();
                if (remainder.Length > 0)
                    statements.Add(remainder);
            }
        }
        return statements;
    }

    private static List<string> Tokenize(string text)
    {
        var tokens = new List<string>(16);
        int start = -1;
        for (int i = 0; i <= text.Length; i++)
        {
            bool isSep = i == text.Length || (!char.IsLetterOrDigit(text[i]) && text[i] != '_' && text[i] != '-');
            if (isSep)
            {
                if (start >= 0)
                {
                    tokens.Add(text[start..i]);
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

    private static (StepType type, int verbIndex) ClassifyVerb(List<string> tokens)
    {
        for (int i = 0; i < tokens.Count; i++)
        {
            var word = tokens[i];
            foreach (var (verbs, type) in VerbMap)
            {
                foreach (var verb in verbs)
                {
                    if (word.StartsWith(verb, StringComparison.OrdinalIgnoreCase))
                        return (type, i);
                }
            }
        }
        // Default to Query if no verb found
        return (StepType.Query, -1);
    }

    private (string? slug, string? name) FindEntity(List<string> tokens)
    {
        // Try multi-word entity names first (e.g. "purchase order")
        for (int len = 3; len >= 1; len--)
        {
            for (int i = 0; i <= tokens.Count - len; i++)
            {
                if (NoiseWords.Contains(tokens[i])) continue;

                var candidate = len == 1
                    ? tokens[i]
                    : string.Join(" ", tokens.Skip(i).Take(len));

                // Match against graph entities (name, slug, or plural form)
                foreach (var entity in _graph.Entities)
                {
                    if (MatchesEntity(candidate, entity.Name, entity.Slug))
                        return (entity.Slug, entity.Name);
                }
            }
        }
        return (null, null);
    }

    private static bool MatchesEntity(string candidate, string name, string slug)
    {
        if (string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(candidate, slug, StringComparison.OrdinalIgnoreCase))
            return true;
        // Plural/singular matching: "customers" → "customer"
        if (candidate.Length > 1 && candidate.EndsWith('s')
            && string.Equals(candidate[..^1], name, StringComparison.OrdinalIgnoreCase))
            return true;
        if (candidate.Length > 1 && candidate.EndsWith('s')
            && string.Equals(candidate[..^1], slug, StringComparison.OrdinalIgnoreCase))
            return true;
        // Entity name might be plural, candidate singular
        if (name.Length > 1 && name.EndsWith('s')
            && string.Equals(candidate, name[..^1], StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static string? ExtractCondition(List<string> tokens, int verbIndex)
    {
        // Find condition marker and capture everything after it
        int markerIndex = -1;
        for (int i = Math.Max(0, verbIndex + 1); i < tokens.Count; i++)
        {
            foreach (var marker in ConditionMarkers)
            {
                if (string.Equals(tokens[i], marker, StringComparison.OrdinalIgnoreCase))
                {
                    markerIndex = i;
                    break;
                }
            }
            if (markerIndex >= 0) break;
        }

        if (markerIndex < 0 || markerIndex >= tokens.Count - 1)
            return null;

        return string.Join(' ', tokens.Skip(markerIndex + 1));
    }

    private string? InferActionName(List<string> tokens, string entitySlug)
    {
        // Try to find a matching action in the capability graph
        var actionNodes = _graph.GetCapabilities(entitySlug)
            .Where(n => n.Type == CapabilityType.RunAction);

        foreach (var node in actionNodes)
        {
            var actionDetail = node.Detail ?? node.Label;
            foreach (var token in tokens)
            {
                if (actionDetail.Contains(token, StringComparison.OrdinalIgnoreCase))
                    return node.Detail;
            }
        }

        // Fall back to constructing a name from action-like words in the input
        var actionWords = new List<string>();
        bool pastVerb = false;
        foreach (var token in tokens)
        {
            if (!pastVerb)
            {
                // Check if this is an action verb
                foreach (var (verbs, _) in VerbMap)
                {
                    if (Array.Exists(verbs, v => token.StartsWith(v, StringComparison.OrdinalIgnoreCase)))
                    {
                        pastVerb = true;
                        actionWords.Add(token.ToLowerInvariant());
                        break;
                    }
                }
                continue;
            }
            if (NoiseWords.Contains(token)) continue;
            // Stop at condition markers
            if (Array.Exists(ConditionMarkers, m => string.Equals(m, token, StringComparison.OrdinalIgnoreCase)))
                break;
            // Stop at entity name (already captured separately)
            bool isEntity = false;
            foreach (var e in _graph.Entities)
            {
                if (MatchesEntity(token, e.Name, e.Slug)) { isEntity = true; break; }
            }
            if (isEntity) continue;
            actionWords.Add(token.ToLowerInvariant());
            if (actionWords.Count >= 4) break; // cap action name length
        }

        return actionWords.Count > 0 ? string.Join('_', actionWords) : null;
    }

    private int FindCapabilityNode(StepType stepType, string? entitySlug, string? actionName)
    {
        if (entitySlug == null) return -1;

        var targetType = stepType switch
        {
            StepType.Query => CapabilityType.QueryEntity,
            StepType.Create => CapabilityType.CreateEntity,
            StepType.Update => CapabilityType.UpdateEntity,
            StepType.Delete => CapabilityType.DeleteEntity,
            StepType.RunAction => CapabilityType.RunAction,
            StepType.RunWorkflow => CapabilityType.RunWorkflow,
            _ => CapabilityType.QueryEntity
        };

        foreach (var node in _graph.GetCapabilities(entitySlug))
        {
            if (node.Type != targetType) continue;

            // For actions, try to match the action name
            if (targetType == CapabilityType.RunAction && actionName != null)
            {
                if (node.Label.Contains(actionName, StringComparison.OrdinalIgnoreCase)
                    || (node.Detail != null && node.Detail.Contains(actionName, StringComparison.OrdinalIgnoreCase)))
                    return node.Id;
                continue; // keep looking for a better match
            }

            return node.Id;
        }

        // Fallback: if we were looking for a specific action but didn't find it,
        // return any action node for this entity
        if (targetType == CapabilityType.RunAction)
        {
            foreach (var node in _graph.GetCapabilities(entitySlug))
                if (node.Type == CapabilityType.RunAction)
                    return node.Id;
        }

        return -1;
    }

    private static string GenerateOutputVariable(StepType type, string entitySlug, int stepOrder)
    {
        string suffix = type switch
        {
            StepType.Query => "list",
            StepType.Create => "id",
            StepType.Update => "updated",
            StepType.Delete => "deleted",
            StepType.RunAction => "result",
            StepType.RunWorkflow => "result",
            _ => "output"
        };
        return $"{entitySlug}_{suffix}_{stepOrder}";
    }

    private void Validate(List<WorkflowStep> steps, List<string> errors)
    {
        if (steps.Count == 0)
        {
            errors.Add("No valid steps could be parsed from the input.");
            return;
        }

        // Check that all capability nodes were resolved
        for (int i = 0; i < steps.Count; i++)
        {
            if (steps[i].CapabilityNodeId < 0)
                errors.Add($"Step {i + 1}: capability \"{steps[i].Type}({steps[i].EntitySlug})\" not found in graph.");
        }

        // Validate graph reachability: each step should be reachable from the prior step
        for (int i = 1; i < steps.Count; i++)
        {
            var prev = steps[i - 1];
            var curr = steps[i];
            if (prev.CapabilityNodeId < 0 || curr.CapabilityNodeId < 0)
                continue; // already reported as unresolved

            if (!IsReachable(prev.CapabilityNodeId, curr.CapabilityNodeId, maxDepth: 4))
            {
                errors.Add($"Step {i + 1}: \"{curr.Type}({curr.EntitySlug})\" is not " +
                    $"reachable from step {i} \"{prev.Type}({prev.EntitySlug})\" in the capability graph.");
            }
        }
    }

    /// <summary>BFS reachability check within a bounded depth.</summary>
    private bool IsReachable(int fromNode, int toNode, int maxDepth)
    {
        if (fromNode == toNode) return true;

        var visited = new HashSet<int> { fromNode };
        var frontier = new Queue<(int node, int depth)>();
        frontier.Enqueue((fromNode, 0));

        while (frontier.Count > 0)
        {
            var (current, depth) = frontier.Dequeue();
            if (depth >= maxDepth) continue;

            foreach (int neighbor in _graph.GetNeighbors(current))
            {
                if (neighbor == toNode) return true;
                if (visited.Add(neighbor))
                    frontier.Enqueue((neighbor, depth + 1));
            }
        }

        return false;
    }
}
