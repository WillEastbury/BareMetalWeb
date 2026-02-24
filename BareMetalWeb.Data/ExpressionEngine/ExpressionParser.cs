using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Parser for simple arithmetic and function expressions.
/// Supports: +, -, *, /, %, parentheses, field references, string literals, numbers,
/// and functions (Round, Min, Max, Abs, If).
/// </summary>
public sealed class ExpressionParser
{
    private string _expression = string.Empty;
    private int _position;
    private char _currentChar;

    public ExpressionNode Parse(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            throw new ArgumentException("Expression cannot be empty", nameof(expression));

        _expression = expression;
        _position = 0;
        _currentChar = _expression[0];
        
        SkipWhitespace(); // Skip leading whitespace

        var result = ParseExpression();

        SkipWhitespace(); // Skip trailing whitespace
        if (_position < _expression.Length)
            throw new InvalidOperationException($"Unexpected character '{_currentChar}' at position {_position}");

        return result;
    }

    private ExpressionNode ParseExpression()
    {
        return ParseComparison();
    }

    private ExpressionNode ParseComparison()
    {
        var left = ParseAddSubtract();

        if (_position < _expression.Length)
        {
            string? op = null;
            if (_currentChar == '>' && _position + 1 < _expression.Length && _expression[_position + 1] == '=')
            {
                op = ">="; Advance(); Advance(); SkipWhitespace();
            }
            else if (_currentChar == '<' && _position + 1 < _expression.Length && _expression[_position + 1] == '=')
            {
                op = "<="; Advance(); Advance(); SkipWhitespace();
            }
            else if (_currentChar == '!' && _position + 1 < _expression.Length && _expression[_position + 1] == '=')
            {
                op = "!="; Advance(); Advance(); SkipWhitespace();
            }
            else if (_currentChar == '=' && _position + 1 < _expression.Length && _expression[_position + 1] == '=')
            {
                op = "=="; Advance(); Advance(); SkipWhitespace();
            }
            else if (_currentChar == '>')
            {
                op = ">"; Advance(); SkipWhitespace();
            }
            else if (_currentChar == '<')
            {
                op = "<"; Advance(); SkipWhitespace();
            }

            if (op != null)
            {
                var right = ParseAddSubtract();
                left = new BinaryOpNode(left, op, right);
            }
        }

        return left;
    }

    private ExpressionNode ParseAddSubtract()
    {
        var left = ParseMultiplyDivideModulo();

        while (_position < _expression.Length && (_currentChar == '+' || _currentChar == '-'))
        {
            var op = _currentChar.ToString();
            Advance();
            SkipWhitespace(); // Skip whitespace after operator
            var right = ParseMultiplyDivideModulo();
            left = new BinaryOpNode(left, op, right);
        }

        return left;
    }

    private ExpressionNode ParseMultiplyDivideModulo()
    {
        var left = ParseUnary();

        while (_position < _expression.Length && (_currentChar == '*' || _currentChar == '/' || _currentChar == '%'))
        {
            var op = _currentChar.ToString();
            Advance();
            SkipWhitespace(); // Skip whitespace after operator
            var right = ParseUnary();
            left = new BinaryOpNode(left, op, right);
        }

        return left;
    }

    private ExpressionNode ParseUnary()
    {
        SkipWhitespace();
        if (_position < _expression.Length && (_currentChar == '-' || _currentChar == '+'))
        {
            var op = _currentChar.ToString();
            Advance();
            SkipWhitespace();
            return new UnaryOpNode(op, ParseUnary());
        }

        return ParsePrimary();
    }

    private ExpressionNode ParsePrimary()
    {
        SkipWhitespace();

        if (_position >= _expression.Length)
            throw new InvalidOperationException("Unexpected end of expression");

        if (_currentChar == '(')
        {
            Advance();
            SkipWhitespace(); // Skip whitespace after opening paren
            var node = ParseExpression();
            SkipWhitespace();
            if (_currentChar != ')')
                throw new InvalidOperationException($"Expected ')' at position {_position}");
            Advance();
            SkipWhitespace(); // Skip whitespace after closing paren
            return node;
        }

        if (_currentChar == '\'' || _currentChar == '"')
        {
            return ParseStringLiteral();
        }

        if (char.IsDigit(_currentChar) || _currentChar == '.')
        {
            return ParseNumber();
        }

        if (char.IsLetter(_currentChar) || _currentChar == '_')
        {
            var identifier = ParseIdentifier();

            SkipWhitespace();
            if (_position < _expression.Length && _currentChar == '(')
            {
                return ParseFunctionCall(identifier);
            }

            if (identifier.Equals("true", StringComparison.OrdinalIgnoreCase))
                return new LiteralNode(true);
            if (identifier.Equals("false", StringComparison.OrdinalIgnoreCase))
                return new LiteralNode(false);
            if (identifier.Equals("null", StringComparison.OrdinalIgnoreCase))
                return new LiteralNode(null);

            // Dot-notation: Entity.Field or Entity.SubEntity.Field
            if (_position < _expression.Length && _currentChar == '.')
            {
                var pathSegments = new List<string>();
                while (_position < _expression.Length && _currentChar == '.')
                {
                    Advance(); // skip '.'
                    var segment = ParseIdentifier();
                    pathSegments.Add(segment);
                }
                SkipWhitespace();
                return new DotAccessNode(identifier, pathSegments);
            }

            return new FieldNode(identifier);
        }

        throw new InvalidOperationException($"Unexpected character '{_currentChar}' at position {_position}");
    }

    private ExpressionNode ParseStringLiteral()
    {
        var quote = _currentChar;
        var sb = new StringBuilder();
        Advance();

        while (_position < _expression.Length && _currentChar != quote)
        {
            if (_currentChar == '\\' && _position + 1 < _expression.Length)
            {
                Advance();
                sb.Append(_currentChar);
            }
            else
            {
                sb.Append(_currentChar);
            }
            Advance();
        }

        if (_currentChar != quote)
            throw new InvalidOperationException($"Unterminated string literal starting at position {_position}");

        Advance();
        SkipWhitespace();
        return new LiteralNode(sb.ToString());
    }

    private ExpressionNode ParseNumber()
    {
        var sb = new StringBuilder();

        while (_position < _expression.Length && (char.IsDigit(_currentChar) || _currentChar == '.'))
        {
            sb.Append(_currentChar);
            Advance();
        }

        var numberStr = sb.ToString();
        if (!decimal.TryParse(numberStr, NumberStyles.Any, CultureInfo.InvariantCulture, out var value))
            throw new InvalidOperationException($"Invalid number format: {numberStr}");

        SkipWhitespace();
        return new LiteralNode(value);
    }

    private string ParseIdentifier()
    {
        var sb = new StringBuilder();

        while (_position < _expression.Length && (char.IsLetterOrDigit(_currentChar) || _currentChar == '_'))
        {
            sb.Append(_currentChar);
            Advance();
        }

        return sb.ToString();
    }

    private ExpressionNode ParseFunctionCall(string functionName)
    {
        Advance();
        SkipWhitespace();

        var arguments = new List<ExpressionNode>();

        if (_currentChar != ')')
        {
            arguments.Add(ParseExpression());
            SkipWhitespace();

            while (_currentChar == ',')
            {
                Advance();
                SkipWhitespace();
                arguments.Add(ParseExpression());
                SkipWhitespace();
            }
        }

        if (_currentChar != ')')
            throw new InvalidOperationException($"Expected ')' at position {_position}");

        Advance();
        SkipWhitespace();
        return new FunctionNode(functionName, arguments);
    }

    private void Advance()
    {
        _position++;
        _currentChar = _position < _expression.Length ? _expression[_position] : '\0';
    }

    private void SkipWhitespace()
    {
        while (_position < _expression.Length && char.IsWhiteSpace(_currentChar))
        {
            Advance();
        }
    }
}
