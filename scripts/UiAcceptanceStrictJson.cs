using System;
using System.Collections.Generic;
using System.Text;

namespace CodeSignAuto.UiAcceptance.StrictJson
{
    public static class Preflight
    {
        public static void ValidateObject(string json, int maxDepth, int maxLength)
        {
            if (json == null)
            {
                throw new FormatException("ui_acceptance_json_invalid");
            }
            if (json.Length == 0 || maxDepth < 1 || maxDepth > 128 ||
                maxLength < 2 || maxLength > 1048576 || json.Length > maxLength)
            {
                Fail();
            }

            Parser parser = new Parser(json, maxDepth);
            parser.ParseRootObject();
        }

        private static void Fail()
        {
            throw new FormatException("ui_acceptance_json_invalid");
        }

        private sealed class Parser
        {
            private readonly string json;
            private readonly int maxDepth;
            private int index;

            internal Parser(string json, int maxDepth)
            {
                this.json = json;
                this.maxDepth = maxDepth;
            }

            internal void ParseRootObject()
            {
                SkipWhitespace();
                if (index >= json.Length || json[index] != '{')
                {
                    Fail();
                }

                ParseObject(1);
                SkipWhitespace();
                if (index != json.Length)
                {
                    Fail();
                }
            }

            private void ParseObject(int depth)
            {
                EnsureDepth(depth);
                Consume('{');
                SkipWhitespace();
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                if (TryConsume('}'))
                {
                    return;
                }

                while (true)
                {
                    SkipWhitespace();
                    if (index >= json.Length || json[index] != '"')
                    {
                        Fail();
                    }

                    string name = ParseString();
                    if (!names.Add(name))
                    {
                        Fail();
                    }

                    SkipWhitespace();
                    Consume(':');
                    SkipWhitespace();
                    ParseValue(depth);
                    SkipWhitespace();
                    if (TryConsume('}'))
                    {
                        return;
                    }

                    Consume(',');
                }
            }

            private void ParseArray(int depth)
            {
                EnsureDepth(depth);
                Consume('[');
                SkipWhitespace();
                if (TryConsume(']'))
                {
                    return;
                }

                while (true)
                {
                    SkipWhitespace();
                    ParseValue(depth);
                    SkipWhitespace();
                    if (TryConsume(']'))
                    {
                        return;
                    }

                    Consume(',');
                }
            }

            private void ParseValue(int containerDepth)
            {
                if (index >= json.Length)
                {
                    Fail();
                }

                char token = json[index];
                if (token == '{')
                {
                    ParseObject(containerDepth + 1);
                }
                else if (token == '[')
                {
                    ParseArray(containerDepth + 1);
                }
                else if (token == '"')
                {
                    ParseString();
                }
                else if (token == 't')
                {
                    ConsumeLiteral("true");
                }
                else if (token == 'f')
                {
                    ConsumeLiteral("false");
                }
                else if (token == 'n')
                {
                    ConsumeLiteral("null");
                }
                else if (token == '-' || IsDigit(token))
                {
                    ParseNumber();
                }
                else
                {
                    Fail();
                }
            }

            private string ParseString()
            {
                Consume('"');
                StringBuilder result = new StringBuilder();
                while (index < json.Length)
                {
                    char current = json[index++];
                    if (current == '"')
                    {
                        return result.ToString();
                    }

                    if (current < 0x20)
                    {
                        Fail();
                    }

                    if (current != '\\')
                    {
                        result.Append(current);
                        continue;
                    }

                    if (index >= json.Length)
                    {
                        Fail();
                    }

                    char escaped = json[index++];
                    switch (escaped)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            result.Append(escaped);
                            break;
                        case 'b':
                            result.Append('\b');
                            break;
                        case 'f':
                            result.Append('\f');
                            break;
                        case 'n':
                            result.Append('\n');
                            break;
                        case 'r':
                            result.Append('\r');
                            break;
                        case 't':
                            result.Append('\t');
                            break;
                        case 'u':
                            result.Append(ParseUnicodeEscape());
                            break;
                        default:
                            Fail();
                            break;
                    }
                }

                Fail();
                return string.Empty;
            }

            private char ParseUnicodeEscape()
            {
                if (json.Length - index < 4)
                {
                    Fail();
                }

                int value = 0;
                for (int offset = 0; offset < 4; offset++)
                {
                    int digit = HexValue(json[index++]);
                    if (digit < 0)
                    {
                        Fail();
                    }

                    value = (value << 4) | digit;
                }

                return (char)value;
            }

            private void ParseNumber()
            {
                TryConsume('-');
                if (index >= json.Length)
                {
                    Fail();
                }

                if (json[index] == '0')
                {
                    index++;
                    if (index < json.Length && IsDigit(json[index]))
                    {
                        Fail();
                    }
                }
                else
                {
                    if (!IsNonZeroDigit(json[index]))
                    {
                        Fail();
                    }

                    do
                    {
                        index++;
                    }
                    while (index < json.Length && IsDigit(json[index]));
                }

                if (TryConsume('.'))
                {
                    ConsumeDigits();
                }

                if (index < json.Length && (json[index] == 'e' || json[index] == 'E'))
                {
                    index++;
                    if (index < json.Length && (json[index] == '+' || json[index] == '-'))
                    {
                        index++;
                    }

                    ConsumeDigits();
                }
            }

            private void ConsumeDigits()
            {
                int start = index;
                while (index < json.Length && IsDigit(json[index]))
                {
                    index++;
                }

                if (index == start)
                {
                    Fail();
                }
            }

            private void ConsumeLiteral(string literal)
            {
                if (json.Length - index < literal.Length ||
                    !string.Equals(json.Substring(index, literal.Length), literal, StringComparison.Ordinal))
                {
                    Fail();
                }

                index += literal.Length;
            }

            private void Consume(char expected)
            {
                if (!TryConsume(expected))
                {
                    Fail();
                }
            }

            private bool TryConsume(char expected)
            {
                if (index < json.Length && json[index] == expected)
                {
                    index++;
                    return true;
                }

                return false;
            }

            private void SkipWhitespace()
            {
                while (index < json.Length)
                {
                    char current = json[index];
                    if (current != ' ' && current != '\t' && current != '\r' && current != '\n')
                    {
                        return;
                    }

                    index++;
                }
            }

            private void EnsureDepth(int depth)
            {
                if (depth > maxDepth)
                {
                    Fail();
                }
            }

            private static bool IsDigit(char value)
            {
                return value >= '0' && value <= '9';
            }

            private static bool IsNonZeroDigit(char value)
            {
                return value >= '1' && value <= '9';
            }

            private static int HexValue(char value)
            {
                if (value >= '0' && value <= '9')
                {
                    return value - '0';
                }
                if (value >= 'a' && value <= 'f')
                {
                    return value - 'a' + 10;
                }
                if (value >= 'A' && value <= 'F')
                {
                    return value - 'A' + 10;
                }

                return -1;
            }
        }
    }
}
