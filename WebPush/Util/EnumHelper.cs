using System;
using System.Text.RegularExpressions;

namespace WebPush.Util;

public static partial class EnumHelper
{

    public static string ToKebabCaseLower<T>(this T val) where T : Enum
    {
        return RegexVariableName().Replace(val.ToString()!, "$1-$2").ToLower();
    }

    [GeneratedRegex("([a-z0-9]|(?<=[a-z0-9]))([A-Z])")]
    private static partial Regex RegexVariableName();
}

