using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace ProxiFyre.Configuration
{
    public static class DomainRules
    {
        public static bool HasConditions(ProxyRule rule)
        {
            return rule != null && ((rule.Domains != null && rule.Domains.Count > 0) ||
                (rule.DomainSuffixes != null && rule.DomainSuffixes.Count > 0));
        }

        public static bool TryNormalize(string value, bool suffix, out string normalized)
        {
            normalized = null;
            if (string.IsNullOrWhiteSpace(value)) return false;
            var name = value.Trim().TrimEnd('.');
            if (suffix)
            {
                if (name.StartsWith("*.", StringComparison.Ordinal)) name = name.Substring(2);
                else if (name.StartsWith(".", StringComparison.Ordinal)) name = name.Substring(1);
            }
            IPAddress address;
            if (IPAddress.TryParse(name, out address)) return false;
            try
            {
                name = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(name).ToLowerInvariant();
            }
            catch (ArgumentException) { return false; }
            if (name.Length == 0 || name.Length > 253 || name.Split('.').Any(label => label.Length == 0 ||
                label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-' ||
                label.Any(ch => !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-')))
                return false;
            normalized = name;
            return true;
        }

        // Keep invalid values visible so validation reports them instead of broadening a rule.
        public static List<string> Normalize(IList<string> values, bool suffix)
        {
            if (values == null) return null;
            var result = new List<string>();
            foreach (var value in values)
            {
                string name;
                var output = TryNormalize(value, suffix, out name) ? name : value;
                if (!result.Contains(output, StringComparer.OrdinalIgnoreCase)) result.Add(output);
            }
            return result;
        }

        // Whether an earlier domain condition can hide any part of a later condition.
        public static bool Overlap(ProxyRule earlier, ProxyRule later)
        {
            if (!HasConditions(earlier)) return true;
            if (!HasConditions(later)) return false; // A domain rule cannot hide the general fallback.
            var leftExact = Normalize(earlier.Domains, false) ?? new List<string>();
            var leftSuffix = Normalize(earlier.DomainSuffixes, true) ?? new List<string>();
            var rightExact = Normalize(later.Domains, false) ?? new List<string>();
            var rightSuffix = Normalize(later.DomainSuffixes, true) ?? new List<string>();
            return leftExact.Any(left => rightExact.Contains(left) || rightSuffix.Any(right => Under(left, right))) ||
                leftSuffix.Any(left => rightExact.Any(right => Under(right, left)) ||
                    rightSuffix.Any(right => Under(left, right) || Under(right, left)));
        }

        private static bool Under(string name, string suffix)
        {
            return name != null && suffix != null && (name == suffix || name.EndsWith("." + suffix, StringComparison.Ordinal));
        }
    }
}
