using NUnit.Framework;
using ProxiFyre.Configuration;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class DomainRulesTests
    {
        [TestCase(" STORE.Example.COM. ", false, "store.example.com")]
        [TestCase("*.Example.COM", true, "example.com")]
        [TestCase(".Example.COM.", true, "example.com")]
        [TestCase("bücher.example", false, "xn--bcher-kva.example")]
        public void CanonicalizesNamesWithoutDnsLookups(string value, bool suffix, string expected)
        {
            string result;
            Assert.That(DomainRules.TryNormalize(value,suffix,out result),Is.True);
            Assert.That(result,Is.EqualTo(expected));
        }

        [TestCase(null)] [TestCase("")] [TestCase(" ")] [TestCase("*.example.com")]
        [TestCase("https://example.com")] [TestCase("example.com/path")]
        [TestCase("example.com:443")] [TestCase("127.0.0.1")] [TestCase("::1")]
        [TestCase("example..com")] [TestCase("-bad.example")]
        public void InvalidExactNamesAreErrorsAndSurviveNormalization(string value)
        {
            var rule = TestModels.ValidRule(); rule.Domains = new List<string>{value};
            var normalized = new ConfigurationNormalizer().NormalizeRule(rule);
            var errors = new ConfigurationValidator().ValidateRule(normalized).Issues;
            Assert.That(errors.Any(issue => issue.Code == "DOMAIN_INVALID" && issue.Severity == ValidationSeverity.Error),Is.True);
            Assert.That(normalized.Domains,Has.Count.EqualTo(1));
        }

        [Test]
        public void ListsRoundTripCloneAndNormalize()
        {
            var config = TestModels.ValidConfiguration();
            config.Proxies[0].Domains = new List<string>{"Store.Example.com.","store.example.com"};
            config.Proxies[0].DomainSuffixes = new List<string>{"*.Example.NET"};
            var serializer = new ConfigurationSerializer();
            var normalized = new ConfigurationNormalizer().Normalize(serializer.Deserialize(serializer.Serialize(config)));
            Assert.That(normalized.Proxies[0].Domains,Is.EqualTo(new[]{"store.example.com"}));
            Assert.That(normalized.Proxies[0].DomainSuffixes,Is.EqualTo(new[]{"example.net"}));
            var clone = serializer.CloneRule(normalized.Proxies[0]);
            clone.Domains.Add("other.example");
            Assert.That(normalized.Proxies[0].Domains,Has.Count.EqualTo(1));
            Assert.That(new ConfigurationValidator().Validate(normalized).HasErrors,Is.False);
        }

        [Test]
        public void EmptyListsAreFallbackAndLegacyJsonDoesNotGainDomainConditions()
        {
            var rule = TestModels.ValidRule();
            Assert.That(DomainRules.HasConditions(rule),Is.False);
            rule.Domains = new List<string>(); rule.DomainSuffixes = new List<string>();
            Assert.That(DomainRules.HasConditions(rule),Is.False);
            var serializer = new ConfigurationSerializer();
            Assert.That(serializer.Serialize(TestModels.ValidConfiguration()),Does.Not.Contain("domainSuffixes"));
        }

        [Test]
        public void DisjointDomainRulesAndLaterFallbackDoNotProduceShadowWarnings()
        {
            var config = TestModels.ValidConfiguration();
            config.Proxies[0].Domains = new List<string>{"first.example"};
            var second = TestModels.ValidRule(); second.DomainSuffixes = new List<string>{"second.example"};
            config.Proxies.Add(second); config.Proxies.Add(TestModels.ValidRule());
            Assert.That(new ConfigurationValidator().Validate(config).Issues.Any(issue => issue.Code == "APP_MATCH_SHADOWED"),Is.False);
            config.Proxies.Reverse();
            Assert.That(new ConfigurationValidator().Validate(config).Issues.Any(issue => issue.Code == "APP_MATCH_SHADOWED"),Is.True);
        }

        [Test]
        public void SuffixOverlapChecksLabelBoundariesAndRoots()
        {
            var first = TestModels.ValidRule(); first.DomainSuffixes = new List<string>{"example.com"};
            var second = TestModels.ValidRule(); second.Domains = new List<string>{"store.example.com"};
            Assert.That(DomainRules.Overlap(first,second),Is.True);
            second.Domains[0] = "evilexample.com";
            Assert.That(DomainRules.Overlap(first,second),Is.False);
            second.Domains[0] = "example.com";
            Assert.That(DomainRules.Overlap(first,second),Is.True);
        }

        [Test]
        public void ExcessiveListsAndWrongJsonTypesAreRejected()
        {
            var rule = TestModels.ValidRule(); rule.Domains = Enumerable.Repeat("example.com",257).ToList();
            Assert.That(new ConfigurationValidator().ValidateRule(rule).Issues.Any(issue => issue.Code == "DOMAIN_LIMIT"),Is.True);
            Assert.Throws<ConfigurationFormatException>(() => new ConfigurationSerializer().Deserialize(
                "{\"proxies\":[{\"appNames\":[\"steam.exe\"],\"domains\":\"example.com\"}]}"));
        }
    }
}
