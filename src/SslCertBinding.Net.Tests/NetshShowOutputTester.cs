using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SslCertBinding.Net.Sample.Tests
{
	public static class NetshShowOutputTester
	{
		public static void AssertContainsOutput(string output, string expected)
		{
			string normalisedOutput = NormaliseShowOutput(output);
			string normalisedExpectedOutput = NormaliseShowOutput(expected);
			StringAssert.Contains(normalisedOutput, normalisedExpectedOutput);
		}

		private static string NormaliseShowOutput(string output)
		{
			string result = Regex.Replace(output, "^\\s*", "", RegexOptions.Multiline);
			result = Regex.Replace(result, "\\s*$", "", RegexOptions.Multiline);
			result = Regex.Replace(result, "\\s*:\\s*", ":");
			return result.ToLowerInvariant();
		}
	}
}