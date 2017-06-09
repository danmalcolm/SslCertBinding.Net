using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SslCertBinding.Net.Sample.Tests.Properties;

namespace SslCertBinding.Net.Sample.Tests
{
	internal static class TestCertificateInstaller
	{
		private const string TestCertificateSubject = "CN=SSLCertBinding.Net.Sample.Tests";
		private const string IssuerCertificateSubject = "CN=SSLCertBinding.Net.Sample.Tests Root CA";
			
		/// <summary>
		/// Installs a test certificate and returns the thumbprint of the certificate
		/// </summary>
		/// <returns></returns>
		public static string InstallTestCertificates()
		{
			var collection = new X509Certificate2Collection();
			collection.Import(Resources.TestCertsPfx, "", X509KeyStorageFlags.PersistKeySet);
			var issuerCertificate = FindSingleBySubject(collection, IssuerCertificateSubject);
			var testCertificate = FindSingleBySubject(collection, TestCertificateSubject);
			
			WithLocalMachineStore(StoreName.AuthRoot, store => store.Add(issuerCertificate));
			WithLocalMachineStore(StoreName.My, store => store.Add(testCertificate));
			// Also add the test certificate to the Trusted Root Certification Authorities as some
			// tests validate that certificate is added from specific stores
			WithLocalMachineStore(StoreName.AuthRoot, store => store.Add(testCertificate));

			return testCertificate.Thumbprint;
		}

		private static IEnumerable<X509Certificate2> FindBySubject(X509Certificate2Collection collection, string subjectName)
		{
			return collection.Cast<X509Certificate2>()
				.Where(x => x.Subject == subjectName);
		}

		private static X509Certificate2 FindSingleBySubject(X509Certificate2Collection collection, string subjectName)
		{
			var certificate = FindBySubject(collection, subjectName).SingleOrDefault();
			if (certificate == null)
			{
				throw new Exception(string.Format("Expected test certificate {0} not found in TestCertsPfx resource", subjectName));
			}
			return certificate;
		}
		public static void UninstallTestCertificates()
		{
			RemoveCertificate(StoreName.My, TestCertificateSubject);
			RemoveCertificate(StoreName.AuthRoot, IssuerCertificateSubject);
			RemoveCertificate(StoreName.AuthRoot, TestCertificateSubject);
		}

		private static void WithLocalMachineStore(StoreName storeName, Action<X509Store> action)
		{
			var store = new X509Store(storeName, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
			action(store);
			store.Close();
		}
		public static void RemoveCertificate(StoreName storeName, string subject)
		{
			WithLocalMachineStore(storeName, store =>
			{
				var certificates = FindBySubject(store.Certificates, subject).ToList();
				certificates.ForEach(store.Remove);
			});
		}
	}
}