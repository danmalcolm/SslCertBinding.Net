using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Sample
{
	class Program
	{
		private static void Main(string[] args) {
			var configuration = new CertificateBindingConfiguration();

			string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;

			switch (command){
				case "show":
					Show(args, configuration);
					break;
				case "bind":
					Bind(args, configuration);
					break;
				case "delete":
					Delete(args, configuration);
					break;
				default:
					Console.WriteLine("Use \r\n'show [<IP or hostname:port>]' command to show all SSL Certificate bindings, \r\n'delete <IP:port>' to remove a binding and \r\n'bind <certificateThumbprint> <certificateStoreName> <IP:port> <appId>' to add or update a binding.");
					break;
			}
		}

		private static void Show(string[] args, CertificateBindingConfiguration configuration) {
			Console.WriteLine("SSL Certificate bindings:\r\n-------------------------\r\n");
			var stores = new Dictionary<string, X509Store>();
			var endPoint = args.Length > 1 ? ParseEndPoint(args[1]) : null;
			var certificateBindings = configuration.Query(endPoint);
			foreach (var info in certificateBindings){
				X509Store store;
				if (!stores.TryGetValue(info.StoreName, out store)){
					store = new X509Store(info.StoreName, StoreLocation.LocalMachine);
					store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
					stores.Add(info.StoreName, store);
				}

				var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, info.Thumbprint, false)[0];
				string addressAndPortLabel = info.EndPoint.EndPointType == BindingEndPointType.IpAddress
					? "IP:port        "
					: "Hostname:port  ";
				string certStr = String.Format(
@" {0}: {1}
 Thumbprint     : {2}
 Subject        : {3}
 Issuer         : {4}
 Application ID : {5}
 Store Name     : {6}
 Verify Client Certificate Revocation                   : {7}
 Verify Revocation Using Cached Client Certificate Only : {8}
 Usage Check                 : {9}
 Revocation Freshness Time   : {10}
 URL Retrieval Timeout       : {11}
 Ctl Identifier : {12}
 Ctl Store Name : {13}
 DS Mapper Usage             : {14}
 Negotiate Client Certificate: {15}
",
					addressAndPortLabel, info.EndPoint.AddressAndPort, info.Thumbprint, certificate.Subject, certificate.Issuer, 
					info.AppId, info.StoreName, !info.Options.DoNotVerifyCertificateRevocation, info.Options.VerifyRevocationWithCachedCertificateOnly, 
					!info.Options.NoUsageCheck, info.Options.RevocationFreshnessTime + (info.Options.EnableRevocationFreshnessTime ? string.Empty : " (disabled)"),
					info.Options.RevocationUrlRetrievalTimeout, info.Options.SslCtlIdentifier, info.Options.SslCtlStoreName, 
					info.Options.UseDsMappers, info.Options.NegotiateCertificate);
				Console.WriteLine(certStr);
			}
		}

		private static void Bind(string[] args, CertificateBindingConfiguration configuration){
			var endPoint = ParseEndPoint(args[3]);
			var updated = configuration.Bind(new CertificateBinding(args[1], args[2], endPoint, Guid.Parse(args[4])));
			Console.WriteLine(updated ? "The binding record has been successfully updated." : "The binding record has been successfully added.");
		}

		private static void Delete(string[] args, CertificateBindingConfiguration configuration){
			var endPoint = ParseEndPoint(args[1]);
			configuration.Delete(endPoint);
			Console.WriteLine("The binding record has been successfully removed.");
		}

		private static BindingEndPoint ParseEndPoint(string str)
		{
			BindingEndPoint endPoint;
			if (!BindingEndPoint.TryParse(str, out endPoint))
			{
				throw new ArgumentException("Invalid endpoint address");
			}
			return endPoint;
		}
	}
}
