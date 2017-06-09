using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net
{
	/// <summary>
	/// Defines a record in the SSL configuration store
	/// </summary>
	public class CertificateBinding
	{
		/// <summary>
		/// A string representation the SSL certificate hash. 
		/// </summary>
		public string Thumbprint { get; private set; }

		/// <summary>
		/// The name of the store from which the server certificate is to be read. If set to NULL, "MY" is assumed as the default name. 
		/// The specified certificate store name must be present in the Local Machine store location.
		/// </summary>
		public string StoreName { get; private set; }

		/// <summary>
		/// The binding with which this SSL certificate is associated. This will combine either an IP address
		/// and port or a host name and port for bindings in the SSL Server Name Indication (SNI) store 
		/// </summary>
		public BindingEndPoint EndPoint { get; private set; }

		/// <summary>
		/// A unique identifier of the application setting this record.
		/// </summary>
		public Guid AppId { get; private set; }

		/// <summary>
		/// Additional options.
		/// </summary>
		public BindingOptions Options { get; private set; }

		public CertificateBinding(string certificateThumbprint, StoreName certificateStoreName, BindingEndPoint endPoint, Guid appId, BindingOptions options = null)
			: this(certificateThumbprint, certificateStoreName.ToString(), endPoint, appId, options) { }

		public CertificateBinding(string certificateThumbprint, string certificateStoreName, BindingEndPoint endPoint, Guid appId, BindingOptions options = null)
		{

			if (certificateThumbprint == null) throw new ArgumentNullException("certificateThumbprint");
			if (endPoint == null) throw new ArgumentNullException("endPoint");


			if (certificateStoreName == null) {
				// StoreName of null is assumed to be My / Personal
				// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364647(v=vs.85).aspx
				certificateStoreName = "MY";
			}

			Thumbprint = certificateThumbprint;
			StoreName = certificateStoreName;
			EndPoint = endPoint;
			AppId = appId;
			Options = options ?? new BindingOptions();
		}
	}
}