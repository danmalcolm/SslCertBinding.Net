using System.Net;

namespace SslCertBinding.Net
{
	public interface ICertificateBindingConfiguration
	{
		CertificateBinding[] Query(BindingEndPoint endPoint);
		bool Bind(CertificateBinding binding);
		void Delete(BindingEndPoint endPoint);
		void Delete(BindingEndPoint[] endPoints);
	}
}