using System.Net;
using System.Net.Sockets;

namespace SslCertBinding.Net
{
	internal class SockAddrStorageInterop
	{
		internal static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(int port)
		{
			var result = new HttpApi.SOCKADDR_STORAGE();
			result.ss_family = (short)AddressFamily.InterNetwork;
			var ipEndPoint = new IPEndPoint(IPAddress.Any, port);
			var socketAddress = ipEndPoint.Serialize();
			// https://msdn.microsoft.com/en-us/library/windows/desktop/ms740504(v=vs.85).aspx
			// __ss_pad1 is 6 bytes in length - socketAddress is 16...
			result.__ss_pad1 = new byte[6];
			for (var i = 2; i < 8; i++)
			{
				result.__ss_pad1[i - 2] = socketAddress[i];
			}
			return result;
		}
	}
}