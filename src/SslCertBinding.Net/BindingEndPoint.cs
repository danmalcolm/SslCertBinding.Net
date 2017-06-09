using System;
using System.Net;
using System.Text.RegularExpressions;

namespace SslCertBinding.Net
{
	/// <summary>
	/// Represents a binding endpoint combining either an IP address or hostname with a port
	/// </summary>
	/// <remarks>Could be replaced with IPEndPoint and DnsEndPoint if we upgrade to .Net 4.0+</remarks>
	public class BindingEndPoint
	{
		/// <summary>
		/// Creates BindingEndPoint from a string representing a host name / IP address
		/// followed by a colon and then a port number. Note that host names are restricted
		/// to the alphanumeric characters, hyphens and periods but are not validated in terms
		/// of any internet address specification.
		/// </summary>
		/// <param name="value"></param>
		/// <returns>A BindingEndPoint initialise with the address and port supplied</returns>
		public static BindingEndPoint Parse(string value)
		{
			BindingEndPoint endPoint;
			if (!TryParse(value, out endPoint))
			{
				throw new FormatException("Invalid format");
			}
			return endPoint;
		}

		/// <summary>
		/// Determines whether a string contains a valid BindingEndPoint address (a string 
		/// representing a host name / IP address followed by a colon and then a port number).
		/// Note that host names are restricted to the alphanumeric characters, hyphens and 
		/// periods but are not validated in terms of any internet address specification.
		/// </summary>
		/// <param name="value"></param>
		/// <param name="endPoint">The BindingEndPoint initialised from the value supplied</param>
		/// <returns>A value indicating whether the value was parsed successfully</returns>
		public static bool TryParse(string value, out BindingEndPoint endPoint)
		{
			if (value == null) throw new ArgumentNullException("value");

			var result = Regex.Match(value, "([a-zA-Z0-9-\\.]+):(\\d+)");
			if (result.Success)	
			{
				string address = result.Groups[1].Value;
				int port = int.Parse(result.Groups[2].Value);
				IPAddress ipAddress;
				if (IPAddress.TryParse(address, out ipAddress))
				{
					endPoint = new BindingEndPoint(ipAddress, port);
				}
				else
				{
					endPoint = new BindingEndPoint(address, port);
				}
				return true;
			}
			endPoint = null;
			return false;
		}

		/// <summary>
		/// Creates a BindingEndPoint from an IPAddress and port
		/// </summary>
		/// <param name="ipAddress"></param>
		/// <param name="port"></param>
		public BindingEndPoint(IPAddress ipAddress, int port)
			: this(new IPEndPoint(ipAddress, port))
		{
		}

		/// <summary>
		/// Creates a BindingEndPoint from an IPEndPoint
		/// </summary>
		/// <param name="ipEndPoint"></param>
		public BindingEndPoint(IPEndPoint ipEndPoint) : this (ipEndPoint, null, BindingEndPointType.IpAddress)
		{
			
		}

		/// <summary>
		/// Creates a BindingEndPoint from a host name and port
		/// </summary>
		/// <param name="hostName"></param>
		/// <param name="port"></param>
		public BindingEndPoint(string hostName, int port)
			: this(new IPEndPoint(IPAddress.Any, port), hostName, BindingEndPointType.HostName)
		{
			if (hostName == null) throw new ArgumentNullException("hostName");
		}

		private BindingEndPoint(IPEndPoint ipEndPoint, string hostName, BindingEndPointType endPointType)
		{
			IpEndPoint = ipEndPoint;
			HostName = hostName;
			EndPointType = endPointType;
			AddressAndPort = EndPointType == BindingEndPointType.IpAddress
				? IpEndPoint.ToString()
				: string.Format("{0}:{1}", hostName, Port);
		}

		/// <summary>
		/// Gets the IPAddress used for this binding - this will be 
		/// IPAddress.Any if a host name is specified. If the <see cref="IPEndPoint.Address"/> 
		/// property is set to 0.0.0.0, the certificate is applicable to all IPv4 and IPv6 addresses.
		/// If the <see cref="IPEndPoint.Address"/> property is set to [::], the certificate is applicable 
		/// to all IPv6 addresses.
		/// </summary>
		public IPAddress IpAddress { get { return IpEndPoint.Address; } }

		/// <summary>
		/// The host name used for this binding
		/// </summary>
		public string HostName { get; private set; }

		/// <summary>
		/// The port used for this binding
		/// </summary>
		public int Port { get { return IpEndPoint.Port; } }

		/// <summary>
		/// The type of endpoint
		/// </summary>
		public BindingEndPointType EndPointType { get; private set; }

		/// <summary>
		/// Gets an IPEndPoint for the IP address and port. The IP address will be
		/// based on IPAddress.Any if a host name is used
		/// </summary>
		public IPEndPoint IpEndPoint { get; private set; }

		/// <summary>
		/// Gets a string combining the IP address or host name followed by the
		/// port separated by a colon character
		/// </summary>
		public string AddressAndPort {get; private set; }

		protected bool Equals(BindingEndPoint other)
		{
			return string.Equals(HostName, other.HostName) && EndPointType == other.EndPointType && Equals(IpEndPoint, other.IpEndPoint);
		}

		public override bool Equals(object obj)
		{
			if (ReferenceEquals(null, obj)) return false;
			if (ReferenceEquals(this, obj)) return true;
			if (obj.GetType() != this.GetType()) return false;
			return Equals((BindingEndPoint) obj);
		}

		public override int GetHashCode()
		{
			unchecked
			{
				var hashCode = (HostName != null ? HostName.GetHashCode() : 0);
				hashCode = (hashCode * 397) ^ (int) EndPointType;
				hashCode = (hashCode * 397) ^ (IpEndPoint != null ? IpEndPoint.GetHashCode() : 0);
				return hashCode;
			}
		}

		public override string ToString()
		{
			return AddressAndPort;
		}
	}
}