using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SslCertBinding.Net.Sample.Tests
{
	[TestClass]
	public class BindingEndPointTests
	{
		[TestMethod]
		public void CtorShouldInitialiseFromIPAddressAndPort()
		{
			var endPoint = new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999);
			Assert.AreEqual(endPoint.Port, 8999);
			Assert.AreEqual(endPoint.IpAddress.ToString(), "127.0.0.1");
			Assert.AreEqual(endPoint.EndPointType, BindingEndPointType.IpAddress);
			Assert.AreEqual(endPoint.AddressAndPort, "127.0.0.1:8999");
			Assert.IsNull(endPoint.HostName);
		}

		[TestMethod]
		public void CtorShouldInitialiseFromHostNameAndPort()
		{
			var endPoint = new BindingEndPoint("testhost", 8999);
			Assert.AreEqual(endPoint.Port, 8999);
			Assert.AreEqual(endPoint.HostName, "testhost");
			Assert.AreEqual(endPoint.IpAddress, IPAddress.Any);
			Assert.AreEqual(endPoint.EndPointType, BindingEndPointType.HostName);
			Assert.AreEqual(endPoint.AddressAndPort, "testhost:8999");
		}

		[TestMethod]
		public void EqualsShouldMatchSameValues()
		{
			Assert.AreEqual(new BindingEndPoint("testhost", 8999), new BindingEndPoint("testhost", 8999));
			Assert.AreEqual(new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999), new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999));
		}

		[TestMethod]
		public void EqualsShouldNotMatchDifferentValues()
		{
			Assert.AreNotEqual(new BindingEndPoint("testhost", 8999), new BindingEndPoint("testhost", 9999));
			Assert.AreNotEqual(new BindingEndPoint("testhost1", 8999), new BindingEndPoint("testhost2", 8999));
			Assert.AreNotEqual(new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999), new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 9999));
			Assert.AreNotEqual(new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999), new BindingEndPoint(IPAddress.Parse("127.0.0.2"), 8999));
		}

		[TestMethod]
		public void ParseShouldParseHostNameAndPort()
		{
			var endPoint = BindingEndPoint.Parse("testhost:8999");

			Assert.AreEqual(new BindingEndPoint("testhost", 8999),  endPoint);
		}

		[TestMethod]
		public void TryParseShouldParseValidAddresses()
		{
			BindingEndPoint endPoint;
			bool result;

			result = BindingEndPoint.TryParse("testhost:8999", out endPoint);
			Assert.IsTrue(result);
			Assert.AreEqual(new BindingEndPoint("testhost", 8999), endPoint);

			result = BindingEndPoint.TryParse("127.0.0.1:8999", out endPoint);
			Assert.IsTrue(result);
			Assert.AreEqual(new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999), endPoint);
		}

		[TestMethod]
		public void TryParseShouldNotParseInvalidAddresses()
		{
			BindingEndPoint endPoint;
			var result = BindingEndPoint.TryParse("askfljasdfl", out endPoint);
			Assert.IsFalse(result);
			Assert.IsNull(endPoint);
		}

		[TestMethod]
		public void ParseShouldParseIpAddressAndPort()
		{
			var endPoint = BindingEndPoint.Parse("127.0.0.1:8999");

			Assert.AreEqual(new BindingEndPoint(IPAddress.Parse("127.0.0.1"), 8999), endPoint);
		}
	}
}