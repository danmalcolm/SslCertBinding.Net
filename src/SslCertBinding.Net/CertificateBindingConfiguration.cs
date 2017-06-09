using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
	public class CertificateBindingConfiguration : ICertificateBindingConfiguration
	{
		private delegate object CreateInputConfig(uint token);
		private delegate CertificateBinding MapBinding<in T>(T output);
		private delegate void Action();

		public CertificateBinding[] Query(BindingEndPoint endPoint = null) {
			if (endPoint == null) 
				return QueryAll();

			var info = QueryExact(endPoint);
			return info == null ? new CertificateBinding[0] : new[] { info };
		}
		
		public bool Bind(CertificateBinding binding) {
			var options = binding.Options;
			byte[] hash = GetHash(binding.Thumbprint);
			var handleHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
				
			var paramDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM
			{
				AppId = binding.AppId,
				DefaultCertCheckMode = (options.DoNotVerifyCertificateRevocation ? HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation : 0)
				                       | (options.VerifyRevocationWithCachedCertificateOnly ? HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly : 0)
				                       | (options.EnableRevocationFreshnessTime ? HttpApi.CertCheckModes.EnableRevocationFreshnessTime : 0)
				                       | (options.NoUsageCheck ? HttpApi.CertCheckModes.NoUsageCheck : 0),
				DefaultFlags = (options.NegotiateCertificate ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT : 0)
				               | (options.UseDsMappers ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER : 0)
				               | (options.DoNotPassRequestsToRawFilters ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER : 0),
				DefaultRevocationFreshnessTime = (int)options.RevocationFreshnessTime.TotalSeconds,
				DefaultRevocationUrlRetrievalTimeout = (int)options.RevocationUrlRetrievalTimeout.TotalMilliseconds,
				pSslCertStoreName = binding.StoreName,
				pSslHash = handleHash.AddrOfPinnedObject(),
				SslHashLength = hash.Length,
				pDefaultSslCtlIdentifier = options.SslCtlIdentifier,
				pDefaultSslCtlStoreName = options.SslCtlStoreName
			};

			var endPoint = binding.EndPoint;
			if (endPoint.EndPointType == BindingEndPointType.IpAddress)
			{
				// Add SSL binding by IP
				GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(endPoint.IpEndPoint);
				IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
				var keyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);
				var configInformation = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET {
					KeyDesc = keyDesc,
					ParamDesc = paramDesc
				};

				return SetInternal(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo, 
					configInformation,
					delegate()
					{
						if (handleHash.IsAllocated)
							handleHash.Free();
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					}
				);
			}
			else
			{
				// Add SSL SNI binding based on hostname
				var sockAddrStorage = SockAddrStorageInterop.CreateSockaddrStorage(endPoint.Port);
				var keyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_KEY(sockAddrStorage, endPoint.HostName);
				var configInformation = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET
				{
					KeyDesc = keyDesc,
					ParamDesc = paramDesc
				};

				return SetInternal(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
					configInformation,
					delegate()
					{
						if (handleHash.IsAllocated)
							handleHash.Free();
					}
				);
			}

		}

		/// <summary>
		/// Indicates whether the current machine supports SSL SNI bindings
		/// </summary>
		/// <returns></returns>
		public bool SupportsSslSniBindings()
		{
			bool supported = false;
			HttpApi.CallHttpApi(delegate
			{
				var inputConfigInfo = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
				{
					QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
					dwToken = 0
				};
				IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
					Marshal.SizeOf(inputConfigInfo.GetType()));
				Marshal.StructureToPtr(inputConfigInfo, pInputConfigInfo, false);

				IntPtr pOutputConfigInfo = IntPtr.Zero;
				int returnLength = 0;
				try
				{
					int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfo);
					uint retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
						HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo, 
						pInputConfigInfo,
						inputConfigInfoSize,
						pOutputConfigInfo,
						returnLength,
						out returnLength,
						IntPtr.Zero);
					if (retVal == HttpApi.ERROR_THE_PARAMETER_IS_INCORRECT)
					{
						// Expected result code if HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
						// is not supported
						supported = false;
					}
					else if (retVal == HttpApi.ERROR_FILE_NOT_FOUND
						|| retVal == HttpApi.ERROR_NO_MORE_ITEMS
						|| retVal == HttpApi.ERROR_INSUFFICIENT_BUFFER)
					{
						// Successful and no results found or we need to make
						// call with buffer size matching output
						supported = true;
					}
					else
					{
						HttpApi.ThrowWin32ExceptionIfError(retVal);
					}
				}
				finally
				{
					Marshal.FreeCoTaskMem(pInputConfigInfo);
				}
			});
			return supported;
		}

		private bool SetInternal(HttpApi.HTTP_SERVICE_CONFIG_ID configId, object configInformation, Action cleanUp) {
			bool bindingUpdated = false;
			HttpApi.CallHttpApi(
				delegate
				{
					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
						Marshal.SizeOf(configInformation.GetType()));
					Marshal.StructureToPtr(configInformation, pInputConfigInfo, false);

					try
					{
						uint retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
							configId,
							pInputConfigInfo,
							Marshal.SizeOf(configInformation),
							IntPtr.Zero);

						if (HttpApi.ERROR_ALREADY_EXISTS != retVal)
						{
							HttpApi.ThrowWin32ExceptionIfError(retVal);
						}
						else
						{
							retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
								configId,
								pInputConfigInfo,
								Marshal.SizeOf(configInformation),
								IntPtr.Zero);
							HttpApi.ThrowWin32ExceptionIfError(retVal);

							retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
								configId,
								pInputConfigInfo,
								Marshal.SizeOf(configInformation),
								IntPtr.Zero);
							HttpApi.ThrowWin32ExceptionIfError(retVal);
							bindingUpdated = true;
						}
					}
					finally
					{
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (cleanUp != null)
						{
							cleanUp();
						}
					}
				});
			return bindingUpdated;
		}

		public void Delete(BindingEndPoint endPoint) {
			Delete(new[] { endPoint });
		}

		public void Delete(BindingEndPoint[] endPoints)
		{
			if (endPoints == null)
				throw new ArgumentNullException("endPoints");
			if (endPoints.Length == 0)
				return;

			HttpApi.CallHttpApi(
			delegate {
				foreach (var endPoint in endPoints) {
					if (endPoint.EndPointType == BindingEndPointType.IpAddress)
					{
						var sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(endPoint.IpEndPoint);
						var pIpPort = sockAddrHandle.AddrOfPinnedObject();
						var keyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);
						var configInformation = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET
						{
							KeyDesc = keyDesc
						};
						Delete(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
							configInformation, delegate
							{
								if (sockAddrHandle.IsAllocated)
									sockAddrHandle.Free();
							});
					}
					else
					{
						var sockAddrStorage = SockAddrStorageInterop.CreateSockaddrStorage(endPoint.Port);
						var keyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_KEY(sockAddrStorage, endPoint.HostName);
						var configInformation = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET
						{
							KeyDesc = keyDesc
						};
						Delete(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
							configInformation, null);
					}
					
				}
			});
		}

		private void Delete(HttpApi.HTTP_SERVICE_CONFIG_ID configId, object configInformation, Action cleanUp)
		{
			IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
				Marshal.SizeOf(configInformation.GetType()));
			Marshal.StructureToPtr(configInformation, pInputConfigInfo, false);

			try
			{
				uint retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
					configId,
					pInputConfigInfo,
					Marshal.SizeOf(configInformation),
					IntPtr.Zero);
				HttpApi.ThrowWin32ExceptionIfError(retVal);
			}
			finally
			{
				Marshal.FreeCoTaskMem(pInputConfigInfo);
				if (cleanUp != null)
					cleanUp();
			}
					
		}

		private static CertificateBinding QueryExact(BindingEndPoint endPoint)
		{
			if (endPoint.EndPointType == BindingEndPointType.IpAddress)
			{
				// Query SSL binding by IP
				GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(endPoint.IpEndPoint);
				IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();

				var inputConfigInfo = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
				{
					QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
					KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort)
				};
				
				return QuerySingle(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo, inputConfigInfo,
					delegate(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET output)
					{
						return CreateCertificateBindingInfo(output);
					},
					delegate()
					{
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					});
				
			}
			else
			{
				// Query SSL SNI binding by hostname
				var sockAddrStorage = SockAddrStorageInterop.CreateSockaddrStorage(endPoint.Port);
				var inputConfigInfo = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
				{
					QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
					KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_KEY(sockAddrStorage, endPoint.HostName)
				};

				return QuerySingle(HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo, inputConfigInfo,
					delegate(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET output)
					{
						return CreateCertificateBindingInfo(output);
					},
					null);
			}
		}

		/// <summary>
		/// Generic method that allows for variation according to whether we are querying
		/// by hostname or just IP address
		/// </summary>
		private static CertificateBinding QuerySingle<TOutput>(HttpApi.HTTP_SERVICE_CONFIG_ID configId, 
			object inputConfigInfo, MapBinding<TOutput> mapBinding, Action cleanUp)
		{
			CertificateBinding result = null;
			
			uint retVal;
			HttpApi.CallHttpApi(
				delegate
				{
					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
						Marshal.SizeOf(inputConfigInfo.GetType()));
					Marshal.StructureToPtr(inputConfigInfo, pInputConfigInfo, false);

					IntPtr pOutputConfigInfo = IntPtr.Zero;
					int returnLength = 0;

					try
					{
						int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfo);
						retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
							configId,
							pInputConfigInfo,
							inputConfigInfoSize,
							pOutputConfigInfo,
							returnLength,
							out returnLength,
							IntPtr.Zero);
						if (retVal == HttpApi.ERROR_FILE_NOT_FOUND)
							return;

						if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
						{
							pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);
							try
							{
								retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
									configId,
									pInputConfigInfo,
									inputConfigInfoSize,
									pOutputConfigInfo,
									returnLength,
									out returnLength,
									IntPtr.Zero);
								HttpApi.ThrowWin32ExceptionIfError(retVal);

								var outputConfigInfo = (TOutput)Marshal.PtrToStructure(
									pOutputConfigInfo, typeof(TOutput));
								result = mapBinding(outputConfigInfo);
							}
							finally
							{
								Marshal.FreeCoTaskMem(pOutputConfigInfo);
							}
						}
						else
						{
							HttpApi.ThrowWin32ExceptionIfError(retVal);
						}

					}
					finally
					{
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (cleanUp != null)
						{
							cleanUp();
						}
					}
				});

			return result;
		}
		

		private CertificateBinding[] QueryAll()
		{
			// SSL bindings
			var result = QueryMany(
				HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
				delegate(uint token1)
				{
					return new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
					{
						QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
						dwToken = token1
					};
				},
				delegate(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET output2)
				{
					return CreateCertificateBindingInfo(output2);
				}
			);
			// SSL SNI bindings (based on host)
			if (SupportsSslSniBindings())
			{
				var sslSniBindings = QueryMany(
					HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
					delegate(uint token2)
					{
						return new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
						{
							QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
							dwToken = token2
						};
					},
					delegate(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET output2)
					{
						return CreateCertificateBindingInfo(output2);
					}
				);
				result.AddRange(sslSniBindings);
			}
			return result.ToArray();
		}

		private static List<CertificateBinding> QueryMany<TOutput>(HttpApi.HTTP_SERVICE_CONFIG_ID configId, CreateInputConfig createInput, MapBinding<TOutput> mapBinding)
			where TOutput : struct 
		{
			var result = new List<CertificateBinding>();

			HttpApi.CallHttpApi(
				delegate
				{
					uint token = 0;

					uint retVal;
					do
					{
						var inputConfigInfo = createInput(token);
						IntPtr inputConfigInfoPointer = Marshal.AllocCoTaskMem(
							Marshal.SizeOf(inputConfigInfo.GetType()));
						Marshal.StructureToPtr(inputConfigInfo, inputConfigInfoPointer, false);

						IntPtr pOutputConfigInfo = IntPtr.Zero;
						int returnLength = 0;

						try
						{
							int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfo);
							retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
								configId,
								inputConfigInfoPointer,
								inputConfigInfoSize,
								pOutputConfigInfo,
								returnLength,
								out returnLength,
								IntPtr.Zero);
							if (HttpApi.ERROR_NO_MORE_ITEMS == retVal)
								break;
							if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
							{
								pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);

								try
								{
									retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
										configId,
										inputConfigInfoPointer,
										inputConfigInfoSize,
										pOutputConfigInfo,
										returnLength,
										out returnLength,
										IntPtr.Zero);
									HttpApi.ThrowWin32ExceptionIfError(retVal);

									var outputConfigInfo = (TOutput)Marshal.PtrToStructure(
										pOutputConfigInfo, typeof(TOutput));
									var resultItem = mapBinding(outputConfigInfo);
									result.Add(resultItem);
									token++;
								}
								finally
								{
									Marshal.FreeCoTaskMem(pOutputConfigInfo);
								}
							}
							else
							{
								HttpApi.ThrowWin32ExceptionIfError(retVal);
							}
						}
						finally
						{
							Marshal.FreeCoTaskMem(inputConfigInfoPointer);
						}

					} while (HttpApi.NOERROR == retVal);

				});

			return result;
		}



		private static CertificateBinding CreateCertificateBindingInfo(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET configInfo) {
			byte[] hash = new byte[configInfo.ParamDesc.SslHashLength];
			Marshal.Copy(configInfo.ParamDesc.pSslHash, hash, 0, hash.Length);
			Guid appId = configInfo.ParamDesc.AppId;
			string storeName = configInfo.ParamDesc.pSslCertStoreName;
			IPEndPoint ipPort = SockaddrInterop.ReadSockaddrStructure(configInfo.KeyDesc.pIpPort);
			var endPoint = new BindingEndPoint(ipPort);
			var options = CreateBindingOptions(configInfo.ParamDesc);
			var result = new CertificateBinding(GetThumbrint(hash), storeName, endPoint, appId, options);
			return result;
		}

		private static CertificateBinding CreateCertificateBindingInfo(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET configInfo)
		{
			byte[] hash = new byte[configInfo.ParamDesc.SslHashLength];
			Marshal.Copy(configInfo.ParamDesc.pSslHash, hash, 0, hash.Length);
			Guid appId = configInfo.ParamDesc.AppId;
			string storeName = configInfo.ParamDesc.pSslCertStoreName;
			IPEndPoint ipPort = CreateIPEndPoint(configInfo.KeyDesc.IpPort);
			string hostName = configInfo.KeyDesc.Host;
			var endPoint = new BindingEndPoint(hostName, ipPort.Port);
			var options = CreateBindingOptions(configInfo.ParamDesc);
			var result = new CertificateBinding(GetThumbrint(hash), storeName, endPoint, appId, options);
			return result;
		}

		private static BindingOptions CreateBindingOptions(HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc)
		{
			var checkModes = paramDesc.DefaultCertCheckMode;
			var options = new BindingOptions
			{
				DoNotVerifyCertificateRevocation = HasFlag(checkModes, HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation),
				VerifyRevocationWithCachedCertificateOnly = HasFlag(checkModes,
					HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly),
				EnableRevocationFreshnessTime = HasFlag(checkModes, HttpApi.CertCheckModes.EnableRevocationFreshnessTime),
				NoUsageCheck = HasFlag(checkModes, HttpApi.CertCheckModes.NoUsageCheck),
				RevocationFreshnessTime = TimeSpan.FromSeconds(paramDesc.DefaultRevocationFreshnessTime),
				RevocationUrlRetrievalTimeout = TimeSpan.FromMilliseconds(paramDesc.DefaultRevocationUrlRetrievalTimeout),
				SslCtlIdentifier = paramDesc.pDefaultSslCtlIdentifier,
				SslCtlStoreName = paramDesc.pDefaultSslCtlStoreName,
				NegotiateCertificate = HasFlag(paramDesc.DefaultFlags,
					HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT),
				UseDsMappers = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER),
				DoNotPassRequestsToRawFilters = HasFlag(paramDesc.DefaultFlags,
					HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER),
			};
			return options;
		}

		private static IPEndPoint CreateIPEndPoint(HttpApi.SOCKADDR_STORAGE storage)
		{
			short sAddressFamily = storage.ss_family;
			AddressFamily addressFamily = (AddressFamily)sAddressFamily;

			switch (addressFamily)
			{
				case AddressFamily.InterNetwork:
					// IP v4 address
					var sockAddrSructureSize = 8;
					var socketAddress = new SocketAddress(AddressFamily.InterNetwork, sockAddrSructureSize);
					socketAddress[0] = 2;
					socketAddress[1] = 0;
					for (int i = 2; i < sockAddrSructureSize; i++)
					{
						socketAddress[i] = storage.__ss_pad1[i - 2];
					}

					var ipEndPointAny = new IPEndPoint(IPAddress.Any, 0);
					return (IPEndPoint)ipEndPointAny.Create(socketAddress);
				default:
					throw new ArgumentOutOfRangeException("storage", "Unknown address family");
			}
		}

		private static string GetThumbrint(byte[] hash) {
			string thumbrint = BitConverter.ToString(hash).Replace("-", "");
			return thumbrint;
		}

		private static byte[] GetHash(string thumbprint) {
			int length = thumbprint.Length;
			byte[] bytes = new byte[length / 2];
			for (int i = 0; i < length; i += 2)
				bytes[i / 2] = Convert.ToByte(thumbprint.Substring(i, 2), 16);
			return bytes;
		}

		private static bool HasFlag(uint value, uint flag) {
			return (value & flag) == flag;
		}

		private static bool HasFlag<T>(T value, T flag) where T : IConvertible {
			var uintValue = Convert.ToUInt32(value);
			var uintFlag = Convert.ToUInt32(flag);
			return HasFlag(uintValue, uintFlag);
		}
	}
}
