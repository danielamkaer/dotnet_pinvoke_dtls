using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace Dtls
{
	public class DtlsSocket
	{
		class Timer
		{
			System.Timers.Timer internalTimer;
			public bool IsElapsed { get; private set; } = false;

			public Timer(uint delay)
			{
				internalTimer = new System.Timers.Timer(delay)
				{
					AutoReset = false
				};
				internalTimer.Elapsed += InternalTimer_Elapsed;
				internalTimer.Start();
			}

			private void InternalTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
			{
				IsElapsed = true;
			}
		}

		IntPtr instance;
		readonly UdpClient udpClient;
		readonly IPEndPoint remote;

		Timer intermediateTimer;
		Timer finalTimer;

		public DtlsSocket(UdpClient udpClient, IPEndPoint remote)
		{
			instance = NativeMethods.Dtls_Create(new NativeMethods.ContextFunctions {
				SendFunction = NativeSendFunction,
				ReceiveFunction = NativeReceiveFunction,
				ReceiveWithTimeoutFunction = null,
				SetTimerFunction = NativeSetTimerFunction,
				GetTimerFunction = NativeGetTimerFunction
			});
			this.udpClient = udpClient;
			this.remote = remote;

			this.udpClient.Connect(remote);
		}

		public void SetPresharedKey(byte[] presharedKey, byte[] identity)
		{
			var result = NativeMethods.Dtls_SetPresharedKey(instance, presharedKey, presharedKey.Length, identity, identity.Length);

			if (result != 0)
			{
				throw new MbedtlsException(result);
			}
		}

		public Task AuthenticateAsClientAsync()
		{
			return Task.Run(() => AuthenticateAsClient());
		}

		public void AuthenticateAsClient()
		{
			var result = NativeMethods.Dtls_Handshake(instance);

			if (result != 0)
			{
				throw new MbedtlsException(result);
			}
		}

		public void Write(byte[] buffer, int bufferLength)
		{
			NativeMethods.Dtls_Write(instance, buffer, (uint) bufferLength);
		}

		public byte[] Read()
		{
			byte[] buffer = new byte[16 * 1024];
			int amountRead = NativeMethods.Dtls_Read(instance, buffer, (uint) buffer.Length);

			var data = new byte[amountRead];
			Array.Copy(buffer, 0, data, 0, amountRead);

			return data;
		}

		public Task<byte[]> ReadAsync()
		{
			return Task.Run(() => Read());
		}

		int NativeSendFunction(IntPtr instance, byte[] buffer, uint bufferSize)
		{
			Debug.WriteLine($"Sending datagram, size = {bufferSize}");

			return udpClient.Send(buffer, (int) bufferSize);
		}

		int NativeReceiveFunction(IntPtr instance, byte[] buffer, uint bufferSize)
		{
			IPEndPoint remoteAddress = default(IPEndPoint);

			var datagram = udpClient.Receive(ref remoteAddress);

			var length = datagram.Length > (int)bufferSize ? (int)bufferSize : datagram.Length;

			Debug.WriteLine($"Received Datagram, size = {length}");
			
			for (int i = 0; i < length; i++)
			{
				buffer[i] = datagram[i];
			}

			//Array.Copy(datagram, 0, buffer, 0, length);

			return length;
		}

		void NativeSetTimerFunction(IntPtr instance, uint intermediateDelay, uint finalDelay)
		{
			Debug.WriteLine($"SetTimer: {intermediateDelay}, {finalDelay}");

			if (finalDelay == 0)
			{
				intermediateTimer = null;
				finalTimer = null;
				return;
			}

			intermediateTimer = new Timer(intermediateDelay);
			finalTimer = new Timer(finalDelay);
		}

		int NativeGetTimerFunction(IntPtr instance)
		{
			if (finalTimer == null)
			{
				Debug.WriteLine($"GetTimer returning -1");
				return -1;
			}

			int numberElapsed = (intermediateTimer.IsElapsed ? 1 : 0) + (finalTimer.IsElapsed ? 1 : 0);

			Debug.WriteLine($"GetTimer returning {numberElapsed}");

			return numberElapsed;
		}

		~DtlsSocket()
		{
			NativeMethods.Dtls_Free(instance);
		}
	}
}
