using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Dtls
{
	static class NativeMethods
	{
		internal struct ContextFunctions
		{
			internal delegate int SendFunctionDelegate(IntPtr instance, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] buffer, uint bufferSize);
			internal delegate int ReceiveFunctionDelegate(IntPtr instance, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), Out] byte[] buffer, uint bufferSize);
			internal delegate int ReceiveWithTimeoutFunctionDelegate(IntPtr instance, byte[] buffer, uint bufferSize, uint timeout);
			internal delegate void SetTimerFunctionDelegate(IntPtr instance, uint intermediateDelay, uint finalDelay);
			internal delegate int GetTimerFunctionDelegate(IntPtr instance);

			internal SendFunctionDelegate SendFunction { get; set; }
			internal ReceiveFunctionDelegate ReceiveFunction { get; set; }
			internal ReceiveWithTimeoutFunctionDelegate ReceiveWithTimeoutFunction { get; set; }
			internal SetTimerFunctionDelegate SetTimerFunction { get; set; }
			internal GetTimerFunctionDelegate GetTimerFunction { get; set; }
		}

		delegate int GetRandomFunctionDelegate(IntPtr argument, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=2), Out] byte[] buffer, uint amount);
		delegate void PrintLineFunctionDelegate(string message);

		[DllImport("libdtls")]
		static extern void Dtls_Initialize(GetRandomFunctionDelegate getRandomFunction, PrintLineFunctionDelegate printLineFunction);

		[DllImport("libdtls")]
		internal static extern IntPtr Dtls_Create(ContextFunctions contextFunctions);

		[DllImport("libdtls")]
		internal static extern void Dtls_Free(IntPtr instance);

		[DllImport("libdtls")]
		internal static extern int Dtls_Handshake(IntPtr instance);

		[DllImport("libdtls")]
		internal static extern int Dtls_Write(IntPtr instance, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] buffer, uint bufferSize);

		[DllImport("libdtls")]
		internal static extern int Dtls_Read(IntPtr instance, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] buffer, uint bufferSize);

		[DllImport("libdtls")]
		internal static extern void Dtls_GetErrorMessage(int errorCode, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), Out] char[] destination, int destinationSize);

		[DllImport("libdtls")]
		internal static extern int Dtls_SetPresharedKey(IntPtr instance, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] psk, int pskLength, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] pskIdentity, int pskIdentityLength);

		static RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

		static NativeMethods()
		{
			Dtls_Initialize(new GetRandomFunctionDelegate(GetRandom), new PrintLineFunctionDelegate(PrintLine));
		}

		static void PrintLine(string message)
		{
			Console.Write(message);
		}

		public static string ErrorToString(int errorCode)
		{
			var message = new char[256];

			Dtls_GetErrorMessage(errorCode, message, message.Length);

			return new string(message);
		}

		private static int GetRandom(IntPtr argument, byte[] buffer, uint amount)
		{
			var length = (int)amount;

			randomNumberGenerator.GetBytes(buffer, 0, length);
						
			return 0;
		}

	}
}
