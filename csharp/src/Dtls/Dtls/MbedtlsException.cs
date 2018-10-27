using System;

namespace Dtls
{
	public class MbedtlsException : Exception
	{
		public int Result { get; set; }

		internal MbedtlsException(int result) : base(NativeMethods.ErrorToString(result))
		{
			Result = result;
		}
	}
}
