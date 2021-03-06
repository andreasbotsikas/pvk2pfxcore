using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Org.Mentalis.Security.Cryptography;

namespace Org.Mentalis.Security.Testing {
	public class MD2CryptoServiceProviderBox : HashBox {
		public MD2CryptoServiceProviderBox(Stream fs) : base(fs) {}
		public override string Name {
			get {
				return "MD2CryptoServiceProvider";
			}
		}
		protected override HashAlgorithm GetHashInstance() {
			return new MD2CryptoServiceProvider();
		}
		protected override byte[][][] GetTestVectors() {
			return new byte[][][] {hash1, hash2, hash3, hash4, hash5, hash6, hash7};
		}
		protected override bool IsKeyed() {
			return false;
		}
		static byte[][] hash1 = new byte[][]{Encoding.ASCII.GetBytes(""), new byte[]{0x83, 0x50, 0xe5, 0xa3, 0xe2, 0x4c, 0x15, 0x3d, 0xf2, 0x27, 0x5c, 0x9f, 0x80, 0x69, 0x27, 0x73}};
		static byte[][] hash2 = new byte[][]{Encoding.ASCII.GetBytes("a"), new byte[]{0x32, 0xec, 0x01, 0xec, 0x4a, 0x6d, 0xac, 0x72, 0xc0, 0xab, 0x96, 0xfb, 0x34, 0xc0, 0xb5, 0xd1}};
		static byte[][] hash3 = new byte[][]{Encoding.ASCII.GetBytes("abc"), new byte[]{0xda, 0x85, 0x3b, 0x0d, 0x3f, 0x88, 0xd9, 0x9b, 0x30, 0x28, 0x3a, 0x69, 0xe6, 0xde, 0xd6, 0xbb}};
		static byte[][] hash4 = new byte[][]{Encoding.ASCII.GetBytes("message digest"), new byte[]{0xab, 0x4f, 0x49, 0x6b, 0xfb, 0x2a, 0x53, 0x0b, 0x21, 0x9f, 0xf3, 0x30, 0x31, 0xfe, 0x06, 0xb0}};
		static byte[][] hash5 = new byte[][]{Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz"), new byte[]{0x4e, 0x8d, 0xdf, 0xf3, 0x65, 0x02, 0x92, 0xab, 0x5a, 0x41, 0x08, 0xc3, 0xaa, 0x47, 0x94, 0x0b}};
		static byte[][] hash6 = new byte[][]{Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), new byte[]{0xda, 0x33, 0xde, 0xf2, 0xa4, 0x2d, 0xf1, 0x39, 0x75, 0x35, 0x28, 0x46, 0xc3, 0x03, 0x38, 0xcd}};
		static byte[][] hash7 = new byte[][]{Encoding.ASCII.GetBytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), new byte[]{0xd5, 0x97, 0x6f, 0x79, 0xd8, 0x3d, 0x3a, 0x0d, 0xc9, 0x80, 0x6c, 0x3c, 0x66, 0xf3, 0xef, 0xd8}};
	}
}
