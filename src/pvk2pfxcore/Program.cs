using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using CommandLine;
using System.IO;
using System.Text;
using Org.Mentalis.Security.Certificates;

namespace pvk2pfxcore
{
    /// <summary>
    /// A .net core alternative to pvk2pfx.
    /// Based on Mentalis.org Security Library
    /// http://www.mentalis.org/soft/projects/seclib/
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(opts => RunApplication(opts));
        }

        private static void RunApplication(Options opts)
        {
            // Fix relative paths
            if (!Path.IsPathRooted(opts.Spc))
            {
                opts.Spc = Path.Combine(Environment.CurrentDirectory, opts.Spc);
            }
            if (!Path.IsPathRooted(opts.Pvk))
            {
                opts.Pvk = Path.Combine(Environment.CurrentDirectory, opts.Pvk);
            }
            if (!Path.IsPathRooted(opts.Pfx))
            {
                opts.Pfx = Path.Combine(Environment.CurrentDirectory, opts.Pfx);
            }

            // Check that cer file exists
            if (!File.Exists(opts.Spc))
            {
                // Error if not allowed to overwrite
                Console.Error.WriteLine($"Public key file {opts.Spc} doesn't exist.");
                return;
            }
            // Check that pvk file exists
            if (!File.Exists(opts.Pvk))
            {
                // Error if not allowed to overwrite
                Console.Error.WriteLine($"Private key file {opts.Pvk} doesn't exist.");
                return;
            }

            // If password is empty, pass null
            if (opts.PvkPassword != null && opts.PvkPassword.Length == 0)
            {
                opts.PvkPassword = null;
            }
            if (opts.PfxPassword != null && opts.PfxPassword.Length == 0)
            {
                // Use PVK pass instead of null
                opts.PfxPassword = opts.PvkPassword;
            }

            // Check if pfx exists
            if (File.Exists(opts.Pfx))
            {
                if (!opts.OverwritePfx)
                {
                    // Error if not allowed to overwrite
                    Console.Error.WriteLine($"Pfx file {opts.Pfx} exists. Specify -f to overwrite it.");
                    return;
                }
                else
                {
                    // Delete file if it exists
                    File.Delete(opts.Pfx);
                }
            }

            // create a Certificate instance from the certificate file
            Certificate cert = Certificate.CreateFromCerFile(opts.Spc);
            // associate the certificate with the specified private key
            cert.AssociateWithPrivateKey(opts.Pvk, opts.PvkPassword, true);

            // export the PKCS#12 file
            cert.ToPfxFile(opts.Pfx, opts.PfxPassword, true, false);
        }

		
	}
}
