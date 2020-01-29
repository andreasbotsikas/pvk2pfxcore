using CommandLine;
using System;
using System.Collections.Generic;
using System.Text;

namespace pvk2pfxcore
{
    public class Options
    {

        [Option("pvk", Required = true, HelpText = "input PVK file name.")]
        public string Pvk { get; set; }

        [Option("spc", Required = true, HelpText = "input SPC/CER file name.")]
        public string Spc { get; set; }

        [Option("pfx", Required = true, HelpText = "output PFX file name.")]
        public string Pfx { get; set; }

        [Option("pi", Required = false, HelpText = "PVK password.", Default = null)]
        public string PvkPassword { get; set; }

        [Option("po", Required = false, HelpText = "PFX password; same as -pi if not given.", Default = null)]
        public string PfxPassword { get; set; }

        [Option('f', "force", Required = false, HelpText = "force overwrite existing PFX file.", Default = false)]
        public bool OverwritePfx { get; set; }
    }
}
