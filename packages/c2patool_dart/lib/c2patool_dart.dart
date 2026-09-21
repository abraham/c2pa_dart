/// Programmatic entry points for the `c2patool` command-line application.
library;

export 'src/cli.dart'
    show C2paCli, CliExitCode, CliResult, c2patoolVersion, runC2paCli;
export 'src/signers.dart'
    show LocalKeyC2paSigner, SubprocessC2paSigner, SubprocessSignerException;
