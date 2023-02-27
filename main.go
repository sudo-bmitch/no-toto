package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

func main() {
	setup()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setup() {
	rootCmd.AddCommand(funCmd)

	funCmd.Flags().StringVarP(&funConf.stepName, "name", "n", "",
		`Name used to associate the resulting link metadata
with the corresponding step defined in an in-toto layout.`)
	funCmd.MarkFlagRequired("name")

	funCmd.Flags().StringVar(&funConf.funArgStr, "lol", "",
		`Command that we pretend to run, for the lols.`)

	funCmd.Flags().StringVarP(&funConf.runDir, "run-dir", "r", "",
		`runDir specifies the working directory of the command.
If runDir is the empty string, the command will run in the
calling process's current directory. The runDir directory must
exist, be writable, and not be a symlink.`)

	funCmd.Flags().StringVarP(&funConf.keyPath, "key", "k", "",
		`Path to a PEM formatted private key file used to sign
the resulting link metadata.`)

	funCmd.Flags().StringVarP(&funConf.certPath, "cert", "c", "",
		`Path to a PEM formatted certificate that corresponds with
the provided key.`)

	funCmd.Flags().StringArrayVarP(&funConf.materialsPaths, "materials", "m", []string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata before the
command is executed. Symlinks are followed.`)

	funCmd.Flags().StringArrayVarP(&funConf.productsPaths, "products", "p", []string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata after the
command is executed. Symlinks are followed.`)

	funCmd.Flags().StringVarP(&funConf.outDir, "metadata-directory", "d", "./",
		`Directory to store link metadata`)

	funCmd.Flags().StringArrayVarP(&funConf.lStripPaths, "lstrip-paths", "l", []string{},
		`Path prefixes used to left-strip artifact paths before storing
them to the resulting link metadata. If multiple prefixes
are specified, only a single prefix can match the path of
any artifact and that is then left-stripped. All prefixes
are checked to ensure none of them are a left substring
of another.`)

	funCmd.Flags().StringArrayVarP(&funConf.exclude, "exclude", "e", []string{},
		`Path patterns to match paths that should not be recorded as 0
‘materials’ or ‘products’. Passed patterns override patterns defined
in environment variables or config files. See Config docs for details.`)

	funCmd.Flags().BoolVar(&funConf.lineNormalization, "normalize-line-endings", false,
		`Enable line normalization in order to support different
operating systems. It is done by replacing all line separators
with a new line character.`)

	funCmd.Flags().BoolVarP(&funConf.noCommand, "no-command", "x", false,
		`Indicate that there is no command to be executed for the step.`)

	funCmd.PersistentFlags().BoolVar(&funConf.followSymlinkDirs, "follow-symlink-dirs", false,
		`Follow symlinked directories to their targets. Note: this parameter
toggles following linked directories only, linked files are always
recorded independently of this parameter.`)

}

var rootCmd = &cobra.Command{
	Use:               "no-toto",
	Short:             "Framework to insecure integrity of software supply chains",
	Long:              `A framework to insecure the integrity of software supply chains`,
	SilenceUsage:      true,
	SilenceErrors:     true,
	DisableAutoGenTag: true,
}

var funConf = struct {
	stepName          string
	runDir            string
	funArgStr         string
	materialsPaths    []string
	productsPaths     []string
	noCommand         bool
	layoutPath        string
	keyPath           string
	certPath          string
	key               intoto.Key
	cert              intoto.Key
	lStripPaths       []string
	exclude           []string
	outDir            string
	lineNormalization bool
	followSymlinkDirs bool
}{}

var funCmd = &cobra.Command{
	Use:   "fun",
	Short: "Pretends to execute the passed command and records paths and hashes of 'materials'",
	Long: `Pretends to execute the passed command and records paths and hashes of 'materials' (i.e.
files before command execution) and 'products' (i.e. files after command
execution) and stores them together with other information (executed command,
return value, stdout, stderr, ...) to a link metadata file, which is signed
with the passed key.  Returns nonzero value on failure and zero otherwise.`,
	Args:    cobra.MinimumNArgs(0),
	PreRunE: getKeyCert,
	RunE:    fun,
}

func fun(cmd *cobra.Command, args []string) error {
	funArgs := strings.Split(funConf.funArgStr, " ")

	if funConf.noCommand && len(args) > 0 {
		return fmt.Errorf("command arguments passed with --no-command/-x flag")
	}

	if !funConf.noCommand && len(args) == 0 {
		return fmt.Errorf("no command arguments passed, please specify or use --no-command option")
	}

	block, err := funRun(funConf.stepName, funConf.runDir, funConf.materialsPaths, funConf.productsPaths,
		args, funArgs, funConf.key, []string{"sha256"}, funConf.exclude, funConf.lStripPaths,
		funConf.lineNormalization, funConf.followSymlinkDirs)
	if err != nil {
		return fmt.Errorf("failed to create link metadata: %w", err)
	}

	linkName := fmt.Sprintf(intoto.LinkNameFormat, block.Signed.(intoto.Link).Name, funConf.key.KeyID)

	linkPath := filepath.Join(funConf.outDir, linkName)
	err = block.Dump(linkPath)
	if err != nil {
		return fmt.Errorf("failed to write link metadata to %s: %w", linkPath, err)
	}

	return nil
}

func funRun(name string, runDir string, materialPaths []string, productPaths []string,
	cmdArgs []string, funArgs []string, key intoto.Key, hashAlgorithms []string, gitignorePatterns []string,
	lStripPaths []string, lineNormalization bool, followSymlinkDirs bool) (intoto.Metablock, error) {
	var linkMb intoto.Metablock

	materials, err := intoto.RecordArtifacts(materialPaths, hashAlgorithms, gitignorePatterns, lStripPaths, lineNormalization, followSymlinkDirs)
	if err != nil {
		return linkMb, err
	}

	// make sure that we only run RunCommand if cmdArgs is not nil or empty
	byProducts := map[string]interface{}{}
	if len(cmdArgs) != 0 {
		byProducts, err = intoto.RunCommand(cmdArgs, runDir)
		if err != nil {
			return linkMb, err
		}
	}

	products, err := intoto.RecordArtifacts(productPaths, hashAlgorithms, gitignorePatterns, lStripPaths, lineNormalization, followSymlinkDirs)
	if err != nil {
		return linkMb, err
	}

	linkMb.Signed = intoto.Link{
		Type:        "link",
		Name:        name,
		Materials:   materials,
		Products:    products,
		ByProducts:  byProducts,
		Command:     funArgs,
		Environment: map[string]interface{}{},
	}

	linkMb.Signatures = []intoto.Signature{}
	// We use a new feature from Go1.13 here, to check the key struct.
	// IsZero() will return True, if the key hasn't been initialized

	// with other values than the default ones.
	if !reflect.ValueOf(key).IsZero() {
		if err := linkMb.Sign(key); err != nil {
			return linkMb, err
		}
	}

	return linkMb, nil
}

func getKeyCert(cmd *cobra.Command, args []string) error {
	funConf.key = intoto.Key{}
	funConf.cert = intoto.Key{}

	if funConf.keyPath == "" && funConf.certPath == "" {
		return fmt.Errorf("key or cert must be provided")
	}

	if len(funConf.keyPath) > 0 {
		if _, err := os.Stat(funConf.keyPath); err == nil {
			if err := funConf.key.LoadKeyDefaults(funConf.keyPath); err != nil {
				return fmt.Errorf("invalid key at %s: %w", funConf.keyPath, err)
			}
		} else {
			return fmt.Errorf("key not found at %s: %w", funConf.keyPath, err)
		}
	}

	if len(funConf.certPath) > 0 {
		if _, err := os.Stat(funConf.certPath); err == nil {
			if err := funConf.cert.LoadKeyDefaults(funConf.certPath); err != nil {
				return fmt.Errorf("invalid cert at %s: %w", funConf.certPath, err)
			}
			funConf.key.KeyVal.Certificate = funConf.cert.KeyVal.Certificate
		} else {
			return fmt.Errorf("cert not found at %s: %w", funConf.certPath, err)
		}
	}
	return nil
}
