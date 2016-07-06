package commands

import (
	"fmt"

	"github.com/docopt/docopt-go"
)

const VERSION = "0.1.0-go"

func Version(args []string) error {
	doc := `Usage:
calicoctl version

Description:
  Display the version of calicoctl`

	_, _ = docopt.Parse(doc, args, true, "calicoctl", false, false)

	fmt.Println("Version:     ", VERSION)
	fmt.Println("Build date:  ", BUILD_DATE)
	fmt.Println("Git tag ref: ", GIT_DESCRIPTION)
	fmt.Println("Git commit:  ", GIT_REVISION)
	return nil
}
