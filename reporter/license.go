package reporter

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/models"
)

func WriteLicenseReport(results models.ScanResults) (err error) {
	packages := results[0].Packages

	filename := fmt.Sprintf("%s %s", results[0].ScannedAt, results[0].ServerName)

	pkgColumnLength := 0

	for _, pkg := range packages {
		if len(pkg.Name) > pkgColumnLength {
			pkgColumnLength = len(pkg.Name)
		}
	}

	indexDigits := len(strconv.Itoa(len(packages)))
	indexHeader := strings.Repeat("#", indexDigits+2)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "%s %-*s %s\n", indexHeader, pkgColumnLength, "PACKAGE", "LICENSE")

	for i, pkg := range packages.ToSortedSlice() {
		fmt.Fprintf(writer, "[%*d] %-*s %s\n", indexDigits, i+1,
			pkgColumnLength, pkg.Name,
			pkg.License)
	}

	writer.Flush()
	return nil
}
