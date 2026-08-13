package opencode

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	coreVersionPattern  = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$`)
	exactVersionPattern = regexp.MustCompile(`(?:^|[ \t(:])(v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)(?:$|[ \t),])`)
)

func compareVersion(left, right string) (int, error) {
	leftParts, err := parseCoreVersion(left)
	if err != nil {
		return 0, err
	}
	rightParts, err := parseCoreVersion(right)
	if err != nil {
		return 0, err
	}
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1, nil
		}
		if leftParts[index] > rightParts[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func parseCoreVersion(value string) ([3]uint64, error) {
	match := coreVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 4 {
		return [3]uint64{}, fmt.Errorf("invalid core version %q", value)
	}
	var result [3]uint64
	for index := range result {
		part := match[index+1]
		if part == "" {
			continue
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return [3]uint64{}, fmt.Errorf("invalid core version %q", value)
		}
		result[index] = parsed
	}
	return result, nil
}

func firstExactVersionToken(output string) string {
	match := exactVersionPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimPrefix(match[1], "v")
}
