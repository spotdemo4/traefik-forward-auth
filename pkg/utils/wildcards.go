package utils

// For each character in template, replace * with the corresponding value in replacement
func ReplaceWildcards(template, replacement string) (result string) {
	for i := range template {
		ri := template[len(template)-1-i]

		if len(replacement) == 0 {
			result = string(ri) + result
			continue
		}

		if ri == '*' {
			count := 0
			for j := range replacement {
				ji := replacement[len(replacement)-1-j]

				if ji == '.' || ji == ':' {
					break
				} else {
					result = string(ji) + result

					count++
				}
			}

			replacement = replacement[:len(replacement)-count] // pop
			continue
		}

		result = string(ri) + result
		replacement = replacement[:len(replacement)-1] // pop
	}

	return result
}
