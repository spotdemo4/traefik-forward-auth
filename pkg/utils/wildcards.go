package utils

func ReplaceWildcards(template, replacement string) (result string) {
	for i := range template {
		if len(replacement) == 0 {
			break
		}

		ri := template[len(template)-1-i]

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
		} else {
			result = string(ri) + result

			replacement = replacement[:len(replacement)-1] // pop
		}
	}

	return result
}
