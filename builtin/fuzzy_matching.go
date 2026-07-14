package builtin

import (
	"strings"
	"unicode/utf8"

	"mutant/object"
)

func TextLevenshtein(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}

	left, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to `text_levenshtein` must be STRING, got %s", args[0].Type())
	}

	right, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to `text_levenshtein` must be STRING, got %s", args[1].Type())
	}

	distance := levenshteinDistance(left.Value, right.Value)
	return intObj(int64(distance))
}

func TextSimilarity(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}

	left, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to `text_similarity` must be STRING, got %s", args[0].Type())
	}

	right, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to `text_similarity` must be STRING, got %s", args[1].Type())
	}

	maxLen := maxRuneLen(left.Value, right.Value)
	if maxLen == 0 {
		return &object.Float{Value: 1.0}
	}

	distance := levenshteinDistance(left.Value, right.Value)
	similarity := 1.0 - float64(distance)/float64(maxLen)
	if similarity < 0 {
		similarity = 0
	}

	return &object.Float{Value: similarity}
}

func TextFuzzyFind(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=2 or 3", len(args))
	}

	query, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to `text_fuzzy_find` must be STRING, got %s", args[0].Type())
	}

	candidatesObj, ok := args[1].(*object.Array)
	if !ok {
		return newError("argument 2 to `text_fuzzy_find` must be ARRAY, got %s", args[1].Type())
	}

	maxDistance := int64(2)
	if len(args) == 3 {
		distanceObj, ok := args[2].(*object.Integer)
		if !ok {
			return newError("argument 3 to `text_fuzzy_find` must be INTEGER, got %s", args[2].Type())
		}
		maxDistance = distanceObj.Value
	}

	bestMatch := ""
	bestIndex := int64(-1)
	bestDistance := int64(1<<62 - 1)
	queryLower := strings.ToLower(query.Value)

	for idx, candidateObj := range candidatesObj.Elements {
		candidate, ok := candidateObj.(*object.String)
		if !ok {
			return newError("argument 2 to `text_fuzzy_find` must contain only STRING values. element %d got %s", idx, candidateObj.Type())
		}

		distance := int64(levenshteinDistance(queryLower, strings.ToLower(candidate.Value)))
		if distance < bestDistance {
			bestDistance = distance
			bestMatch = candidate.Value
			bestIndex = int64(idx)
		}
	}

	if bestIndex == -1 {
		return makeHashObject(map[string]object.Object{
			"found":    boolObj(false),
			"match":    stringObj(""),
			"index":    intObj(-1),
			"distance": intObj(-1),
		})
	}

	if bestDistance > maxDistance {
		return makeHashObject(map[string]object.Object{
			"found":    boolObj(false),
			"match":    stringObj(""),
			"index":    intObj(-1),
			"distance": intObj(bestDistance),
		})
	}

	return makeHashObject(map[string]object.Object{
		"found":    boolObj(true),
		"match":    stringObj(bestMatch),
		"index":    intObj(bestIndex),
		"distance": intObj(bestDistance),
	})
}

func TextJaroWinkler(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}

	left, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to `text_jaro_winkler` must be STRING, got %s", args[0].Type())
	}

	right, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to `text_jaro_winkler` must be STRING, got %s", args[1].Type())
	}

	score := jaroWinkler(left.Value, right.Value)
	return &object.Float{Value: score}
}

func levenshteinDistance(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}

	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := 0; j <= len(br); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}

			deletion := prev[j] + 1
			insertion := cur[j-1] + 1
			substitution := prev[j-1] + cost

			cur[j] = deletion
			if insertion < cur[j] {
				cur[j] = insertion
			}
			if substitution < cur[j] {
				cur[j] = substitution
			}
		}
		prev, cur = cur, prev
	}

	return prev[len(br)]
}

func maxRuneLen(a, b string) int {
	aLen := utf8.RuneCountInString(a)
	bLen := utf8.RuneCountInString(b)
	if aLen > bLen {
		return aLen
	}
	return bLen
}

func jaroWinkler(a, b string) float64 {
	if a == b {
		if a == "" {
			return 1
		}
		return 1
	}

	ar := []rune(a)
	br := []rune(b)
	if len(ar) == 0 || len(br) == 0 {
		return 0
	}

	matchDistance := maxInt(len(ar), len(br))/2 - 1
	if matchDistance < 0 {
		matchDistance = 0
	}

	aMatches := make([]bool, len(ar))
	bMatches := make([]bool, len(br))

	matches := 0
	for i := 0; i < len(ar); i++ {
		start := i - matchDistance
		if start < 0 {
			start = 0
		}
		end := i + matchDistance + 1
		if end > len(br) {
			end = len(br)
		}

		for j := start; j < end; j++ {
			if bMatches[j] {
				continue
			}
			if ar[i] != br[j] {
				continue
			}
			aMatches[i] = true
			bMatches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0
	}

	transpositions := 0
	j := 0
	for i := 0; i < len(ar); i++ {
		if !aMatches[i] {
			continue
		}
		for ; j < len(br); j++ {
			if bMatches[j] {
				break
			}
		}
		if j < len(br) && ar[i] != br[j] {
			transpositions++
		}
		j++
	}

	m := float64(matches)
	jaro := ((m / float64(len(ar))) + (m / float64(len(br))) + ((m - float64(transpositions)/2) / m)) / 3.0

	prefixLen := 0
	for i := 0; i < minInt(4, minInt(len(ar), len(br))); i++ {
		if ar[i] != br[i] {
			break
		}
		prefixLen++
	}

	return jaro + float64(prefixLen)*0.1*(1.0-jaro)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
