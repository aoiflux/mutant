package analyzer

// Curated, hand-authored return types for a subset of builtins. Mutant's builtin
// metadata carries no machine-readable types (only prose), so this table is the
// seed for inferring the result type of a builtin call. It is intentionally a
// high-confidence subset: any builtin absent here infers to Any, which is always
// safe (the editor simply shows no type). `fallible` marks the `(value, err)`
// idiom so multi-bind `let v, e = f()` can type v as the value and e as error.
//
// Grow this table over time; never add an entry you are not confident about, to
// avoid showing misleading types.

type builtinSig struct {
	ret      Type
	fallible bool
}

var (
	tInt    = Type{Kind: TypeInt}
	tFloat  = Type{Kind: TypeFloat}
	tBool   = Type{Kind: TypeBool}
	tString = Type{Kind: TypeString}
	tHash   = Type{Kind: TypeHash}
	tArray  = Type{Kind: TypeArray}
)

var builtinReturnTypes = map[string]builtinSig{
	// core / collections
	"len":      {ret: tInt},
	"contains": {ret: tBool},
	"index_of": {ret: tInt},
	"keys":     {ret: tArray},
	"values":   {ret: tArray},
	"entries":  {ret: tArray},
	"push":     {ret: tArray},
	"rest":     {ret: tArray},
	"pop":      {ret: tArray},
	"reverse":  {ret: tArray},
	"unique":   {ret: tArray},
	"sort":     {ret: tArray},
	"sort_by":  {ret: tArray},
	"zip":      {ret: tArray},
	"map":      {ret: tArray},
	"filter":   {ret: tArray},
	"range":    {ret: arrayOf(tInt)},

	// conversion
	"to_int":    {ret: tInt, fallible: true},
	"to_float":  {ret: tFloat, fallible: true},
	"to_string": {ret: tString},
	"type_of":   {ret: tString},

	// strings
	"str_upper":       {ret: tString},
	"str_lower":       {ret: tString},
	"str_title":       {ret: tString},
	"str_trim":        {ret: tString},
	"str_trim_left":   {ret: tString},
	"str_trim_right":  {ret: tString},
	"str_trim_prefix": {ret: tString},
	"str_trim_suffix": {ret: tString},
	"str_replace":     {ret: tString},
	"str_repeat":      {ret: tString},
	"str_reverse":     {ret: tString},
	"str_substr":      {ret: tString},
	"str_char_at":     {ret: tString},
	"str_pad_left":    {ret: tString},
	"str_pad_right":   {ret: tString},
	"str_format":      {ret: tString},
	"str_join":        {ret: tString},
	"str_split":       {ret: arrayOf(tString)},
	"str_starts_with": {ret: tBool},
	"str_ends_with":   {ret: tBool},

	// text
	"text_contains":     {ret: tBool},
	"text_replace":      {ret: tString},
	"text_split":        {ret: arrayOf(tString)},
	"text_count":        {ret: tInt},
	"text_index":        {ret: tInt},
	"text_levenshtein":  {ret: tInt},
	"text_similarity":   {ret: tFloat},
	"text_jaro_winkler": {ret: tFloat},

	// structured data
	"json_stringify": {ret: tString, fallible: true},

	// filesystem
	"fs_read":   {ret: tString, fallible: true},
	"fs_write":  {ret: tInt, fallible: true},
	"fs_exists": {ret: tBool},
	"fs_list":   {ret: tArray, fallible: true},
	"fs_stat":   {ret: tHash, fallible: true},

	// time
	"time_now": {ret: tHash},

	// encoding (bytes ride on strings in Mutant)
	"hex_encode":    {ret: tString},
	"hex_decode":    {ret: tString, fallible: true},
	"base64_encode": {ret: tString},
	"base64_decode": {ret: tString, fallible: true},
}

func builtinReturnType(name string) (builtinSig, bool) {
	sig, ok := builtinReturnTypes[name]
	return sig, ok
}
