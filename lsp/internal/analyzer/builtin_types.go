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
	"slice":    {ret: tArray},
	"concat":   {ret: tArray},
	"flatten":  {ret: tArray},
	"has_key":  {ret: tBool},
	"range":    {ret: arrayOf(tInt)},

	// math (kind-preserving ops — abs/sum/min/max/clamp/mod — are handled
	// arg-aware in infer.go, not here, since their int-vs-float result depends
	// on the argument types).
	"pow":        {ret: tFloat},
	"sqrt":       {ret: tFloat},
	"floor":      {ret: tInt},
	"ceil":       {ret: tInt},
	"round":      {ret: tInt},
	"avg":        {ret: tFloat},
	"rand":       {ret: tFloat},
	"rand_int":   {ret: tInt},
	"rand_bytes": {ret: tString},
	"math_pi":    {ret: tFloat},
	"math_e":     {ret: tFloat},

	// conversion
	"to_int":      {ret: tInt, fallible: true},
	"to_float":    {ret: tFloat, fallible: true},
	"to_string":   {ret: tString},
	"to_bool":     {ret: tBool, fallible: true},
	"parse_int":   {ret: tInt, fallible: true},
	"parse_float": {ret: tFloat, fallible: true},
	"type_of":     {ret: tString},
	"is_null":     {ret: tBool},
	"to_base":     {ret: tString},
	"from_base":   {ret: tInt, fallible: true},

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

	// time (epoch seconds are integers; time_now is a hash)
	"time_now":    {ret: tHash},
	"time_unix":   {ret: tInt},
	"time_format": {ret: tString},
	"time_parse":  {ret: tInt, fallible: true},
	"time_diff":   {ret: tInt},
	"time_add":    {ret: tInt},

	// identifiers
	"uuid_v7":    {ret: tString},
	"random_hex": {ret: tString},
	"nanoid":     {ret: tString},

	// encoding (bytes ride on strings in Mutant; decoders return (value, err))
	"hex_encode":       {ret: tString},
	"hex_decode":       {ret: tString, fallible: true},
	"base64_encode":    {ret: tString},
	"base64_decode":    {ret: tString, fallible: true},
	"base64url_encode": {ret: tString},
	"base64url_decode": {ret: tString, fallible: true},
	"base32_encode":    {ret: tString},
	"base32_decode":    {ret: tString, fallible: true},
	"url_encode":       {ret: tString},
	"url_decode":       {ret: tString, fallible: true},
	"gzip":             {ret: tString},
	"gunzip":           {ret: tString, fallible: true},
	"zlib_compress":    {ret: tString},
	"zlib_decompress":  {ret: tString, fallible: true},
}

func builtinReturnType(name string) (builtinSig, bool) {
	sig, ok := builtinReturnTypes[name]
	return sig, ok
}
