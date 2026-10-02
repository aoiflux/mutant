package builtin

// maxBuiltinResultBytes bounds a result whose size the script picks outright:
// a repeat count, a pad width, a number of random bytes. Uncapped, one
// mistyped count does not fail -- it leaves the process alive holding tens of
// gibibytes of the host's commit charge, printing nothing and surviving every
// ordinary kill, so the case it was opened for is never released.
//
// The sizes something else decides were bounded already: maxConnReadBytes and
// maxHTTPBodyBytes cap what a socket may hand us, a record read is capped by
// the length the record itself carries, and a filesystem read is clamped to
// the bytes the image could locate. A count typed into a script had no cap at
// all, and it is the one an examiner is most likely to get wrong.
//
// The value matches the 32 MiB the network readers already accept, because a
// result past that belongs in a file and not in a VM variable, which is
// re-encrypted on every store. Builtins that allocate runes divide it by
// utf8.UTFMax at the point of the check, and random_hex halves it because hex
// doubles; both are written where they are enforced, next to the thing they
// bound. Raising the cap is one edit here.
//
//mutant:limit bytes
const maxBuiltinResultBytes = 32 << 20
