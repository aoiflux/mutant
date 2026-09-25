package graphstore

import "slices"

// PropKeyLister is the one method of *graphene.Graph that UnindexedKeys needs,
// named so a caller can hand it a graph of either backend.
type PropKeyLister interface {
	NodePropKeys() ([]string, bool)
}

// UnindexedKeys names the keys the node property index holds nothing under, in
// the order they were asked about and each once.
//
// A property filter on such a key matches nothing and returns no error,
// whatever the stored property blobs hold, and graphene's planner costs it at
// zero and picks it to drive the query -- so ANDed onto a correct filter it
// turns a right answer into an empty one. Every reader that takes a key from
// somewhere it did not write asks this first.
//
// known is false when the store cannot list its keys, and the list is then
// empty because nothing could be said. graphene's list is an upper bound on the
// disk backend -- a key whose every entry was since retracted may still be
// named -- so a key missing from it matches nothing for certain, which is the
// direction this needs: it can miss a key that matches nothing, and it never
// names one that matches something.
//
// graphene returns the list sorted -- "so BinarySearch is the intended shape"
// -- and it is searched rather than copied into a set, because a query asks
// this once per call.
func UnindexedKeys(g PropKeyLister, keys []string) (unindexed []string, known bool) {
	indexed, ok := g.NodePropKeys()
	if !ok {
		return nil, false
	}
	for i, key := range keys {
		if slices.Contains(keys[:i], key) {
			continue
		}
		if _, found := slices.BinarySearch(indexed, key); !found {
			unindexed = append(unindexed, key)
		}
	}
	return unindexed, true
}
