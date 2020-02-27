package config

import (
	"math"
	"sort"
)

func removeDuplicateGroups(groups []*Group) []*Group {
	dupCheck := make(map[*Group]bool)
	newGroup := make([]*Group, 0, len(groups))
	for _, gptr := range groups {
		if _, ok := dupCheck[gptr]; ok {
			continue
		}
		newGroup = append(newGroup, gptr)
		dupCheck[gptr] = true
	}
	return newGroup
}

func Assignments(groups map[string]*Group) [][]*Group {
	n := len(groups)
	l := int(math.Ceil(math.Sqrt(2*float64(n)-.25) - .5))

	glist := make([]string, n)
	i := 0
	for gid := range groups {
		glist[i] = gid
		i++
	}
	sort.Strings(glist)

	assigns := make([][]*Group, l+1)
	assigns[0] = make([]*Group, l)
	for i := range assigns[0] {
		assigns[0][i] = groups[glist[i]]
	}
	last := l - 1

	for i := 1; i < l+1; i++ {
		a := 0
		assign := make([]*Group, l)
		for j := 0; j < i; j++ {
			if len(assigns[j]) > i-1 {
				assign[a] = assigns[j][i-1]
				a++
			}
		}
		idx := 0
		for j := a; j < l; j++ {
			if last+1 >= n {
				assign[a] = assign[idx]
				a++
				idx++
			} else {
				assign[a] = groups[glist[last+1]]
				a++
				last++
			}
		}
		assigns[i] = assign
	}

	for k, v := range assigns {
		assigns[k] = removeDuplicateGroups(v)
	}

	return assigns
}
