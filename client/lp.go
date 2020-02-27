package client

import (
	"sort"

	"github.com/kwonalbert/xrd/config"
	"github.com/willauld/lpsimplex"
)

func findOptimalAssignment(groups map[string]*config.Group, assignments [][]*config.Group) ([]float64, float64) {
	l := len(assignments)
	n := len(groups)

	glist := make([]string, n)
	i := 0
	for gid := range groups {
		glist[i] = gid
		i++
	}
	sort.Strings(glist)

	maximize := make([]float64, l+1)
	for i := range maximize {
		if i == 0 {
			maximize[i] = 1
		} else {
			maximize[i] = 0
		}
	}

	xjs := make(map[int][]float64)
	for j := range glist {
		cur := groups[glist[j]]
		xj := make([]float64, len(assignments))
		for i := range assignments {
			xj[i] = 0
			for k := range assignments[i] {
				if assignments[i][k] == cur {
					xj[i] = 1
					break
				}
			}
		}
		xjs[j] = xj
	}

	Aub := make([][]float64, n)
	bub := make([]float64, n)

	// inequalities
	for j := 0; j < n; j++ {
		Aub[j] = make([]float64, l+1)
		Aub[j][0] = -1
		for i := 1; i < l+1; i++ {
			Aub[j][i] = xjs[j][i-1]
		}
		bub[j] = 0
	}

	// equality
	Aeq := [][]float64{make([]float64, l+1)}
	beq := []float64{1}

	Aeq[0][0] = 0
	for i := 1; i < l+1; i++ {
		Aeq[0][i] = 1
	}

	callback := lpsimplex.Callbackfunc(nil)
	result := lpsimplex.LPSimplex(maximize, Aub, bub, Aeq, beq, nil, callback, false, 4000, 1.0E-12, false)

	return result.X[1:], result.X[0]
}
