// span is used to divide an array into mostly equal size pieces
// inspired by David Lazar's span, with minor changes

package span

type Span struct {
	Start int
	End   int
}

func SpanWithSize(n, size int) []Span {
	quo := n / size
	mod := n % size
	if mod != 0 {
		quo += 1
	}

	spans := make([]Span, quo)
	for i := range spans {
		start := i * size
		offset := size
		if i == quo-1 && mod != 0 {
			offset = mod
		}
		end := start + offset
		spans[i] = Span{
			Start: start,
			End:   end,
		}
	}
	return spans
}

func NSpans(n, numSpans int) []Span {
	if n < numSpans {
		numSpans = n
	}

	size := n / numSpans
	mod := n % numSpans

	spans := make([]Span, numSpans)
	end := 0
	for i := 0; i < numSpans; i++ {
		start := end
		offset := size
		if i < mod {
			offset += 1
		}
		end = start + offset
		spans[i] = Span{
			Start: start,
			End:   end,
		}
	}
	return spans
}

func StreamSpan(n, streamSize, msgSize int) []Span {
	perSpan := streamSize / msgSize
	return SpanWithSize(n, perSpan)
}
