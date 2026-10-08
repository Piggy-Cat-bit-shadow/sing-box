package group

import (
	"context"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

type fanResult struct {
	member   *member
	response *mDNS.Msg
	err      error
}

// fan is the single fan-out primitive serving three callers: the rescue fan
// after a target failed, the fastest election, and every parallel query. Keeping
// one implementation is what makes the three modes share their anti-storm and
// accounting behaviour instead of drifting apart.
//
// The first valid answer wins the query. The remaining participants are then
// cancelled, because a query that has been answered must not leave a family of
// sockets running behind it; the collection goroutine still drains every result
// so the single-flight lock is released and no goroutine is left parked on the
// channel.
//
// election is the token this fan owns, or the zero token for a fan that is not
// an election. It is handed down to collectFan untouched, because the release
// has to prove ownership rather than merely assert that "an election" ended: by
// the time the collector runs, Reset may have invalidated this token and a new
// query may already own a fresh one.
//
// Participants run under a context derived from the request, not a detached one:
// a late answer is one arriving before the winner, not one arriving after the
// caller stopped caring.
func (t *Transport) fan(ctx context.Context, message *mDNS.Msg, participants []*member, gen int, election electionToken) (*mDNS.Msg, error) {
	fanCtx, cancelFan := context.WithCancel(ctx)
	// Cancels the probes that lost as soon as this function returns, whether it
	// returned a winner or an error.
	defer cancelFan()

	if t.logger != nil {
		tags := make([]string, 0, len(participants))
		for _, participant := range participants {
			tags = append(tags, participant.tag)
		}
		t.logger.DebugContext(ctx, "group[", t.Tag(), "]: fan to [", strings.Join(tags, " "), "]")
	}

	// Buffered so a participant can always post its result and exit; an
	// unbuffered channel would leak every loser as soon as the fan stopped
	// reading.
	results := make(chan fanResult, len(participants))
	for _, participant := range participants {
		go func(current *member) {
			// Each participant gets its own copy: transports may rewrite the
			// message they are given, and a shared one would let two members
			// answer different questions.
			response, err := current.transport.Exchange(fanCtx, message.Copy())
			results <- fanResult{member: current, response: response, err: err}
		}(participant)
	}

	winnerCh := make(chan fanResult, 1)
	go t.collectFan(fanCtx, len(participants), results, winnerCh, gen, election)

	select {
	case result := <-winnerCh:
		if result.response == nil && result.err == nil {
			// Degenerate guard: a fan must never resolve to (nil, nil), because
			// the client dereferences the response when the error is nil.
			if cause := fanCtx.Err(); cause != nil {
				return nil, cause
			}
			return nil, E.New("group[", t.Tag(), "]: fan yielded no result")
		}
		return result.response, result.err
	case <-fanCtx.Done():
		return nil, fanCtx.Err()
	}
}

// collectFan consumes every participant result, decides the winner, and owns
// the release of the election token.
//
// It always runs to the last result - cancelled participants return promptly
// once fan cancels them - and then releases `election` if this fan held it. That
// unconditional release on the way out is what keeps a caller's cancellation
// from leaking the single-flight lock: if the token were released only on the
// success path, one cancelled election would disable elections for the life of
// the transport.
//
// The release is token-scoped, not "clear the field": a slow collector can
// finish long after Reset has invalidated its token and a new generation has
// minted its own, and clearing the field then would delete the new election's
// ownership. releaseElection compares the whole token, so this collector can end
// its own election and nothing else.
func (t *Transport) collectFan(ctx context.Context, count int, results chan fanResult, winnerCh chan fanResult, gen int, election electionToken) {
	var (
		errs      []error
		delivered bool
	)
	for index := 0; index < count; index++ {
		result := <-results
		if isFailure(result.response, result.err) {
			// A failure observed after the fan was cancelled - because another
			// member won, or because the caller gave up - is an artifact of our
			// own cancellation, not evidence about the member. Recording it
			// would let one blackholed target mark every other member dirty and
			// collapse the group into survival mode.
			if ctx.Err() != nil {
				continue
			}
			t.noteError(result.member.tag, gen)
			t.logProbeFailure(ctx, result.member.tag, result.response, result.err)
			switch {
			case result.err != nil:
				errs = append(errs, E.Cause(result.err, result.member.tag))
			case result.response != nil:
				errs = append(errs, E.New(result.member.tag, ": SERVFAIL"))
			default:
				errs = append(errs, E.New(result.member.tag, ": no response"))
			}
			continue
		}
		// A success always erases the member's live errors, even a success that
		// arrived too late to answer: its answer is discarded, but the fact that
		// the member is reachable is still true and still useful.
		t.noteSuccess(result.member.tag, gen)
		if ctx.Err() != nil {
			continue
		}
		if !delivered {
			delivered = true
			if t.mode == ModeFastest {
				// Only the FIRST success of a fan earns a win. Minting one for
				// every participant would make the fan's own noise the signal
				// fastest ranks on.
				t.noteWin(result.member.tag, gen)
			}
			if t.mode != ModeParallel {
				// Parallel has no sticky target by design: it is the mode for
				// callers who want the fan itself, every time.
				if previous, changed := t.setCurrent(result.member.tag, gen); changed {
					t.logCurrentChange(ctx, previous, result.member.tag)
				}
			}
			t.logger.DebugContext(ctx, "group[", t.Tag(), "]: fan winner: ", result.member.tag)
			winnerCh <- result
		}
	}
	if election.held() {
		t.releaseElection(election)
	}
	if !delivered {
		failure := E.Errors(errs...)
		if failure == nil {
			// Every failure was abandoned by the guard above, so the fan died
			// with its request context. E.Errors of nothing is nil, and a fan
			// must never resolve to (nil, nil).
			if cause := ctx.Err(); cause != nil {
				failure = E.Cause(cause, "group[", t.Tag(), "]: all fan probes abandoned")
			} else {
				failure = E.New("group[", t.Tag(), "]: fan yielded no result")
			}
		}
		winnerCh <- fanResult{err: failure}
	}
}
