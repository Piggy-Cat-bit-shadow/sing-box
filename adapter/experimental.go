package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
)

type URLTestHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type V2RayServer interface {
	LifecycleService
	StatsService() ConnectionTracker
}

type CacheFile interface {
	LifecycleService

	CacheID() string

	StoreFakeIP() bool
	FakeIPStorage

	StoreRDRC() bool
	RDRCStore

	StoreDNS() bool
	DNSCacheStore

	SetDisableExpire(disableExpire bool)
	SetOptimisticTimeout(timeout time.Duration)
	Flush()

	LoadMode() string
	StoreMode(mode string) error
	LoadSelected(group string) string
	StoreSelected(group string, selected string) error
	LoadGroupExpand(group string) (isExpand bool, loaded bool)
	StoreGroupExpand(group string, expand bool) error
	LoadRuleSet(tag string) *SavedBinary
	SaveRuleSet(tag string, set *SavedBinary) error
}

type SavedBinary struct {
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
	URLHash     []byte
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(2))
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.Content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.Content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.LastEtag)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(s.LastEtag)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.URLHash)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.URLHash)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if contentLength > uint64(reader.Len()) {
		return E.New("invalid content length: ", contentLength)
	}
	s.Content = make([]byte, contentLength)
	_, err = io.ReadFull(reader, s.Content)
	if err != nil {
		return err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if etagLength > uint64(reader.Len()) {
		return E.New("invalid etag length: ", etagLength)
	}
	etagBytes := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etagBytes)
	if err != nil {
		return err
	}
	s.LastEtag = string(etagBytes)
	if version < 2 {
		return nil
	}
	urlHashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if urlHashLength > uint64(reader.Len()) {
		return E.New("invalid url hash length: ", urlHashLength)
	}
	s.URLHash = make([]byte, urlHashLength)
	_, err = io.ReadFull(reader, s.URLHash)
	if err != nil {
		return err
	}
	return nil
}

type OutboundGroup interface {
	Outbound
	All() []string
	Selected(network string) Outbound
	AttachConnection(closer io.Closer) (detach func())
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
	PerformUpdateCheck()
}

// FlowAwareOutboundGroup is an OPTIONAL capability of a group whose member choice
// depends on which flow is being routed rather than only on the network.
//
// # Why it is a separate interface
//
// Selected(network) is the contract every group already implements, and it is the right
// contract for the groups whose choice does not depend on the flow: a selector has one
// answer, a urltest has one best node. Load balancing does not: its answer is a property
// of the flow, so it needs the flow, which Selected does not receive.
//
// Adding the parameter to Selected would have changed every implementation and every
// caller at once. This capability is asked for where the flow exists and is absent
// everywhere else, so an existing group is untouched and only a balancing group pays
// for the fewer than one interface assertion per routing decision.
type FlowAwareOutboundGroup interface {
	OutboundGroup

	// SelectForFlow chooses the member that serves this flow.
	//
	// commit reports whether the caller will own the connection this choice is for. A
	// speculative caller - the pre-match preview, a leaf-labeling traversal, a
	// control-plane read - passes false, and the implementation MUST then answer
	// purely: no balanced cursor advance, no affinity write, no accounting side effect.
	// Its answer may be used to make a decision about a connection that is never
	// created, so consuming state for it would spend a slot on nothing and let two
	// callers for one flow disagree about the member.
	//
	// It returns nil only when the group cannot serve the network at all, which the
	// caller reports as an error rather than falling through to another outbound.
	SelectForFlow(metadata *InboundContext, network string, commit bool) Outbound
}

// FailoverOutboundGroup is an OPTIONAL capability of a group that can own the DIAL of a
// flow it has selected, not only the choice of member.
//
// # Why the dial has to move into the group
//
// The route path walks a group chain down to a leaf and dials that leaf itself, which is
// what keeps a group a control-plane object: it never wraps a connection and never sees a
// byte. The cost of that split is that the group never learns that its choice failed, so a
// member a probe marked healthy that then times out on live traffic is simply reported to
// the caller.
//
// Retrying above the group is not equivalent and not safe here: a caller that reconnects
// cannot know how far the first attempt got, so it cannot know whether a second attempt
// would replay a request the destination already received. A retry that runs INSIDE the
// group, immediately after a failure that proves nothing was delivered, does not have that
// problem - and that is why the capability owns the dial rather than handing the error
// back.
//
// # Why the interface is implemented unconditionally and the behaviour is not
//
// A group implements this interface whenever it COULD own a dial, and reports through
// FailoverEnabled whether its configuration actually asked for the retry. Splitting the two
// keeps the route path's assertion cheap and free of a registry, while making the behaviour
// opt-in: a group that reports false is resolved and dialled by the old path, so an
// existing configuration that never asked for failover keeps the single attempt it had
// before this capability existed.
type FailoverOutboundGroup interface {
	OutboundGroup

	// FailoverEnabled reports whether this group's configuration opted into the retry.
	//
	// A group that reports false MUST NOT be asked to DialWithFailover. The route path
	// treats it as an outbound without the capability - the chain is resolved with commit
	// and the resolved leaf is handed to the connection manager - and a parent group
	// resolves it to a leaf and dials once. That is what makes "opt-in" mean exactly the
	// pre-capability behaviour rather than "the same path with the retry disabled".
	FailoverEnabled() bool

	// DialWithFailover dials this flow through the group's own selection.
	//
	// A group that implements this MUST own the whole decision: it resolves the chain to a
	// leaf for each attempt, and on a failure that proves the PATH to the chosen member is
	// dead it re-runs its own selection with that member excluded and dials ONE alternate.
	// It MUST NOT simply index to the next member, because that would bypass the strategy,
	// the health filter and the failure filter at once.
	//
	// The contract the caller depends on:
	//
	//   - At most two dial attempts for the WHOLE flow, across nesting. The budget is
	//     carried in the context from the outermost capability dial to every nested one, so
	//     a chain of groups cannot spend one alternate per level. A third attempt overall
	//     would turn a bounded replacement into a scan of the member list on every outage.
	//   - The caller's context is used unchanged, so the retry shares the remaining
	//     deadline instead of extending it. The retry is worth having only while the caller
	//     is still waiting.
	//   - A failure that does not implicate the path - the destination refused, the caller
	//     cancelled - is returned without a retry. A second member cannot fix a target that
	//     answered.
	//   - Existing connections are never interrupted. The failure being replaced belongs to
	//     the attempt that has not produced a connection yet; a connection already handed to
	//     a caller is a different object.
	//   - ListenPacket is NOT covered. A packet connection is one session, and replacing it
	//     would change the source address underneath NAT, QUIC and DNS.
	//
	// The implementation is free to fail OPEN: if it has no alternate to offer, or if the
	// dial fails in a way that is not about the path, it returns the error the first member
	// produced.
	DialWithFailover(ctx context.Context, metadata *InboundContext, network string, destination M.Socksaddr) (net.Conn, error)
}
