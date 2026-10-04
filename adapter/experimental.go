package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
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
