package serf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-msgpack/codec"
	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/serf/coordinate"
)

const (
	ProtocolVersionMin uint8 = 2
	ProtocolVersionMax       = 5
	tagMagicByte uint8 = 255
	SerfAlive SerfState = iota
	SerfLeaving
	SerfLeft
	SerfShutdown
	StatusNone MemberStatus = iota
	StatusAlive
	StatusLeaving
	StatusLeft
	StatusFailed
	snapshotSizeLimit  = 128 * 1024
	UserEventSizeLimit = 9 * 1024
)

var (
	FeatureNotSupported = fmt.Errorf("Feature not supported")
)
type Serf struct {
	clock      LamportClock
	eventClock LamportClock
	queryClock LamportClock

	broadcasts    *memberlist.TransmitLimitedQueue
	config        *Config
	failedMembers []*memberState
	leftMembers   []*memberState
	memberlist    *memberlist.Memberlist
	memberLock    sync.RWMutex
	members       map[string]*memberState

	recentIntents map[string]nodeIntent

	eventBroadcasts *memberlist.TransmitLimitedQueue
	eventBuffer     []*userEvents
	eventJoinIgnore atomic.Value
	eventMinTime    LamportTime
	eventLock       sync.RWMutex

	queryBroadcasts *memberlist.TransmitLimitedQueue
	queryBuffer     []*queries
	queryMinTime    LamportTime
	queryResponse   map[LamportTime]*QueryResponse
	queryLock       sync.RWMutex

	logger     *log.Logger
	joinLock   sync.Mutex
	stateLock  sync.Mutex
	state      SerfState
	shutdownCh chan struct{}

	snapshotter *Snapshotter
	keyManager  *KeyManager

	coordClient    *coordinate.Client
	coordCache     map[string]*coordinate.Coordinate
	coordCacheLock sync.RWMutex
}
type Member struct {
	Name   string
	Addr   net.IP
	Port   uint16
	Tags   map[string]string
	Status MemberStatus

	ProtocolMin uint8
	ProtocolMax uint8
	ProtocolCur uint8
	DelegateMin uint8
	DelegateMax uint8
	DelegateCur uint8
}
type memberState struct {
	Member
	statusLTime LamportTime
	leaveTime   time.Time
}
type nodeIntent struct {
	Type messageType
	WallTime time.Time
	LTime LamportTime
}
type userEvent struct {
	Name    string
	Payload []byte
}
type userEvents struct {
	LTime  LamportTime
	Events []userEvent
}
type queries struct {
	LTime    LamportTime
	QueryIDs []uint32
}

type MemberStatus int
type SerfState int

func init() {
	rand.Seed(time.Now().UnixNano())
}
func (s SerfState) String() string {
	switch s {
	case SerfAlive:
		return "alive"
	case SerfLeaving:
		return "leaving"
	case SerfLeft:
		return "left"
	case SerfShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}
func (s MemberStatus) String() string {
	switch s {
	case StatusNone:
		return "none"
	case StatusAlive:
		return "alive"
	case StatusLeaving:
		return "leaving"
	case StatusLeft:
		return "left"
	case StatusFailed:
		return "failed"
	default:
		panic(fmt.Sprintf("unknown MemberStatus: %d", s))
	}
}
func (ue *userEvent) Equals(other *userEvent) bool {
	if ue.Name != other.Name {
		return false
	}
	if bytes.Compare(ue.Payload, other.Payload) != 0 {
		return false
	}
	return true
}

func Create(conf *Config) (*Serf, error) {
	conf.Init()
	if conf.ProtocolVersion < ProtocolVersionMin {
		return nil, fmt.Errorf("Protocol version '%d' too low. Must be in range: [%d, %d]",
			conf.ProtocolVersion, ProtocolVersionMin, ProtocolVersionMax)
	} else if conf.ProtocolVersion > ProtocolVersionMax {
		return nil, fmt.Errorf("Protocol version '%d' too high. Must be in range: [%d, %d]",
			conf.ProtocolVersion, ProtocolVersionMin, ProtocolVersionMax)
	}

	if conf.UserEventSizeLimit > UserEventSizeLimit {
		return nil, fmt.Errorf("user event size limit exceeds limit of %d bytes", UserEventSizeLimit)
	}

	logger := conf.Logger
	if logger == nil {
		logOutput := conf.LogOutput
		if logOutput == nil {
			logOutput = os.Stderr
		}
		logger = log.New(logOutput, "", log.LstdFlags)
	}

	serf := &Serf{
		config:        conf,
		logger:        logger,
		members:       make(map[string]*memberState),
		queryResponse: make(map[LamportTime]*QueryResponse),
		shutdownCh:    make(chan struct{}),
		state:         SerfAlive,
	}
	serf.eventJoinIgnore.Store(false)

	// Check that the meta data length is okay
	if len(serf.encodeTags(conf.Tags)) > memberlist.MetaMaxSize {
		return nil, fmt.Errorf("Encoded length of tags exceeds limit of %d bytes", memberlist.MetaMaxSize)
	}

	// Check if serf member event coalescing is enabled
	if conf.CoalescePeriod > 0 && conf.QuiescentPeriod > 0 && conf.EventCh != nil {
		c := &memberEventCoalescer{
			lastEvents:   make(map[string]EventType),
			latestEvents: make(map[string]coalesceEvent),
		}

		conf.EventCh = coalescedEventCh(conf.EventCh, serf.shutdownCh,
			conf.CoalescePeriod, conf.QuiescentPeriod, c)
	}

	// Check if user event coalescing is enabled
	if conf.UserCoalescePeriod > 0 && conf.UserQuiescentPeriod > 0 && conf.EventCh != nil {
		c := &userEventCoalescer{
			events: make(map[string]*latestUserEvents),
		}

		conf.EventCh = coalescedEventCh(conf.EventCh, serf.shutdownCh,
			conf.UserCoalescePeriod, conf.UserQuiescentPeriod, c)
	}

	// Listen for internal Serf queries. This is setup before the snapshotter, since
	// we want to capture the query-time, but the internal listener does not passthrough
	// the queries
	outCh, err := newSerfQueries(serf, serf.logger, conf.EventCh, serf.shutdownCh)
	if err != nil {
		return nil, fmt.Errorf("Failed to setup serf query handler: %v", err)
	}
	conf.EventCh = outCh

	// Set up network coordinate client.
	if !conf.DisableCoordinates {
		serf.coordClient, err = coordinate.NewClient(coordinate.DefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("Failed to create coordinate client: %v", err)
		}
	}

	// Try access the snapshot
	var oldClock, oldEventClock, oldQueryClock LamportTime
	var prev []*PreviousNode
	if conf.SnapshotPath != "" {
		eventCh, snap, err := NewSnapshotter(
			conf.SnapshotPath,
			snapshotSizeLimit,
			conf.RejoinAfterLeave,
			serf.logger,
			&serf.clock,
			conf.EventCh,
			serf.shutdownCh)
		if err != nil {
			return nil, fmt.Errorf("Failed to setup snapshot: %v", err)
		}
		serf.snapshotter = snap
		conf.EventCh = eventCh
		prev = snap.AliveNodes()
		oldClock = snap.LastClock()
		oldEventClock = snap.LastEventClock()
		oldQueryClock = snap.LastQueryClock()
		serf.eventMinTime = oldEventClock + 1
		serf.queryMinTime = oldQueryClock + 1
	}

	// Set up the coordinate cache. We do this after we read the snapshot to
	// make sure we get a good initial value from there, if we got one.
	if !conf.DisableCoordinates {
		serf.coordCache = make(map[string]*coordinate.Coordinate)
		serf.coordCache[conf.NodeName] = serf.coordClient.GetCoordinate()
	}

	// Setup the various broadcast queues, which we use to send our own
	// custom broadcasts along the gossip channel.
	serf.broadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       serf.NumNodes,
		RetransmitMult: conf.MemberlistConfig.RetransmitMult,
	}
	serf.eventBroadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       serf.NumNodes,
		RetransmitMult: conf.MemberlistConfig.RetransmitMult,
	}
	serf.queryBroadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       serf.NumNodes,
		RetransmitMult: conf.MemberlistConfig.RetransmitMult,
	}

	// Create the buffer for recent intents
	serf.recentIntents = make(map[string]nodeIntent)

	// Create a buffer for events and queries
	serf.eventBuffer = make([]*userEvents, conf.EventBuffer)
	serf.queryBuffer = make([]*queries, conf.QueryBuffer)

	// Ensure our lamport clock is at least 1, so that the default
	// join LTime of 0 does not cause issues
	serf.clock.Increment()
	serf.eventClock.Increment()
	serf.queryClock.Increment()

	// Restore the clock from snap if we have one
	serf.clock.Witness(oldClock)
	serf.eventClock.Witness(oldEventClock)
	serf.queryClock.Witness(oldQueryClock)

	// Modify the memberlist configuration with keys that we set
	conf.MemberlistConfig.Events = &eventDelegate{serf: serf}
	conf.MemberlistConfig.Conflict = &conflictDelegate{serf: serf}
	conf.MemberlistConfig.Delegate = &delegate{serf: serf}
	conf.MemberlistConfig.DelegateProtocolVersion = conf.ProtocolVersion
	conf.MemberlistConfig.DelegateProtocolMin = ProtocolVersionMin
	conf.MemberlistConfig.DelegateProtocolMax = ProtocolVersionMax
	conf.MemberlistConfig.Name = conf.NodeName
	conf.MemberlistConfig.ProtocolVersion = ProtocolVersionMap[conf.ProtocolVersion]
	if !conf.DisableCoordinates {
		conf.MemberlistConfig.Ping = &pingDelegate{serf: serf}
	}

	// Setup a merge delegate if necessary
	if conf.Merge != nil {
		md := &mergeDelegate{serf: serf}
		conf.MemberlistConfig.Merge = md
		conf.MemberlistConfig.Alive = md
	}

	// Create the underlying memberlist that will manage membership
	// and failure detection for the Serf instance.
	memberlist, err := memberlist.Create(conf.MemberlistConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create memberlist: %v", err)
	}

	serf.memberlist = memberlist

	// Create a key manager for handling all encryption key changes
	serf.keyManager = &KeyManager{serf: serf}

	// Start the background tasks. See the documentation above each method
	// for more information on their role.
	go serf.handleReap()
	go serf.handleReconnect()
	go serf.checkQueueDepth("Intent", serf.broadcasts)
	go serf.checkQueueDepth("Event", serf.eventBroadcasts)
	go serf.checkQueueDepth("Query", serf.queryBroadcasts)

	// Attempt to re-join the cluster if we have known nodes
	if len(prev) != 0 {
		go serf.handleRejoin(prev)
	}

	return serf, nil
}

func (s *Serf) ProtocolVersion() uint8 {
	return s.config.ProtocolVersion
}

func (s *Serf) EncryptionEnabled() bool {
	return s.config.MemberlistConfig.Keyring != nil
}

func (s *Serf) KeyManager() *KeyManager {
	return s.keyManager
}

func (s *Serf) UserEvent(name string, payload []byte, coalesce bool) error {
	payloadSizeBeforeEncoding := len(name) + len(payload)

	// Check size before encoding to prevent needless encoding and return early if it's over the specified limit.
	if payloadSizeBeforeEncoding > s.config.UserEventSizeLimit {
		return fmt.Errorf(
			"user event exceeds configured limit of %d bytes before encoding",
			s.config.UserEventSizeLimit,
		)
	}

	if payloadSizeBeforeEncoding > UserEventSizeLimit {
		return fmt.Errorf(
			"user event exceeds sane limit of %d bytes before encoding",
			UserEventSizeLimit,
		)
	}

	// Create a message
	msg := messageUserEvent{
		LTime:   s.eventClock.Time(),
		Name:    name,
		Payload: payload,
		CC:      coalesce,
	}

	// Start broadcasting the event
	raw, err := encodeMessage(messageUserEventType, &msg)
	if err != nil {
		return err
	}

	// Check the size after encoding to be sure again that
	// we're not attempting to send over the specified size limit.
	if len(raw) > s.config.UserEventSizeLimit {
		return fmt.Errorf(
			"encoded user event exceeds configured limit of %d bytes after encoding",
			s.config.UserEventSizeLimit,
		)
	}

	if len(raw) > UserEventSizeLimit {
		return fmt.Errorf(
			"encoded user event exceeds sane limit of %d bytes before encoding",
			UserEventSizeLimit,
		)
	}

	s.eventClock.Increment()

	// Process update locally
	s.handleUserEvent(&msg)

	s.eventBroadcasts.QueueBroadcast(&broadcast{
		msg: raw,
	})
	return nil
}

func (s *Serf) Query(name string, payload []byte, params *QueryParam) (*QueryResponse, error) {
	// Check that the latest protocol is in use
	if s.ProtocolVersion() < 4 {
		return nil, FeatureNotSupported
	}

	// Provide default parameters if none given
	if params == nil {
		params = s.DefaultQueryParams()
	} else if params.Timeout == 0 {
		params.Timeout = s.DefaultQueryTimeout()
	}

	// Get the local node
	local := s.memberlist.LocalNode()

	// Encode the filters
	filters, err := params.encodeFilters()
	if err != nil {
		return nil, fmt.Errorf("Failed to format filters: %v", err)
	}

	// Setup the flags
	var flags uint32
	if params.RequestAck {
		flags |= queryFlagAck
	}

	// Create a message
	q := messageQuery{
		LTime:       s.queryClock.Time(),
		ID:          uint32(rand.Int31()),
		Addr:        local.Addr,
		Port:        local.Port,
		Filters:     filters,
		Flags:       flags,
		RelayFactor: params.RelayFactor,
		Timeout:     params.Timeout,
		Name:        name,
		Payload:     payload,
	}

	// Encode the query
	raw, err := encodeMessage(messageQueryType, &q)
	if err != nil {
		return nil, err
	}

	// Check the size
	if len(raw) > s.config.QuerySizeLimit {
		return nil, fmt.Errorf("query exceeds limit of %d bytes", s.config.QuerySizeLimit)
	}

	// Register QueryResponse to track acks and responses
	resp := newQueryResponse(s.memberlist.NumMembers(), &q)
	s.registerQueryResponse(params.Timeout, resp)

	// Process query locally
	s.handleQuery(&q)

	// Start broadcasting the event
	s.queryBroadcasts.QueueBroadcast(&broadcast{
		msg: raw,
	})
	return resp, nil
}

func (s *Serf) registerQueryResponse(timeout time.Duration, resp *QueryResponse) {
	s.queryLock.Lock()
	defer s.queryLock.Unlock()

	// Map the LTime to the QueryResponse. This is necessarily 1-to-1,
	// since we increment the time for each new query.
	s.queryResponse[resp.lTime] = resp

	// Setup a timer to close the response and deregister after the timeout
	time.AfterFunc(timeout, func() {
		s.queryLock.Lock()
		delete(s.queryResponse, resp.lTime)
		resp.Close()
		s.queryLock.Unlock()
	})
}

func (s *Serf) SetTags(tags map[string]string) error {
	// Check that the meta data length is okay
	if len(s.encodeTags(tags)) > memberlist.MetaMaxSize {
		return fmt.Errorf("Encoded length of tags exceeds limit of %d bytes",
			memberlist.MetaMaxSize)
	}

	// Update the config
	s.config.Tags = tags

	// Trigger a memberlist update
	return s.memberlist.UpdateNode(s.config.BroadcastTimeout)
}

func (s *Serf) Join(existing []string, ignoreOld bool) (int, error) {
	// Do a quick state check
	if s.State() != SerfAlive {
		return 0, fmt.Errorf("Serf can't Join after Leave or Shutdown")
	}

	// Hold the joinLock, this is to make eventJoinIgnore safe
	s.joinLock.Lock()
	defer s.joinLock.Unlock()

	// Ignore any events from a potential join. This is safe since we hold
	// the joinLock and nobody else can be doing a Join
	if ignoreOld {
		s.eventJoinIgnore.Store(true)
		defer func() {
			s.eventJoinIgnore.Store(false)
		}()
	}

	// Have memberlist attempt to join
	num, err := s.memberlist.Join(existing)

	// If we joined any nodes, broadcast the join message
	if num > 0 {
		// Start broadcasting the update
		if err := s.broadcastJoin(s.clock.Time()); err != nil {
			return num, err
		}
	}

	return num, err
}

func (s *Serf) broadcastJoin(ltime LamportTime) error {
	// Construct message to update our lamport clock
	msg := messageJoin{
		LTime: ltime,
		Node:  s.config.NodeName,
	}
	s.clock.Witness(ltime)

	// Process update locally
	s.handleNodeJoinIntent(&msg)

	// Start broadcasting the update
	if err := s.broadcast(messageJoinType, &msg, nil); err != nil {
		s.logger.Printf("[WARN] serf: Failed to broadcast join intent: %v", err)
		return err
	}
	return nil
}

func (s *Serf) Leave() error {
	// Check the current state
	s.stateLock.Lock()
	if s.state == SerfLeft {
		s.stateLock.Unlock()
		return nil
	} else if s.state == SerfLeaving {
		s.stateLock.Unlock()
		return fmt.Errorf("Leave already in progress")
	} else if s.state == SerfShutdown {
		s.stateLock.Unlock()
		return fmt.Errorf("Leave called after Shutdown")
	}
	s.state = SerfLeaving
	s.stateLock.Unlock()

	// If we have a snapshot, mark we are leaving
	if s.snapshotter != nil {
		s.snapshotter.Leave()
	}

	// Construct the message for the graceful leave
	msg := messageLeave{
		LTime: s.clock.Time(),
		Node:  s.config.NodeName,
	}
	s.clock.Increment()

	// Process the leave locally
	s.handleNodeLeaveIntent(&msg)

	// Only broadcast the leave message if there is at least one
	// other node alive.
	if s.hasAliveMembers() {
		notifyCh := make(chan struct{})
		if err := s.broadcast(messageLeaveType, &msg, notifyCh); err != nil {
			return err
		}

		select {
		case <-notifyCh:
		case <-time.After(s.config.BroadcastTimeout):
			return errors.New("timeout while waiting for graceful leave")
		}
	}

	// Attempt the memberlist leave
	err := s.memberlist.Leave(s.config.BroadcastTimeout)
	if err != nil {
		return err
	}

	// Wait for the leave to propagate through the cluster. The broadcast
	// timeout is how long we wait for the message to go out from our own
	// queue, but this wait is for that message to propagate through the
	// cluster. In particular, we want to stay up long enough to service
	// any probes from other nodes before they learn about us leaving.
	time.Sleep(s.config.LeavePropagateDelay)

	// Transition to Left only if we not already shutdown
	s.stateLock.Lock()
	if s.state != SerfShutdown {
		s.state = SerfLeft
	}
	s.stateLock.Unlock()
	return nil
}

func (s *Serf) hasAliveMembers() bool {
	s.memberLock.RLock()
	defer s.memberLock.RUnlock()

	hasAlive := false
	for _, m := range s.members {
		// Skip ourself, we want to know if OTHER members are alive
		if m.Name == s.config.NodeName {
			continue
		}

		if m.Status == StatusAlive {
			hasAlive = true
			break
		}
	}
	return hasAlive
}

func (s *Serf) LocalMember() Member {
	s.memberLock.RLock()
	defer s.memberLock.RUnlock()
	return s.members[s.config.NodeName].Member
}

func (s *Serf) Members() []Member {
	s.memberLock.RLock()
	defer s.memberLock.RUnlock()

	members := make([]Member, 0, len(s.members))
	for _, m := range s.members {
		members = append(members, m.Member)
	}

	return members
}

func (s *Serf) RemoveFailedNode(node string) error {
	return s.forceLeave(node, false)
}

func (s *Serf) RemoveFailedNodePrune(node string) error {
	return s.forceLeave(node, true)
}

func (s *Serf) forceLeave(node string, prune bool) error {
	msg := messageLeave{
		LTime: s.clock.Time(),
		Node:  node,
		Prune: prune,
	}
	s.clock.Increment()

	s.handleNodeLeaveIntent(&msg)

	if !s.hasAliveMembers() {
		return nil
	}

	notifyCh := make(chan struct{})
	if err := s.broadcast(messageLeaveType, &msg, notifyCh); err != nil {
		return err
	}

	select {
	case <-notifyCh:
	case <-time.After(s.config.BroadcastTimeout):
		return fmt.Errorf("timed out broadcasting node removal")
	}

	return nil
}

func (s *Serf) Shutdown() error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	if s.state == SerfShutdown {
		return nil
	}

	if s.state != SerfLeft {
		s.logger.Printf("[WARN] serf: Shutdown without a Leave")
	}

	s.state = SerfShutdown
	err := s.memberlist.Shutdown()
	if err != nil {
		return err
	}
	close(s.shutdownCh)

	if s.snapshotter != nil {
		s.snapshotter.Wait()
	}

	return nil
}

func (s *Serf) ShutdownCh() <-chan struct{} {
	return s.shutdownCh
}

func (s *Serf) Memberlist() *memberlist.Memberlist {
	return s.memberlist
}

func (s *Serf) State() SerfState {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()
	return s.state
}

func (s *Serf) broadcast(t messageType, msg interface{}, notify chan<- struct{}) error {
	raw, err := encodeMessage(t, msg)
	if err != nil {
		return err
	}

	s.broadcasts.QueueBroadcast(&broadcast{
		msg:    raw,
		notify: notify,
	})
	return nil
}

func (s *Serf) handleNodeJoin(n *memberlist.Node) {
	s.memberLock.Lock()
	defer s.memberLock.Unlock()

	var oldStatus MemberStatus
	member, ok := s.members[n.Name]
	if !ok {
		oldStatus = StatusNone
		member = &memberState{
			Member: Member{
				Name:   n.Name,
				Addr:   net.IP(n.Addr),
				Port:   n.Port,
				Tags:   s.decodeTags(n.Meta),
				Status: StatusAlive,
			},
		}

		if join, ok := recentIntent(s.recentIntents, n.Name, messageJoinType); ok {
			member.statusLTime = join
		}
		if leave, ok := recentIntent(s.recentIntents, n.Name, messageLeaveType); ok {
			member.Status = StatusLeaving
			member.statusLTime = leave
		}

		s.members[n.Name] = member
	} else {
		oldStatus = member.Status
		deadTime := time.Now().Sub(member.leaveTime)
		if oldStatus == StatusFailed && deadTime < s.config.FlapTimeout {
			metrics.IncrCounter([]string{"serf", "member", "flap"}, 1)
		}

		member.Status = StatusAlive
		member.leaveTime = time.Time{}
		member.Addr = net.IP(n.Addr)
		member.Port = n.Port
		member.Tags = s.decodeTags(n.Meta)
	}

	member.ProtocolMin = n.PMin
	member.ProtocolMax = n.PMax
	member.ProtocolCur = n.PCur
	member.DelegateMin = n.DMin
	member.DelegateMax = n.DMax
	member.DelegateCur = n.DCur

	if oldStatus == StatusFailed || oldStatus == StatusLeft {
		s.failedMembers = removeOldMember(s.failedMembers, member.Name)
		s.leftMembers = removeOldMember(s.leftMembers, member.Name)
	}

	metrics.IncrCounter([]string{"serf", "member", "join"}, 1)

	// Send an event along
	s.logger.Printf("[INFO] serf: EventMemberJoin: %s %s",
		member.Member.Name, member.Member.Addr)
	if s.config.EventCh != nil {
		s.config.EventCh <- MemberEvent{
			Type:    EventMemberJoin,
			Members: []Member{member.Member},
		}
	}
}

func (s *Serf) handleNodeLeave(n *memberlist.Node) {
	s.memberLock.Lock()
	defer s.memberLock.Unlock()

	member, ok := s.members[n.Name]
	if !ok {
		return
	}

	switch member.Status {
	case StatusLeaving:
		member.Status = StatusLeft
		member.leaveTime = time.Now()
		s.leftMembers = append(s.leftMembers, member)
	case StatusAlive:
		member.Status = StatusFailed
		member.leaveTime = time.Now()
		s.failedMembers = append(s.failedMembers, member)
	default:
		s.logger.Printf("[WARN] serf: Bad state when leave: %d", member.Status)
		return
	}

	event := EventMemberLeave
	eventStr := "EventMemberLeave"
	if member.Status != StatusLeft {
		event = EventMemberFailed
		eventStr = "EventMemberFailed"
	}

	metrics.IncrCounter([]string{"serf", "member", member.Status.String()}, 1)

	s.logger.Printf("[INFO] serf: %s: %s %s",
		eventStr, member.Member.Name, member.Member.Addr)
	if s.config.EventCh != nil {
		s.config.EventCh <- MemberEvent{
			Type:    event,
			Members: []Member{member.Member},
		}
	}
}

func (s *Serf) handleNodeUpdate(n *memberlist.Node) {
	s.memberLock.Lock()
	defer s.memberLock.Unlock()

	member, ok := s.members[n.Name]
	if !ok {
		return
	}

	member.Addr = net.IP(n.Addr)
	member.Port = n.Port
	member.Tags = s.decodeTags(n.Meta)

	member.ProtocolMin = n.PMin
	member.ProtocolMax = n.PMax
	member.ProtocolCur = n.PCur
	member.DelegateMin = n.DMin
	member.DelegateMax = n.DMax
	member.DelegateCur = n.DCur

	metrics.IncrCounter([]string{"serf", "member", "update"}, 1)

	s.logger.Printf("[INFO] serf: EventMemberUpdate: %s", member.Member.Name)
	if s.config.EventCh != nil {
		s.config.EventCh <- MemberEvent{
			Type:    EventMemberUpdate,
			Members: []Member{member.Member},
		}
	}
}

func (s *Serf) handleNodeLeaveIntent(leaveMsg *messageLeave) bool {

	s.clock.Witness(leaveMsg.LTime)

	s.memberLock.Lock()
	defer s.memberLock.Unlock()

	member, ok := s.members[leaveMsg.Node]
	if !ok {
		return upsertIntent(s.recentIntents, leaveMsg.Node, messageLeaveType, leaveMsg.LTime, time.Now)
	}

	if leaveMsg.LTime <= member.statusLTime {
		return false
	}

	if leaveMsg.Node == s.config.NodeName && s.state == SerfAlive {
		s.logger.Printf("[DEBUG] serf: Refuting an older leave intent")
		go s.broadcastJoin(s.clock.Time())
		return false
	}

	switch member.Status {
	case StatusAlive:
		member.Status = StatusLeaving
		member.statusLTime = leaveMsg.LTime

		if leaveMsg.Prune {
			s.handlePrune(member)
		}
		return true
	case StatusFailed:
		member.Status = StatusLeft
		member.statusLTime = leaveMsg.LTime

		s.failedMembers = removeOldMember(s.failedMembers, member.Name)
		s.leftMembers = append(s.leftMembers, member)

		s.logger.Printf("[INFO] serf: EventMemberLeave (forced): %s %s",
			member.Member.Name, member.Member.Addr)
		if s.config.EventCh != nil {
			s.config.EventCh <- MemberEvent{
				Type:    EventMemberLeave,
				Members: []Member{member.Member},
			}
		}

		if leaveMsg.Prune {
			s.handlePrune(member)
		}

		return true

	case StatusLeaving, StatusLeft:
		if leaveMsg.Prune {
			s.handlePrune(member)
		}
		return true
	default:
		return false
	}
}

func (s *Serf) handlePrune(member *memberState) {
	if member.Status == StatusLeaving {
		time.Sleep(s.config.BroadcastTimeout + s.config.LeavePropagateDelay)
	}

	s.logger.Printf("[INFO] serf: EventMemberReap (forced): %s %s", member.Name, member.Member.Addr)

	if member.Status == StatusLeaving || member.Status == StatusLeft {
		s.leftMembers = removeOldMember(s.leftMembers, member.Name)
	}
	s.eraseNode(member)

}

func (s *Serf) handleNodeJoinIntent(joinMsg *messageJoin) bool {
	// Witness a potentially newer time
	s.clock.Witness(joinMsg.LTime)

	s.memberLock.Lock()
	defer s.memberLock.Unlock()

	member, ok := s.members[joinMsg.Node]
	if !ok {
		// Rebroadcast only if this was an update we hadn't seen before.
		return upsertIntent(s.recentIntents, joinMsg.Node, messageJoinType, joinMsg.LTime, time.Now)
	}

	// Check if this time is newer than what we have
	if joinMsg.LTime <= member.statusLTime {
		return false
	}

	member.statusLTime = joinMsg.LTime

	if member.Status == StatusLeaving {
		member.Status = StatusAlive
	}
	return true
}

func (s *Serf) handleUserEvent(eventMsg *messageUserEvent) bool {
	s.eventClock.Witness(eventMsg.LTime)

	s.eventLock.Lock()
	defer s.eventLock.Unlock()

	if eventMsg.LTime < s.eventMinTime {
		return false
	}

	// Check if this message is too old
	curTime := s.eventClock.Time()
	if curTime > LamportTime(len(s.eventBuffer)) &&
		eventMsg.LTime < curTime-LamportTime(len(s.eventBuffer)) {
		s.logger.Printf(
			"[WARN] serf: received old event %s from time %d (current: %d)",
			eventMsg.Name,
			eventMsg.LTime,
			s.eventClock.Time())
		return false
	}

	idx := eventMsg.LTime % LamportTime(len(s.eventBuffer))
	seen := s.eventBuffer[idx]
	userEvent := userEvent{Name: eventMsg.Name, Payload: eventMsg.Payload}
	if seen != nil && seen.LTime == eventMsg.LTime {
		for _, previous := range seen.Events {
			if previous.Equals(&userEvent) {
				return false
			}
		}
	} else {
		seen = &userEvents{LTime: eventMsg.LTime}
		s.eventBuffer[idx] = seen
	}

	seen.Events = append(seen.Events, userEvent)

	metrics.IncrCounter([]string{"serf", "events"}, 1)
	metrics.IncrCounter([]string{"serf", "events", eventMsg.Name}, 1)

	if s.config.EventCh != nil {
		s.config.EventCh <- UserEvent{
			LTime:    eventMsg.LTime,
			Name:     eventMsg.Name,
			Payload:  eventMsg.Payload,
			Coalesce: eventMsg.CC,
		}
	}
	return true
}

func (s *Serf) handleQuery(query *messageQuery) bool {
	s.queryClock.Witness(query.LTime)

	s.queryLock.Lock()
	defer s.queryLock.Unlock()

	if query.LTime < s.queryMinTime {
		return false
	}

	curTime := s.queryClock.Time()
	if curTime > LamportTime(len(s.queryBuffer)) &&
		query.LTime < curTime-LamportTime(len(s.queryBuffer)) {
		s.logger.Printf(
			"[WARN] serf: received old query %s from time %d (current: %d)",
			query.Name,
			query.LTime,
			s.queryClock.Time())
		return false
	}

	idx := query.LTime % LamportTime(len(s.queryBuffer))
	seen := s.queryBuffer[idx]
	if seen != nil && seen.LTime == query.LTime {
		for _, previous := range seen.QueryIDs {
			if previous == query.ID {
				// Seen this ID already
				return false
			}
		}
	} else {
		seen = &queries{LTime: query.LTime}
		s.queryBuffer[idx] = seen
	}

	seen.QueryIDs = append(seen.QueryIDs, query.ID)

	metrics.IncrCounter([]string{"serf", "queries"}, 1)
	metrics.IncrCounter([]string{"serf", "queries", query.Name}, 1)

	rebroadcast := true
	if query.NoBroadcast() {
		rebroadcast = false
	}

	if !s.shouldProcessQuery(query.Filters) {
		return rebroadcast
	}

	if query.Ack() {
		ack := messageQueryResponse{
			LTime: query.LTime,
			ID:    query.ID,
			From:  s.config.NodeName,
			Flags: queryFlagAck,
		}
		raw, err := encodeMessage(messageQueryResponseType, &ack)
		if err != nil {
			s.logger.Printf("[ERR] serf: failed to format ack: %v", err)
		} else {
			addr := net.UDPAddr{IP: query.Addr, Port: int(query.Port)}
			if err := s.memberlist.SendTo(&addr, raw); err != nil {
				s.logger.Printf("[ERR] serf: failed to send ack: %v", err)
			}
			if err := s.relayResponse(query.RelayFactor, addr, &ack); err != nil {
				s.logger.Printf("[ERR] serf: failed to relay ack: %v", err)
			}
		}
	}

	if s.config.EventCh != nil {
		s.config.EventCh <- &Query{
			LTime:       query.LTime,
			Name:        query.Name,
			Payload:     query.Payload,
			serf:        s,
			id:          query.ID,
			addr:        query.Addr,
			port:        query.Port,
			deadline:    time.Now().Add(query.Timeout),
			relayFactor: query.RelayFactor,
		}
	}
	return rebroadcast
}

func (s *Serf) handleQueryResponse(resp *messageQueryResponse) {
	s.queryLock.RLock()
	query, ok := s.queryResponse[resp.LTime]
	s.queryLock.RUnlock()
	if !ok {
		s.logger.Printf("[WARN] serf: reply for non-running query (LTime: %d, ID: %d) From: %s",
			resp.LTime, resp.ID, resp.From)
		return
	}

	if query.id != resp.ID {
		s.logger.Printf("[WARN] serf: query reply ID mismatch (Local: %d, Response: %d)",
			query.id, resp.ID)
		return
	}

	if query.Finished() {
		return
	}

	if resp.Ack() {
		if _, ok := query.acks[resp.From]; ok {
			metrics.IncrCounter([]string{"serf", "query_duplicate_acks"}, 1)
			return
		}

		metrics.IncrCounter([]string{"serf", "query_acks"}, 1)
		select {
		case query.ackCh <- resp.From:
			query.acks[resp.From] = struct{}{}
		default:
			s.logger.Printf("[WARN] serf: Failed to deliver query ack, dropping")
		}
	} else {
		if _, ok := query.responses[resp.From]; ok {
			metrics.IncrCounter([]string{"serf", "query_duplicate_responses"}, 1)
			return
		}

		metrics.IncrCounter([]string{"serf", "query_responses"}, 1)
		err := query.sendResponse(NodeResponse{From: resp.From, Payload: resp.Payload})
		if err != nil {
			s.logger.Printf("[WARN] %v", err)
		}
	}
}

func (s *Serf) handleNodeConflict(existing, other *memberlist.Node) {
	if existing.Name != s.config.NodeName {
		s.logger.Printf("[WARN] serf: Name conflict for '%s' both %s:%d and %s:%d are claiming",
			existing.Name, existing.Addr, existing.Port, other.Addr, other.Port)
		return
	}

	s.logger.Printf("[ERR] serf: Node name conflicts with another node at %s:%d. Names must be unique! (Resolution enabled: %v)",
		other.Addr, other.Port, s.config.EnableNameConflictResolution)

	if s.config.EnableNameConflictResolution {
		go s.resolveNodeConflict()
	}
}

func (s *Serf) resolveNodeConflict() {
	local := s.memberlist.LocalNode()

	qName := internalQueryName(conflictQuery)
	payload := []byte(s.config.NodeName)
	resp, err := s.Query(qName, payload, nil)
	if err != nil {
		s.logger.Printf("[ERR] serf: Failed to start name resolution query: %v", err)
		return
	}

	var responses, matching int

	respCh := resp.ResponseCh()
	for r := range respCh {
		if len(r.Payload) < 1 || messageType(r.Payload[0]) != messageConflictResponseType {
			s.logger.Printf("[ERR] serf: Invalid conflict query response type: %v", r.Payload)
			continue
		}
		var member Member
		if err := decodeMessage(r.Payload[1:], &member); err != nil {
			s.logger.Printf("[ERR] serf: Failed to decode conflict query response: %v", err)
			continue
		}

		responses++
		if member.Addr.Equal(local.Addr) && member.Port == local.Port {
			matching++
		}
	}

	// Query over, determine if we should live
	majority := (responses / 2) + 1
	if matching >= majority {
		s.logger.Printf("[INFO] serf: majority in name conflict resolution [%d / %d]",
			matching, responses)
		return
	}

	// Since we lost the vote, we need to exit
	s.logger.Printf("[WARN] serf: minority in name conflict resolution, quiting [%d / %d]",
		matching, responses)
	if err := s.Shutdown(); err != nil {
		s.logger.Printf("[ERR] serf: Failed to shutdown: %v", err)
	}
}

func (s *Serf) eraseNode(m *memberState) {
	delete(s.members, m.Name)

	if !s.config.DisableCoordinates {
		s.coordClient.ForgetNode(m.Name)

		s.coordCacheLock.Lock()
		delete(s.coordCache, m.Name)
		s.coordCacheLock.Unlock()
	}

	if s.config.EventCh != nil {
		s.config.EventCh <- MemberEvent{
			Type:    EventMemberReap,
			Members: []Member{m.Member},
		}
	}
}

func (s *Serf) handleReap() {
	for {
		select {
		case <-time.After(s.config.ReapInterval):
			s.memberLock.Lock()
			now := time.Now()
			s.failedMembers = s.reap(s.failedMembers, now, s.config.ReconnectTimeout)
			s.leftMembers = s.reap(s.leftMembers, now, s.config.TombstoneTimeout)
			reapIntents(s.recentIntents, now, s.config.RecentIntentTimeout)
			s.memberLock.Unlock()
		case <-s.shutdownCh:
			return
		}
	}
}

func (s *Serf) handleReconnect() {
	for {
		select {
		case <-time.After(s.config.ReconnectInterval):
			s.reconnect()
		case <-s.shutdownCh:
			return
		}
	}
}

func (s *Serf) reap(old []*memberState, now time.Time, timeout time.Duration) []*memberState {
	n := len(old)
	for i := 0; i < n; i++ {
		m := old[i]

		// Skip if the timeout is not yet reached
		if now.Sub(m.leaveTime) <= timeout {
			continue
		}

		// Delete from the list
		old[i], old[n-1] = old[n-1], nil
		old = old[:n-1]
		n--
		i--

		s.logger.Printf("[INFO] serf: EventMemberReap: %s", m.Name)
		s.eraseNode(m)

	}

	return old
}

func (s *Serf) reconnect() {
	s.memberLock.RLock()

	n := len(s.failedMembers)
	if n == 0 {
		s.memberLock.RUnlock()
		return
	}

	numFailed := float32(len(s.failedMembers))
	numAlive := float32(len(s.members) - len(s.failedMembers) - len(s.leftMembers))
	if numAlive == 0 {
		numAlive = 1 // guard against zero divide
	}
	prob := numFailed / numAlive
	if rand.Float32() > prob {
		s.memberLock.RUnlock()
		s.logger.Printf("[DEBUG] serf: forgoing reconnect for random throttling")
		return
	}

	// Select a random member to try and join
	idx := rand.Int31n(int32(n))
	mem := s.failedMembers[idx]
	s.memberLock.RUnlock()

	// Format the addr
	addr := net.UDPAddr{IP: mem.Addr, Port: int(mem.Port)}
	s.logger.Printf("[INFO] serf: attempting reconnect to %v %s", mem.Name, addr.String())

	// Attempt to join at the memberlist level
	s.memberlist.Join([]string{addr.String()})
}

func (s *Serf) getQueueMax() int {
	max := s.config.MaxQueueDepth
	if s.config.MinQueueDepth > 0 {
		s.memberLock.RLock()
		max = 2 * len(s.members)
		s.memberLock.RUnlock()

		if max < s.config.MinQueueDepth {
			max = s.config.MinQueueDepth
		}
	}
	return max
}

func (s *Serf) checkQueueDepth(name string, queue *memberlist.TransmitLimitedQueue) {
	for {
		select {
		case <-time.After(s.config.QueueCheckInterval):
			numq := queue.NumQueued()
			metrics.AddSample([]string{"serf", "queue", name}, float32(numq))
			if numq >= s.config.QueueDepthWarning {
				s.logger.Printf("[WARN] serf: %s queue depth: %d", name, numq)
			}
			if max := s.getQueueMax(); numq > max {
				s.logger.Printf("[WARN] serf: %s queue depth (%d) exceeds limit (%d), dropping messages!",
					name, numq, max)
				queue.Prune(max)
			}
		case <-s.shutdownCh:
			return
		}
	}
}

// removeOldMember is used to remove an old member from a list of old
// members.
func removeOldMember(old []*memberState, name string) []*memberState {
	for i, m := range old {
		if m.Name == name {
			n := len(old)
			old[i], old[n-1] = old[n-1], nil
			return old[:n-1]
		}
	}

	return old
}

func reapIntents(intents map[string]nodeIntent, now time.Time, timeout time.Duration) {
	for node, intent := range intents {
		if now.Sub(intent.WallTime) > timeout {
			delete(intents, node)
		}
	}
}

func upsertIntent(intents map[string]nodeIntent, node string, itype messageType,
	ltime LamportTime, stamper func() time.Time) bool {
	if intent, ok := intents[node]; !ok || ltime > intent.LTime {
		intents[node] = nodeIntent{
			Type:     itype,
			WallTime: stamper(),
			LTime:    ltime,
		}
		return true
	}

	return false
}

func recentIntent(intents map[string]nodeIntent, node string, itype messageType) (LamportTime, bool) {
	if intent, ok := intents[node]; ok && intent.Type == itype {
		return intent.LTime, true
	}

	return LamportTime(0), false
}

func (s *Serf) handleRejoin(previous []*PreviousNode) {
	for _, prev := range previous {
		// Do not attempt to join ourself
		if prev.Name == s.config.NodeName {
			continue
		}

		s.logger.Printf("[INFO] serf: Attempting re-join to previously known node: %s", prev)
		_, err := s.memberlist.Join([]string{prev.Addr})
		if err == nil {
			s.logger.Printf("[INFO] serf: Re-joined to previously known node: %s", prev)
			return
		}
	}
	s.logger.Printf("[WARN] serf: Failed to re-join any previously known node")
}

func (s *Serf) encodeTags(tags map[string]string) []byte {
	// Support role-only backwards compatibility
	if s.ProtocolVersion() < 3 {
		role := tags["role"]
		return []byte(role)
	}

	// Use a magic byte prefix and msgpack encode the tags
	var buf bytes.Buffer
	buf.WriteByte(tagMagicByte)
	enc := codec.NewEncoder(&buf, &codec.MsgpackHandle{})
	if err := enc.Encode(tags); err != nil {
		panic(fmt.Sprintf("Failed to encode tags: %v", err))
	}
	return buf.Bytes()
}

func (s *Serf) decodeTags(buf []byte) map[string]string {
	tags := make(map[string]string)

	// Backwards compatibility mode
	if len(buf) == 0 || buf[0] != tagMagicByte {
		tags["role"] = string(buf)
		return tags
	}

	// Decode the tags
	r := bytes.NewReader(buf[1:])
	dec := codec.NewDecoder(r, &codec.MsgpackHandle{})
	if err := dec.Decode(&tags); err != nil {
		s.logger.Printf("[ERR] serf: Failed to decode tags: %v", err)
	}
	return tags
}

func (s *Serf) Stats() map[string]string {
	toString := func(v uint64) string {
		return strconv.FormatUint(v, 10)
	}
	s.memberLock.RLock()
	members := toString(uint64(len(s.members)))
	failed := toString(uint64(len(s.failedMembers)))
	left := toString(uint64(len(s.leftMembers)))
	health_score := toString(uint64(s.memberlist.GetHealthScore()))

	s.memberLock.RUnlock()
	stats := map[string]string{
		"members":      members,
		"failed":       failed,
		"left":         left,
		"health_score": health_score,
		"member_time":  toString(uint64(s.clock.Time())),
		"event_time":   toString(uint64(s.eventClock.Time())),
		"query_time":   toString(uint64(s.queryClock.Time())),
		"intent_queue": toString(uint64(s.broadcasts.NumQueued())),
		"event_queue":  toString(uint64(s.eventBroadcasts.NumQueued())),
		"query_queue":  toString(uint64(s.queryBroadcasts.NumQueued())),
		"encrypted":    fmt.Sprintf("%v", s.EncryptionEnabled()),
	}
	if !s.config.DisableCoordinates {
		stats["coordinate_resets"] = toString(uint64(s.coordClient.Stats().Resets))
	}
	return stats
}

func (s *Serf) writeKeyringFile() error {
	if len(s.config.KeyringFile) == 0 {
		return nil
	}

	keyring := s.config.MemberlistConfig.Keyring
	keysRaw := keyring.GetKeys()
	keysEncoded := make([]string, len(keysRaw))

	for i, key := range keysRaw {
		keysEncoded[i] = base64.StdEncoding.EncodeToString(key)
	}

	encodedKeys, err := json.MarshalIndent(keysEncoded, "", "  ")
	if err != nil {
		return fmt.Errorf("Failed to encode keys: %s", err)
	}

	// Use 0600 for permissions because key data is sensitive
	if err = ioutil.WriteFile(s.config.KeyringFile, encodedKeys, 0600); err != nil {
		return fmt.Errorf("Failed to write keyring file: %s", err)
	}

	// Success!
	return nil
}

// GetCoordinate returns the network coordinate of the local node.
func (s *Serf) GetCoordinate() (*coordinate.Coordinate, error) {
	if !s.config.DisableCoordinates {
		return s.coordClient.GetCoordinate(), nil
	}

	return nil, fmt.Errorf("Coordinates are disabled")
}

func (s *Serf) GetCachedCoordinate(name string) (coord *coordinate.Coordinate, ok bool) {
	if !s.config.DisableCoordinates {
		s.coordCacheLock.RLock()
		defer s.coordCacheLock.RUnlock()
		if coord, ok = s.coordCache[name]; ok {
			return coord, true
		}

		return nil, false
	}

	return nil, false
}

func (s *Serf) NumNodes() (numNodes int) {
	s.memberLock.RLock()
	numNodes = len(s.members)
	s.memberLock.RUnlock()

	return numNodes
}
