package serf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics" //best library ever
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
		metrics.IncrCounter([]string{"serf", "ProtocalVersion", conf.ProtocolVersion}, 1)
		
		return nil, fmt.Errorf("Protocol version '%d' too low. Must be in range: [%d, %d]",
			conf.ProtocolVersion, ProtocolVersionMin, ProtocolVersionMax)
	} else if conf.ProtocolVersion > ProtocolVersionMax {
		metrics.IncrCounter([]string{"serf", "ProtocalVersion", conf.ProtocolVersion}, 1)
		
		return nil, fmt.Errorf("Protocol version '%d' too high. Must be in range: [%d, %d]",
			conf.ProtocolVersion, ProtocolVersionMin, ProtocolVersionMax)
	}

	if conf.UserEventSizeLimit > UserEventSizeLimit {
		metrics.IncrCounter([]string{"serf", "UserEventSizeLimit", "Exceeded"}, 1)
		return nil, fmt.Errorf("user event size limit exceeds limit of %d bytes", UserEventSizeLimit)
	}
	
	serf := &Serf{
		config:        conf,
		members:       make(map[string]*memberState),
		queryResponse: make(map[LamportTime]*QueryResponse),
		shutdownCh:    make(chan struct{}),
		state:         SerfAlive,
	}
	serf.eventJoinIgnore.Store(false)

	if len(serf.encodeTags(conf.Tags)) > memberlist.MetaMaxSize {
		metrics.IncrCounter([]string{"serf", "tags", "sizeExceeded"}, 1)
		
		return nil, fmt.Errorf("Encoded length of tags exceeds limit of %d bytes", memberlist.MetaMaxSize)
	}

	if conf.CoalescePeriod > 0 && conf.QuiescentPeriod > 0 && conf.EventCh != nil {
		c := &memberEventCoalescer{
			lastEvents:   make(map[string]EventType),
			latestEvents: make(map[string]coalesceEvent),
		}

		conf.EventCh = coalescedEventCh(conf.EventCh, serf.shutdownCh,
			conf.CoalescePeriod, conf.QuiescentPeriod, c)
	}

	if conf.UserCoalescePeriod > 0 && conf.UserQuiescentPeriod > 0 && conf.EventCh != nil {
		c := &userEventCoalescer{
			events: make(map[string]*latestUserEvents),
		}

		conf.EventCh = coalescedEventCh(conf.EventCh, serf.shutdownCh, conf.UserCoalescePeriod, conf.UserQuiescentPeriod, c)
	}

	outCh, err := newSerfQueries(serf, serf.logger, conf.EventCh, serf.shutdownCh)
	if err != nil {
		metrics.IncrCounter([]string{"serf", "query", "SetupHandler", "failure"}, 1)
		return nil, fmt.Errorf("Failed to setup serf query handler: %v", err)
	}
	conf.EventCh = outCh

	if !conf.DisableCoordinates {
		serf.coordClient, err = coordinate.NewClient(coordinate.DefaultConfig())
		if err != nil {
			metrics.IncrCounter([]string{"serf", "cooardClient", "CreateFailure"}, 1)
			return nil, fmt.Errorf("Failed to create coordinate client: %v", err)
		}
	}

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
			metrics.IncrCounter([]string{"serf", "Snapshot", "SetupFailure"}, 1)
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

	if !conf.DisableCoordinates {
		serf.coordCache = make(map[string]*coordinate.Coordinate)
		serf.coordCache[conf.NodeName] = serf.coordClient.GetCoordinate()
	}

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

	serf.recentIntents = make(map[string]nodeIntent)

	serf.eventBuffer = make([]*userEvents, conf.EventBuffer)
	serf.queryBuffer = make([]*queries, conf.QueryBuffer)

	serf.clock.Increment()
	serf.eventClock.Increment()
	serf.queryClock.Increment()

	serf.clock.Witness(oldClock)
	serf.eventClock.Witness(oldEventClock)
	serf.queryClock.Witness(oldQueryClock)

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

	if conf.Merge != nil {
		md := &mergeDelegate{serf: serf}
		conf.MemberlistConfig.Merge = md
		conf.MemberlistConfig.Alive = md
	}

	memberlist, err := memberlist.Create(conf.MemberlistConfig)
	if err != nil {
		metrics.IncrCounter([]string{"serf", "memberlist", "CreateFailure"}, 1)
		return nil, fmt.Errorf("Failed to create memberlist: %v", err)
	}

	serf.memberlist = memberlist

	serf.keyManager = &KeyManager{serf: serf}

	go serf.handleReap()
	go serf.handleReconnect()
	go serf.checkQueueDepth("Intent", serf.broadcasts)
	go serf.checkQueueDepth("Event", serf.eventBroadcasts)
	go serf.checkQueueDepth("Query", serf.queryBroadcasts)

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

	msg := messageUserEvent{
		LTime:   s.eventClock.Time(),
		Name:    name,
		Payload: payload,
		CC:      coalesce,
	}

	raw, err := encodeMessage(messageUserEventType, &msg)
	if err != nil {
		return err
	}

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

	s.handleUserEvent(&msg)

	s.eventBroadcasts.QueueBroadcast(&broadcast{
		msg: raw,
	})
	return nil
}

func (s *Serf) Query(name string, payload []byte, params *QueryParam) (*QueryResponse, error) {
	if s.ProtocolVersion() < 4 {
		return nil, FeatureNotSupported
	}

	if params == nil {
		params = s.DefaultQueryParams()
	} else if params.Timeout == 0 {
		params.Timeout = s.DefaultQueryTimeout()
	}

	local := s.memberlist.LocalNode()

	filters, err := params.encodeFilters()
	if err != nil {
		metr
		return nil, fmt.Errorf("Failed to format filters: %v", err)
	}

	var flags uint32
	if params.RequestAck {
		flags |= queryFlagAck
	}

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

	raw, err := encodeMessage(messageQueryType, &q)
	if err != nil {
		return nil, err
	}

	if len(raw) > s.config.QuerySizeLimit {
		return nil, fmt.Errorf("query exceeds limit of %d bytes", s.config.QuerySizeLimit)
	}

	resp := newQueryResponse(s.memberlist.NumMembers(), &q)
	s.registerQueryResponse(params.Timeout, resp)

	s.handleQuery(&q)

	s.queryBroadcasts.QueueBroadcast(&broadcast{
		msg: raw,
	})
	return resp, nil
}

func (s *Serf) registerQueryResponse(timeout time.Duration, resp *QueryResponse) {
	s.queryLock.Lock()
	defer s.queryLock.Unlock()

	s.queryResponse[resp.lTime] = resp

	time.AfterFunc(timeout, func() {
		s.queryLock.Lock()
		delete(s.queryResponse, resp.lTime)
		resp.Close()
		s.queryLock.Unlock()
	})
}

func (s *Serf) SetTags(tags map[string]string) error {
	if len(s.encodeTags(tags)) > memberlist.MetaMaxSize {
		metrics.IncrCounter([]string{"serf", "MetaMaxSizeExceed"}, 1)
		return
	}
	s.config.Tags = tags
	return s.memberlist.UpdateNode(s.config.BroadcastTimeout)
}

func (s *Serf) Join(existing []string, ignoreOld bool) (int, error) {
	if s.State() != SerfAlive {
		return 0, fmt.Errorf("Serf can't Join after Leave or Shutdown")
	}

	s.joinLock.Lock()
	defer s.joinLock.Unlock()

	if ignoreOld {
		s.eventJoinIgnore.Store(true)
		defer func() {
			s.eventJoinIgnore.Store(false)
		}()
	}

	num, err := s.memberlist.Join(existing)

	if num > 0 {
		if err := s.broadcastJoin(s.clock.Time()); err != nil {
			return num, err
		}
	}

	return num, err
}

func (s *Serf) broadcastJoin(ltime LamportTime) error {
	msg := messageJoin{
		LTime: ltime,
		Node:  s.config.NodeName,
	}
	s.clock.Witness(ltime)

	s.handleNodeJoinIntent(&msg)

	if err := s.broadcast(messageJoinType, &msg, nil); err != nil {
		return err
	}
	return nil
}

func (s *Serf) Leave() error {
	s.stateLock.Lock()
	if s.state == SerfLeft {
		s.stateLock.Unlock()
		return nil
	} else if s.state == SerfLeaving {
		s.stateLock.Unlock()
		return
	} else if s.state == SerfShutdown {
		s.stateLock.Unlock()
		return
	}
	s.state = SerfLeaving
	s.stateLock.Unlock()

	if s.snapshotter != nil {
		s.snapshotter.Leave()
	}

	msg := messageLeave{
		LTime: s.clock.Time(),
		Node:  s.config.NodeName,
	}
	s.clock.Increment()

	s.handleNodeLeaveIntent(&msg)

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

	err := s.memberlist.Leave(s.config.BroadcastTimeout)
	if err != nil {
		return err
	}

	time.Sleep(s.config.LeavePropagateDelay)

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
		return
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
		return
	}

	event := EventMemberLeave
	eventStr := "EventMemberLeave"
	if member.Status != StatusLeft {
		event = EventMemberFailed
		eventStr = "EventMemberFailed"
	}

	metrics.IncrCounter([]string{"serf", "member", member.Status.String()}, 1)

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
	if member.Status == StatusLeaving || member.Status == StatusLeft {
		s.leftMembers = removeOldMember(s.leftMembers, member.Name)
	}
	s.eraseNode(member)
}
func (s *Serf) handleNodeJoinIntent(joinMsg *messageJoin) bool {
	s.clock.Witness(joinMsg.LTime)
	s.memberLock.Lock()
	defer s.memberLock.Unlock()
	member, ok := s.members[joinMsg.Node]
	if !ok {
		return upsertIntent(s.recentIntents, joinMsg.Node, messageJoinType, joinMsg.LTime, time.Now)
	}
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
	curTime := s.eventClock.Time()
	if curTime > LamportTime(len(s.eventBuffer)) && eventMsg.LTime < curTime-LamportTime(len(s.eventBuffer)) {
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
	if curTime > LamportTime(len(s.queryBuffer)) && query.LTime < curTime-LamportTime(len(s.queryBuffer)) {
		return false
	}

	idx := query.LTime % LamportTime(len(s.queryBuffer))
	seen := s.queryBuffer[idx]
	if seen != nil && seen.LTime == query.LTime {
		for _, previous := range seen.QueryIDs {
			if previous == query.ID {
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
			return
		} else {
			addr := net.UDPAddr{IP: query.Addr, Port: int(query.Port)}
			if err := s.memberlist.SendTo(&addr, raw); err != nil {
				return
			}
			if err := s.relayResponse(query.RelayFactor, addr, &ack); err != nil {
				return
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
		metrics.IncrCounter([]string{"serf", "query_ok_false"}, 1)
		return
	}

	if query.id != resp.ID {
		metrics.IncrCounter([]string{"serf", "query_ID_mismatch"}, 1)
		return
	}

	if query.Finished() {
		metrics.IncrCounter([]string{"serf", "query_finished"}, 1)
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
			return
		}
	} else {
		if _, ok := query.responses[resp.From]; ok {
			metrics.IncrCounter([]string{"serf", "query_duplicate_responses"}, 1)
			return
		}

		metrics.IncrCounter([]string{"serf", "query_responses"}, 1)
		err := query.sendResponse(NodeResponse{From: resp.From, Payload: resp.Payload})
		if err != nil {
			return
		}
	}
}

func (s *Serf) handleNodeConflict(existing, other *memberlist.Node) {
	if existing.Name != s.config.NodeName {
		return
	}

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
		return
	}

	var responses, matching int

	respCh := resp.ResponseCh()
	for r := range respCh {
		if len(r.Payload) < 1 || messageType(r.Payload[0]) != messageConflictResponseType {
			continue
		}
		var member Member
		if err := decodeMessage(r.Payload[1:], &member); err != nil {
			continue
		}

		responses++
		if member.Addr.Equal(local.Addr) && member.Port == local.Port {
			matching++
		}
	}
	majority := (responses / 2) + 1
	if matching >= majority {
		return
	}

	metrics.IncrCounter([]string{"serf", "name_conflict_minor"}, 1)
	if err := s.Shutdown(); err != nil {
		metrics.IncrCounter([]string{"serf", "shutdownFailure"}, 1)
		return err
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

		if now.Sub(m.leaveTime) <= timeout {
			continue
		}

		// Delete from the list
		old[i], old[n-1] = old[n-1], nil
		old = old[:n-1]
		n--
		i--

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
		return
	}

	// Select a random member to try and join
	idx := rand.Int31n(int32(n))
	mem := s.failedMembers[idx]
	s.memberLock.RUnlock()

	// Format the addr
	addr := net.UDPAddr{IP: mem.Addr, Port: int(mem.Port)}
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
				metrics.IncrCounter([]string{"serf", "queueOverflow"}, 1)
				queue.Prune(max)
			}
		case <-s.shutdownCh:
			return
		}
	}
}

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

		_, err := s.memberlist.Join([]string{prev.Addr})
		if err == nil {
			return
		}
	}
	metrics.IncrCounter([]string{"serf", "rejoinFailure"}, 1)
}

func (s *Serf) encodeTags(tags map[string]string) []byte {
	if s.ProtocolVersion() < 3 {
		role := tags["role"]
		return []byte(role)
	}

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

	if len(buf) == 0 || buf[0] != tagMagicByte {
		tags["role"] = string(buf)
		return tags
	}

	r := bytes.NewReader(buf[1:])
	dec := codec.NewDecoder(r, &codec.MsgpackHandle{})
	if err := dec.Decode(&tags); err != nil {
		metrics.IncrCounter([]string{"serf", "TagDecodeFailure"}, 1)
		return err
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
		metrics.IncrCounter([]string{"serf", "KeyEncodeFailure"}, 1)
		return err
	}

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
