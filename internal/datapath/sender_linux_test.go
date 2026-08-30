//go:build linux

package datapath

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

const fakeSendAll = -1

type fakeRawSendResult struct {
	written int
	err     error
}

type fakeRawPollResult struct {
	ready   int
	revents int16
	err     error
}

type fakeSocketOption struct {
	fd     int
	level  int
	option int
	value  int
}

type fakeLinuxPacketSenderSyscalls struct {
	mu sync.Mutex

	socketFD       int
	socketErr      error
	socketCalls    int
	socketDomain   int
	socketType     int
	socketProtocol int
	socketOptions  []fakeSocketOption
	setsockoptErr  error
	sendResults    []fakeRawSendResult
	sendCalls      int
	sendFlags      []int
	pollResults    []fakeRawPollResult
	pollCalls      int
	pollEvents     []int16
	pollTimeouts   []int
	pollFunc       func([]unix.PollFd, int) (int, error)
	closeFDs       []int
	closeFunc      func(int) error
}

func newFakeLinuxPacketSenderSyscalls() *fakeLinuxPacketSenderSyscalls {
	return &fakeLinuxPacketSenderSyscalls{socketFD: 42}
}

func (f *fakeLinuxPacketSenderSyscalls) socket(domain, typ, protocol int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.socketCalls++
	f.socketDomain = domain
	f.socketType = typ
	f.socketProtocol = protocol
	return f.socketFD, f.socketErr
}

func (f *fakeLinuxPacketSenderSyscalls) setsockoptInt(fd, level, option, value int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.socketOptions = append(f.socketOptions, fakeSocketOption{fd: fd, level: level, option: option, value: value})
	return f.setsockoptErr
}

func (f *fakeLinuxPacketSenderSyscalls) sendmsgN(_ int, payload, _ []byte, _ unix.Sockaddr, flags int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.sendCalls
	f.sendCalls++
	f.sendFlags = append(f.sendFlags, flags)
	if call >= len(f.sendResults) {
		return 0, unix.EIO
	}
	result := f.sendResults[call]
	if result.written == fakeSendAll {
		result.written = len(payload)
	}
	return result.written, result.err
}

func (f *fakeLinuxPacketSenderSyscalls) poll(fds []unix.PollFd, timeout int) (int, error) {
	f.mu.Lock()
	call := f.pollCalls
	f.pollCalls++
	f.pollTimeouts = append(f.pollTimeouts, timeout)
	if len(fds) > 0 {
		f.pollEvents = append(f.pollEvents, fds[0].Events)
	}
	pollFunc := f.pollFunc
	var result fakeRawPollResult
	if call < len(f.pollResults) {
		result = f.pollResults[call]
	} else if pollFunc == nil {
		result.err = unix.EIO
	}
	f.mu.Unlock()

	if pollFunc != nil {
		return pollFunc(fds, timeout)
	}
	if len(fds) > 0 {
		fds[0].Revents = result.revents
	}
	return result.ready, result.err
}

func (f *fakeLinuxPacketSenderSyscalls) close(fd int) error {
	f.mu.Lock()
	f.closeFDs = append(f.closeFDs, fd)
	closeFunc := f.closeFunc
	f.mu.Unlock()
	if closeFunc != nil {
		return closeFunc(fd)
	}
	return nil
}

func openFakeLinuxPacketSender(t *testing.T, syscalls *fakeLinuxPacketSenderSyscalls) *linuxPacketSender {
	t.Helper()
	sender, err := newLinuxPacketSender(2048, syscalls)
	if err != nil {
		t.Fatalf("open fake raw sender: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	return sender
}

func rawSenderTestRequest() SendRequest {
	return SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
		IfIndex:     17,
		Payload:     []byte{1, 2, 3, 4},
	}
}

func TestNewLinuxPacketSenderUsesNonblockingSocket(t *testing.T) {
	syscalls := newFakeLinuxPacketSenderSyscalls()
	sender := openFakeLinuxPacketSender(t, syscalls)

	syscalls.mu.Lock()
	defer syscalls.mu.Unlock()
	wantType := unix.SOCK_RAW | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK
	if syscalls.socketCalls != 1 || syscalls.socketDomain != unix.AF_INET || syscalls.socketType != wantType || syscalls.socketProtocol != unix.IPPROTO_RAW {
		t.Fatalf("socket calls=%d domain=%d type=%#x protocol=%d, want one nonblocking raw IPv4 socket", syscalls.socketCalls, syscalls.socketDomain, syscalls.socketType, syscalls.socketProtocol)
	}
	if len(syscalls.socketOptions) != 1 {
		t.Fatalf("socket options = %v, want IP_HDRINCL", syscalls.socketOptions)
	}
	option := syscalls.socketOptions[0]
	if option.fd != sender.fd || option.level != unix.IPPROTO_IP || option.option != unix.IP_HDRINCL || option.value != 1 {
		t.Fatalf("socket option = %+v, want IP_HDRINCL=1", option)
	}
}

func TestNewLinuxPacketSenderClosesSocketAfterSetupFailure(t *testing.T) {
	setupErr := errors.New("setsockopt failed")
	syscalls := newFakeLinuxPacketSenderSyscalls()
	syscalls.setsockoptErr = setupErr

	if _, err := newLinuxPacketSender(2048, syscalls); !errors.Is(err, setupErr) {
		t.Fatalf("open error = %v, want %v", err, setupErr)
	}
	syscalls.mu.Lock()
	defer syscalls.mu.Unlock()
	if len(syscalls.closeFDs) != 1 || syscalls.closeFDs[0] != syscalls.socketFD {
		t.Fatalf("closed fds = %v, want failed socket %d", syscalls.closeFDs, syscalls.socketFD)
	}
}

func TestLinuxPacketSenderBoundsWouldBlock(t *testing.T) {
	pollErr := errors.New("poll failed")
	tests := []struct {
		name          string
		sends         []fakeRawSendResult
		poll          fakeRawPollResult
		wantErr       error
		wantSendCalls int
	}{
		{
			name:          "poll timeout",
			sends:         []fakeRawSendResult{{err: unix.EAGAIN}},
			poll:          fakeRawPollResult{},
			wantErr:       unix.EAGAIN,
			wantSendCalls: 1,
		},
		{
			name:          "one retry after writable",
			sends:         []fakeRawSendResult{{err: unix.EAGAIN}, {written: fakeSendAll}},
			poll:          fakeRawPollResult{ready: 1, revents: unix.POLLOUT},
			wantSendCalls: 2,
		},
		{
			name:          "repeated would block",
			sends:         []fakeRawSendResult{{err: unix.EWOULDBLOCK}, {err: unix.EAGAIN}},
			poll:          fakeRawPollResult{ready: 1, revents: unix.POLLOUT},
			wantErr:       unix.EAGAIN,
			wantSendCalls: 2,
		},
		{
			name:          "poll failure",
			sends:         []fakeRawSendResult{{err: unix.EAGAIN}},
			poll:          fakeRawPollResult{err: pollErr},
			wantErr:       pollErr,
			wantSendCalls: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			syscalls := newFakeLinuxPacketSenderSyscalls()
			syscalls.sendResults = tc.sends
			syscalls.pollResults = []fakeRawPollResult{tc.poll}
			sender := openFakeLinuxPacketSender(t, syscalls)

			err := sender.SendPacket(rawSenderTestRequest())
			if tc.wantErr == nil && err != nil {
				t.Fatalf("SendPacket: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("SendPacket error = %v, want %v", err, tc.wantErr)
			}

			syscalls.mu.Lock()
			defer syscalls.mu.Unlock()
			if syscalls.sendCalls != tc.wantSendCalls || syscalls.pollCalls != 1 {
				t.Fatalf("send calls=%d poll calls=%d, want %d and 1", syscalls.sendCalls, syscalls.pollCalls, tc.wantSendCalls)
			}
			for _, flags := range syscalls.sendFlags {
				if flags&unix.MSG_DONTWAIT == 0 {
					t.Fatalf("send flags = %#x, want MSG_DONTWAIT", flags)
				}
			}
			if len(syscalls.pollEvents) != 1 || syscalls.pollEvents[0] != unix.POLLOUT {
				t.Fatalf("poll events = %v, want POLLOUT", syscalls.pollEvents)
			}
			if len(syscalls.pollTimeouts) != 1 || syscalls.pollTimeouts[0] != int(linuxRawSendTimeout/time.Millisecond) {
				t.Fatalf("poll timeouts = %v, want %s", syscalls.pollTimeouts, linuxRawSendTimeout)
			}
		})
	}
}

func TestLinuxPacketSenderDoesNotRetryAmbiguousResult(t *testing.T) {
	for _, result := range []fakeRawSendResult{
		{written: 1},
		{written: 1, err: unix.EAGAIN},
		{written: fakeSendAll, err: unix.EAGAIN},
	} {
		syscalls := newFakeLinuxPacketSenderSyscalls()
		syscalls.sendResults = []fakeRawSendResult{result}
		sender := openFakeLinuxPacketSender(t, syscalls)

		if err := sender.SendPacket(rawSenderTestRequest()); err == nil {
			t.Fatalf("ambiguous send result %+v succeeded", result)
		}
		syscalls.mu.Lock()
		if syscalls.sendCalls != 1 || syscalls.pollCalls != 0 {
			t.Fatalf("ambiguous result %+v caused send calls=%d poll calls=%d, want 1 and 0", result, syscalls.sendCalls, syscalls.pollCalls)
		}
		syscalls.mu.Unlock()
	}
}

func TestLinuxPacketSenderCloseCompletesAfterInFlightWait(t *testing.T) {
	syscalls := newFakeLinuxPacketSenderSyscalls()
	syscalls.sendResults = []fakeRawSendResult{{err: unix.EAGAIN}}
	pollStarted := make(chan struct{})
	releasePoll := make(chan struct{})
	var polling atomic.Bool
	var closeDuringPoll atomic.Bool
	syscalls.pollFunc = func([]unix.PollFd, int) (int, error) {
		polling.Store(true)
		close(pollStarted)
		<-releasePoll
		polling.Store(false)
		return 0, nil
	}
	syscalls.closeFunc = func(int) error {
		if polling.Load() {
			closeDuringPoll.Store(true)
		}
		return nil
	}
	sender := openFakeLinuxPacketSender(t, syscalls)

	sendDone := make(chan error, 1)
	go func() { sendDone <- sender.SendPacket(rawSenderTestRequest()) }()
	select {
	case <-pollStarted:
	case <-time.After(time.Second):
		t.Fatal("send did not enter poll")
	}
	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- sender.Close()
	}()
	<-closeStarted
	close(releasePoll)

	select {
	case err := <-sendDone:
		if !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("SendPacket error = %v, want bounded EAGAIN", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendPacket did not return after poll completed")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked behind completed send")
	}
	if closeDuringPoll.Load() {
		t.Fatal("Close raced the in-flight send syscall")
	}
	if err := sender.SendPacket(rawSenderTestRequest()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after Close error = %v, want net.ErrClosed", err)
	}
}

func TestLinuxPacketSenderTimeoutTriggersRecoveryWithoutPacketRetry(t *testing.T) {
	syscalls := newFakeLinuxPacketSenderSyscalls()
	syscalls.sendResults = []fakeRawSendResult{{err: unix.EAGAIN}}
	syscalls.pollResults = []fakeRawPollResult{{}}
	initialSender := openFakeLinuxPacketSender(t, syscalls)
	replacementSender := &captureSender{}
	receiver := newScriptedReceiver()
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	factoryCalled := make(chan struct{}, 1)
	dp := newDatapath(
		testConfig(t, "--persistent-error-threshold=1"),
		nil,
		metricSet,
		receiver,
		initialSender,
		func(int) (PacketSender, error) {
			factoryCalled <- struct{}{}
			return replacementSender, nil
		},
	)
	dp.senderRecoveryDelay = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)
	packet := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443), sanitizedAWSOptions(), nil)

	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	select {
	case <-factoryCalled:
	case <-time.After(time.Second):
		t.Fatal("raw send timeout did not request sender recovery")
	}
	waitForMetricValue(t, metricSet.SenderReinitializations.WithLabelValues(metrics.SenderReinitializationOK), 1)
	waitForMetricValue(t, metricSet.GWLBSendFailures, 1)
	waitForMetricValue(t, metricSet.Drops, 1)
	waitForReady(t, dp)

	syscalls.mu.Lock()
	sendCalls := syscalls.sendCalls
	closeCalls := len(syscalls.closeFDs)
	syscalls.mu.Unlock()
	if sendCalls != 1 || replacementSender.Attempts() != 0 {
		t.Fatalf("timed-out packet attempts: initial=%d replacement=%d, want 1 and 0", sendCalls, replacementSender.Attempts())
	}
	if closeCalls != 1 {
		t.Fatalf("timed-out raw sender closes = %d, want 1", closeCalls)
	}
	if testutil.ToFloat64(metricSet.GWLBSendFailures) != 1 || testutil.ToFloat64(metricSet.Drops) != 1 {
		t.Fatal("raw send timeout was not classified as a send failure and drop")
	}
	if testutil.ToFloat64(metricSet.TargetReadinessTransitions.WithLabelValues(metrics.ReadinessComponentSender, metrics.ReadinessStateNotReady)) != 1 {
		t.Fatal("raw send timeout did not make sender readiness unhealthy before recovery")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after raw sender recovery: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after raw sender recovery")
	}
}

func TestIPv4PacketInfoControl(t *testing.T) {
	request := SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
		IfIndex:     17,
	}
	oob, err := ipv4PacketInfoControl(request)
	if err != nil {
		t.Fatalf("build packet info: %v", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse packet info: messages=%d err=%v", len(messages), err)
	}
	message := messages[0]
	if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO {
		t.Fatalf("unexpected control header: %+v", message.Header)
	}
	if got := binary.NativeEndian.Uint32(message.Data[0:4]); got != 17 {
		t.Fatalf("ifindex = %d, want 17", got)
	}
	if got := [4]byte(message.Data[4:8]); got != [4]byte{198, 51, 100, 20} {
		t.Fatalf("source hint = %v", got)
	}
}

func TestIPv4PacketInfoControlRejectsInvalidSourceSelection(t *testing.T) {
	for _, request := range []SendRequest{
		{Source: netip.MustParseAddrPort("[2001:db8::1]:40000"), IfIndex: 17},
		{Source: netip.MustParseAddrPort("198.51.100.20:40000"), IfIndex: 0},
	} {
		if _, err := ipv4PacketInfoControl(request); err == nil {
			t.Fatalf("invalid packet info request succeeded: %+v", request)
		}
	}
}
