package pcap

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

type API struct {
	log     *zap.Logger
	apiConf APIConf
	bufConf BufferConf
	UnimplementedAPIServer
}

type APIConf struct {
	Targets []string
}

func NewAPI(log *zap.Logger, bufConf BufferConf, apiConf APIConf) (*API, error) {
	if log == nil {
		log = zap.L()
	}

	return &API{
		log:     log,
		bufConf: bufConf,
		apiConf: apiConf,
	}, nil
}

func (api *API) boshEnabled() bool {
	// TODO implement
	return true
}

func (api *API) cfEnabled() bool {
	// TODO implement
	return true
}
func (api *API) CaptureBosh(stream API_CaptureBoshServer) (err error) {
	// Receive and validate capture Bosh request
	api.log.Info("received new stream on CaptureBosh handler")

	if !api.boshEnabled() {
		return status.Error(codes.FailedPrecondition, "capturing from bosh vms is not supported")
	}

	ctx, cancel := WithCancelCause(stream.Context())
	defer func() {
		cancel(nil)
	}()

	defer func() {
		if err != nil {
			api.log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unknown, "unable to receive message: %w", err)
	}

	err = validateAPIBoshRequest(req)
	if err != nil {
		return errorf(codes.InvalidArgument, "%w", err)
	}

	// TODO Validate & get targets from bosh
	var targets []string
	targets = api.apiConf.Targets

	opts := req.Payload.(*BoshRequest_Start).Start.Capture

	streamPreparer := &streamPrep{}

	// Start capture
	out, err := capture(ctx, stream, streamPreparer, opts, targets, api.log)
	if err != nil {
		return err
	}

	forwardWG := &sync.WaitGroup{}
	forwardWG.Add(1)

	forwardToStream(cancel, out, stream, api.bufConf, forwardWG)

	// Wait for capture stop
	boshStopCmd(cancel, stream)

	err = Cause(ctx)
	// Cancelling the context with nil causes context.Cancelled to be set
	// which is a non-error in our case.
	if err != nil {
		return err
	}

	forwardWG.Wait()

	return nil
}

func checkAgentStatus(statusRes *StatusResponse, err error, target string) error {
	if err != nil {
		err = fmt.Errorf("status request finished with error for '%s': %w", target, err)
		return err
	}

	if !(statusRes.Healthy) {
		statusErr := fmt.Errorf("agent unhealthy '%s': %s", target, statusRes.Message)
		return statusErr
	}

	if CompatibilityLevel > statusRes.CompatibilityLevel {
		statusErr := fmt.Errorf("incompatible versions for '%s': expected compatibility level %d+ but got %d ", target, CompatibilityLevel, statusRes.CompatibilityLevel)
		return statusErr
	}
	return nil
}

func mergeResponseChannels(cs []<-chan *CaptureResponse) <-chan *CaptureResponse {
	var wg sync.WaitGroup
	out := make(chan *CaptureResponse)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan *CaptureResponse) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are done.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

type streamPrep struct {
}

// prepareStreamToTarget creates a client connection to the given target, contacts the client API for the Agent service
// to start the Capture.
func (p *streamPrep) prepareStreamToTarget(ctx context.Context, req *CaptureOptions, target string) (captureReceiver, error) {
	cc, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials())) // TODO: TLS
	if err != nil {
		err = fmt.Errorf("start capture from '%s': %w", target, err)
		// out <- newMessageResponse(MessageType_START_CAPTURE_FAILED, err.Error())
		return nil, err
	}

	agent := NewAgentClient(cc)

	statusRes, err := agent.Status(ctx, &StatusRequest{})
	err = checkAgentStatus(statusRes, err, target)
	if err != nil {
		return nil, err
	}

	// Do not use the same context as for readMsgFromStream. Otherwise, the call of cancel function will cancel the agent
	// before the stop capture request will be sent
	captureStream, err := agent.Capture(context.Background())

	if err != nil {
		convertStatusCodeToMsg(err, target)
		return nil, err
	}

	err = captureStream.Send(&AgentRequest{
		Payload: &AgentRequest_Start{
			Start: &StartAgentCapture{
				Capture: &CaptureOptions{
					Device:  req.Device,
					Filter:  req.Filter,
					SnapLen: req.SnapLen,
				},
			},
		},
	})
	if err != nil {
		// out <- convertStatusCodeToMsg(err, target)
		return nil, err
	}
	return captureStream, nil
}

type captureReceiver interface {
	Recv() (*CaptureResponse, error)
	Send(*AgentRequest) error
	CloseSend() error
}

// readMsgFromStream reads Capture messages from stream and outputs them to the out channel.If the given context errors
// an AgentRequest_Stop is sent and the messages continue to be read.if context will be cancelled from other routine
// (mostly  because client requests to stop capture), the stop request will be forwarded to agent. The data from the agent will be read till stream ends with EOF.
func readMsgFromStream(ctx context.Context, captureStream captureReceiver, target string) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, 100)
	stopped := false
	go func() {
		defer close(out)
		// defer wg.Done()
		defer captureStream.CloseSend()
		for {
			if ctx.Err() != nil && !stopped {
				stopped = true
				err := captureStream.Send(&AgentRequest{
					Payload: &AgentRequest_Stop{},
				})
				if err != nil {
					out <- convertStatusCodeToMsg(err, target)
					return
				}
			}
			msg, err := captureStream.Recv()
			if err != nil && errors.Is(err, io.EOF) {
				msg := fmt.Sprintf("capture has stopped gracefully: %s", target)
				out <- newMessageResponse(MessageType_CAPTURE_STOPPED, msg)
				return
			}
			code := status.Code(err)
			if code != codes.OK {
				out <- convertStatusCodeToMsg(err, target)
				return
			}
			out <- msg
		}
	}()
	return out
}

func convertStatusCodeToMsg(err error, target string) *CaptureResponse {
	code := status.Code(err)
	err = fmt.Errorf("capturing from agent %s: %w", target, err)

	switch code {
	case codes.InvalidArgument:
		return newMessageResponse(MessageType_INVALID_REQUEST, err.Error())
	case codes.Unavailable:
		return newMessageResponse(MessageType_INSTANCE_DISCONNECTED, err.Error())
	case codes.Internal, codes.Unknown:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error())
	default:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error())
	}
}
func validateAPIBoshRequest(req *BoshRequest) error {
	if req == nil {
		return fmt.Errorf("invalid message: message: %w", errNilField)
	}

	if req.Payload == nil {
		return fmt.Errorf("invalid message: payload: %w", errNilField)
	}

	startReq, ok := req.Payload.(*BoshRequest_Start)
	if !ok {
		return fmt.Errorf("invalid message: expected Payload of type StartBoshRequest: %w", errInvalidPayload)
	}

	if startReq.Start == nil {
		return fmt.Errorf("invalid message: start: %w", errNilField)
	}

	if startReq.Start.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if startReq.Start.Deployment == "" {
		return fmt.Errorf("invalid message: deployment: %w", errEmptyField)
	}

	if len(startReq.Start.Groups) == 0 {
		return fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	if startReq.Start.Capture == nil {
		return fmt.Errorf("invalid message: capture options: %w", errNilField)
	}

	err := startReq.Start.Capture.validate()
	if err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}

	return nil
}

// boshRequestReceiver is an interface used by boshStopCmd to simplify testing.
type boshRequestReceiver interface {
	Recv() (*BoshRequest, error)
}

// stopCmd reads the next message from the stream. It ensures that the message
// has a payload of StopBoshCapture. If any error is encountered or the payload is
// of a different type an appropriate cause is set and the cancel function is called.
func boshStopCmd(cancel CancelCauseFunc, stream boshRequestReceiver) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			cancel(errorf(codes.Unknown, "read message: %w", err))
			return
		}

		if msg == nil || msg.Payload == nil {
			cancel(errorf(codes.InvalidArgument, "read message: message or payload: %w", errNilField))
			return
		}

		// request is empty, no need to save it
		_, ok := msg.Payload.(*BoshRequest_Stop)
		if !ok {
			cancel(errorf(codes.InvalidArgument, "read payload: expected Payload of type StopBoshCapture: %w", errInvalidPayload))
			return
		}

		// cancel without cause - normal exit
		zap.L().Debug("client requested stop of capture")
		cancel(nil)
	}()
}

// cfRequestReceiver is an interface used by cfStopCmd to simplify testing.
type cfRequestReceiver interface {
	Recv() (*CloudfoundryRequest, error)
}

// stopCmd reads the next message from the stream. It ensures that the message
// has a payload of StopCloudfoundryCapture. If any error is encountered or the payload is
// of a different type an appropriate cause is set and the cancel function is called.
func cfStopCmd(cancel CancelCauseFunc, stream cfRequestReceiver) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			cancel(errorf(codes.Unknown, "read message: %w", err))
			return
		}

		if msg == nil || msg.Payload == nil {
			cancel(errorf(codes.InvalidArgument, "read message: message or payload: %w", errNilField))
			return
		}

		// request is empty, no need to save it
		_, ok := msg.Payload.(*CloudfoundryRequest_Stop)
		if !ok {
			cancel(errorf(codes.InvalidArgument, "read payload: expected Payload of type StopCloudfoundryCapture: %w", errInvalidPayload))
			return
		}

		// cancel without cause - normal exit
		zap.L().Debug("client requested stop of capture")
		cancel(nil)
	}()
}

func (api *API) CaptureCloudfoundry(stream API_CaptureCloudfoundryServer) (err error) {
	api.log.Info("received new stream on CaptureCloudfoundry handler")

	if !api.cfEnabled() {
		return status.Error(codes.FailedPrecondition, "capturing from app container is not supported")
	}

	ctx, cancel := WithCancelCause(stream.Context())
	defer func() {
		api.log.Error("defer")
		cancel(nil)
	}()

	defer func() {
		if err != nil {
			api.log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unknown, "unable to receive message: %w", err)
	}

	err = validateAPICfRequest(req)
	if err != nil {
		return errorf(codes.InvalidArgument, "%w", err)
	}

	// TODO Validate with xsuaa
	var targets []string
	targets = append(targets, "localhost:8083")

	api.log.Info("creating capture stream")

	opts := req.Payload.(*CloudfoundryRequest_Start).Start.Capture

	streamPreparer := &streamPrep{}

	out, err := capture(ctx, stream, streamPreparer, opts, targets, api.log)
	if err != nil {
		return err
	}

	forwardWG := &sync.WaitGroup{}
	forwardWG.Add(1)
	forwardToStream(cancel, out, stream, api.bufConf, forwardWG)

	cfStopCmd(cancel, stream)

	err = Cause(ctx)
	// Cancelling the context with nil causes context.Cancelled to be set
	// which is a non-error in our case.
	if err != nil {
		return err
	}

	forwardWG.Wait()
	return nil
}

func validateAPICfRequest(req *CloudfoundryRequest) error {
	if req == nil {
		return fmt.Errorf("invalid message: message: %w", errNilField)
	}

	if req.Payload == nil {
		return fmt.Errorf("invalid message: payload: %w", errNilField)
	}

	startReq, ok := req.Payload.(*CloudfoundryRequest_Start)
	if !ok {
		return fmt.Errorf("invalid message: expected Payload of type StartCloudfoundryRequest: %w", errInvalidPayload)
	}

	if startReq.Start == nil {
		return fmt.Errorf("invalid message: start: %w", errNilField)
	}

	if startReq.Start.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if startReq.Start.AppId == "" {
		return fmt.Errorf("invalid message: application_id: %w", errEmptyField)
	}

	if startReq.Start.Capture == nil {
		return fmt.Errorf("invalid message: capture options: %w", errNilField)
	}

	err := startReq.Start.Capture.validate()
	if err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}

	return nil
}

type streamPreparer interface {
	prepareStreamToTarget(context.Context, *CaptureOptions, string) (captureReceiver, error)
}

func capture(ctx context.Context, stream responseSender, streamPrep streamPreparer, opts *CaptureOptions, targets []string, log *zap.Logger) (<-chan *CaptureResponse, error) {
	var captureCs []<-chan *CaptureResponse

	runningCaptures := 0
	for _, target := range targets {
		log = log.With(zap.String("target", target))
		log.Info("starting capture")

		captureStream, err := streamPrep.prepareStreamToTarget(ctx, opts, target)
		if err != nil {
			stream.Send(newMessageResponse(MessageType_START_CAPTURE_FAILED, err.Error()))

			log.Info("capture cannot be started")

			continue
		}

		runningCaptures++

		log.Info("Add capture waiting group")

		c := readMsgFromStream(ctx, captureStream, target)
		captureCs = append(captureCs, c)
	}

	if runningCaptures == 0 {
		log.Error("Starting of all captures failed during stream preparation")
		return nil, errorf(codes.FailedPrecondition, "Starting of all captures failed")
	}

	// merge channels to one channel and send to forward to stream
	out := mergeResponseChannels(captureCs)
	return out, nil
}
