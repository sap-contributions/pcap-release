package pcap

import (
	"context"
	"errors"
	"testing"
)

func TestValidateBoshStartRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *BoshRequest
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "Request is nil",
			req:         nil,
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload is nil",
			req:         &BoshRequest{},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload invalid type",
			req:         &BoshRequest{Payload: &BoshRequest_Stop{}},
			wantErr:     true,
			expectedErr: errInvalidPayload,
		},
		{
			name:        "Request Payload start is nil",
			req:         &BoshRequest{Payload: &BoshRequest_Start{}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Token is not present",
			req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Deployment: "cf", Groups: []string{"router"}, Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Request Deployment field is not present",
			req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Groups: []string{"router"}, Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Request Groups field is not present",
			req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Deployment: "cf", Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Request Capture Options not complete",
			req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Deployment: "cf", Groups: []string{"router"}}}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Valid request",
			req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Deployment: "cf", Groups: []string{"router"}, Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     false,
			expectedErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateApiBoshRequest(test.req)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}

type mockCaptureStream struct {
	msg *CaptureResponse
	err error
}

func (m *mockCaptureStream) Recv() (*CaptureResponse, error) {
	return m.msg, m.err
}

func (m *mockCaptureStream) Send(*AgentRequest) error {
	return nil
}
func Test_readMsg(t *testing.T) {
	tests := []struct {
		name          string
		captureStream captureReceiver
		target        string
		expectedData  MessageType
	}{
		/*{
			name:          "EOF during capture",
			captureStream: &mockCaptureStream{nil, io.EOF},
			target:        "172.20.0.2",
			expectedData:  MessageType_CAPTURE_STOPPED,
		}
		{
			name:          "Unexpected error from capture stream",
			captureStream: &mockCaptureStream{nil, errorf(codes.Unknown, "unexpected error")},
			target:        "172.20.0.2",
			expectedData:  MessageType_CONNECTION_ERROR,
		},*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make(chan *CaptureResponse, 1)
			ctx := context.Background()
			readMsg(ctx, tt.captureStream, tt.target, out)

			var got MessageType
			for s := range out {
				got = s.GetPayload().(*CaptureResponse_Message).Message.GetType()
			}

			if got != tt.expectedData {
				t.Errorf("Expected %s but got %s ", tt.expectedData, got)
			}
		})
	}
}

func TestCheckAgentStatus(t *testing.T) {
	tests := []struct {
		name      string
		statusRes *StatusResponse
		err       error
		want      *CaptureResponse
		wantErr   bool
	}{

		{
			name:      "some error during status request",
			statusRes: nil,
			err:       errEmptyField,
			wantErr:   true,
		},
		{
			name:      "agent unhealthy",
			statusRes: &StatusResponse{Healthy: false, CompatibilityLevel: CompatibilityLevel},
			err:       nil,
			wantErr:   true,
		},
		{
			name:      "agent incompatible",
			statusRes: &StatusResponse{Healthy: true, CompatibilityLevel: CompatibilityLevel - 1},
			err:       nil,
			wantErr:   true,
		},
		{
			name:      "agent healthy and compatible",
			statusRes: &StatusResponse{Healthy: true, CompatibilityLevel: CompatibilityLevel},
			err:       nil,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkAgentStatus(tt.statusRes, tt.err, "localhost:8083")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkAgentStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
