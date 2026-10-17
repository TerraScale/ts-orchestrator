package oci

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"
)

type terminalSDKRecorder struct {
	requests []*http.Request
}

func (recorder *terminalSDKRecorder) Do(request *http.Request) (*http.Response, error) {
	recorder.requests = append(recorder.requests, request)
	return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
}

type fakeInstanceReadback struct {
	boots       core.ListBootVolumeAttachmentsResponse
	boot        core.GetBootVolumeResponse
	attachments core.ListVnicAttachmentsResponse
	vnic        core.GetVnicResponse
	bootGets    int
	vnicGets    int
}

func (reader *fakeInstanceReadback) ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error) {
	return reader.boots, nil
}

func (reader *fakeInstanceReadback) GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error) {
	reader.bootGets++
	return reader.boot, nil
}

func (reader *fakeInstanceReadback) ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return reader.attachments, nil
}

func (reader *fakeInstanceReadback) GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error) {
	reader.vnicGets++
	return reader.vnic, nil
}

type fakeLaunchSDKClient struct {
	request  *core.LaunchInstanceRequest
	response core.LaunchInstanceResponse
	err      error
	calls    int
}

func (client *fakeLaunchSDKClient) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	client.calls++
	client.request = new(request)
	return client.response, client.err
}
