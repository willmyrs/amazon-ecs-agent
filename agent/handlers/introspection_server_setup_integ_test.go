//go:build integration
// +build integration

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apitask "github.com/aws/amazon-ecs-agent/agent/api/task"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	mock_utils "github.com/aws/amazon-ecs-agent/agent/handlers/mocks"
	v1 "github.com/aws/amazon-ecs-agent/agent/handlers/v1"
	apitaskstatus "github.com/aws/amazon-ecs-agent/ecs-agent/api/task/status"
	"github.com/aws/amazon-ecs-agent/ecs-agent/introspection"
	"github.com/aws/amazon-ecs-agent/ecs-agent/metrics"
	ni "github.com/aws/amazon-ecs-agent/ecs-agent/netlib/model/networkinterface"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testContainerInstanceArn = "test_container_instance_arn"
	testClusterArn           = "test_cluster_arn"
	ipv4Address              = "10.0.0.2"
)

var runtimeStatsConfigForTest = config.BooleanDefaultFalse{}

func TestMetadataHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStateResolver := mock_utils.NewMockDockerStateResolver(ctrl)

	server, _ := introspection.NewServer(&v1.AgentStateImpl{
		ContainerInstanceArn: aws.String(testContainerInstanceArn),
		ClusterName:          testClusterArn,
		TaskEngine:           mockStateResolver,
	}, metrics.NewNopEntryFactory(), introspection.WithRuntimeStats(runtimeStatsConfigForTest.Enabled()))

	requestHandler := server.Handler

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/metadata", nil)
	requestHandler.ServeHTTP(recorder, req)

	var resp introspection.AgentMetadataResponse
	json.Unmarshal(recorder.Body.Bytes(), &resp)

	if resp.Cluster != testClusterArn {
		t.Error("Metadata returned the wrong cluster arn")
	}
	if *resp.ContainerInstanceArn != testContainerInstanceArn {
		t.Error("Metadata returned the wrong cluster arn")
	}
}

func TestListMultipleTasks(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks")

	var tasksResponse introspection.TasksResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &tasksResponse)
	if err != nil {
		t.Fatal(err)
	}

	taskDiffHelper(t, testTasks, tasksResponse)
}

func TestGetTaskByDockerID(t *testing.T) {
	// stateSetupHelper uses the convention of dockerid-$arn-$containerName; the
	// second task has a container named foo
	recorder := performMockRequest(t, "/v1/tasks?dockerid=dockerid-task2-foo")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	if err != nil {
		t.Fatal(err)
	}

	taskDiffHelper(t, []*apitask.Task{testTasks[1]}, introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}})
}

func TestTaskNotFound(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?dockerid=dockerid-task2-foo-bar")

	emptyResponse, _ := json.Marshal(introspection.TaskResponse{})

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Equal(t, emptyResponse, recorder.Body.Bytes())
}

func TestGetTaskByShortDockerIDMultiple(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?dockerid=dockerid-tas")

	assert.Equal(t, http.StatusBadRequest, recorder.Code, "Expected http 400 for dockerid with multiple matches")
}

func TestGetTaskShortByDockerID404(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?dockerid=notfound")

	assert.Equal(t, http.StatusNotFound, recorder.Code, "API did not return 404 for bad dockerid")
}

func TestGetTaskByShortDockerID(t *testing.T) {
	// stateSetupHelper uses the convention of dockerid-$arn-$containerName; the
	// first task has a container name prefix of dockerid-tas
	recorder := performMockRequest(t, "/v1/tasks?dockerid=dockerid-by")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	require.NoError(t, err, "unmarshal failed for get task by short docker id")

	taskDiffHelper(t, []*apitask.Task{testTasks[2]}, introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}})
}

func TestGetTaskByDockerID404(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?dockerid=does-not-exist")

	if recorder.Code != 404 {
		t.Error("API did not return 404 for bad dockerid")
	}
}

func TestGetTaskByTaskArn(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?taskarn=task1")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	if err != nil {
		t.Fatal(err)
	}

	taskDiffHelper(t, []*apitask.Task{testTasks[0]}, introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}})
}

func TestGetAWSVPCTaskByTaskArn(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?taskarn=awsvpcTask")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	if err != nil {
		t.Fatal(err)
	}

	resp := introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}}

	assert.Equal(t, ipv4Address, resp.Tasks[0].Containers[0].Networks[0].IPv4Addresses[0])
	taskDiffHelper(t, []*apitask.Task{testTasks[3]}, resp)
}

func TestGetHostNeworkingTaskByTaskArn(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?taskarn=hostModeNetworkingTask")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	if err != nil {
		t.Fatal(err)
	}

	resp := introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}}

	assert.Equal(t, uint16(80), resp.Tasks[0].Containers[0].Ports[0].ContainerPort)
	assert.Equal(t, "tcp", resp.Tasks[0].Containers[0].Ports[0].Protocol)

	taskDiffHelper(t, []*apitask.Task{testTasks[4]}, resp)
}

func TestGetBridgeNeworkingTaskByTaskArn(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?taskarn=bridgeModeNetworkingTask")

	var taskResponse introspection.TaskResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &taskResponse)
	if err != nil {
		t.Fatal(err)
	}

	resp := introspection.TasksResponse{Tasks: []*introspection.TaskResponse{&taskResponse}}

	assert.Equal(t, uint16(80), resp.Tasks[0].Containers[0].Ports[0].ContainerPort)
	assert.Equal(t, "tcp", resp.Tasks[0].Containers[0].Ports[0].Protocol)

	taskDiffHelper(t, []*apitask.Task{testTasks[5]}, resp)
}

func TestGetTaskByTaskArnNotFound(t *testing.T) {
	recorder := performMockRequest(t, "/v1/tasks?taskarn=doesnotexist")

	if recorder.Code != http.StatusNotFound {
		t.Errorf("Expected %d for bad taskarn, but was %d", http.StatusNotFound, recorder.Code)
	}
}

func TestBackendMismatchMapping(t *testing.T) {
	// Test that a KnownStatus past a DesiredStatus suppresses the DesiredStatus output
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStateResolver := mock_utils.NewMockDockerStateResolver(ctrl)

	containers := []*apicontainer.Container{
		{
			Name: "c1",
		},
	}
	testTask := &apitask.Task{
		Arn:                 "task1",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskStopped,
		Family:              "test",
		Version:             "1",
		Containers:          containers,
	}

	state := dockerstate.NewTaskEngineState()
	stateSetupHelper(state, []*apitask.Task{testTask})

	mockStateResolver.EXPECT().State().Return(state)
	server, _ := introspection.NewServer(&v1.AgentStateImpl{
		ContainerInstanceArn: aws.String(testContainerInstanceArn),
		ClusterName:          testClusterArn,
		TaskEngine:           mockStateResolver,
	}, metrics.NewNopEntryFactory(), introspection.WithRuntimeStats(runtimeStatsConfigForTest.Enabled()))
	requestHandler := server.Handler

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/tasks", nil)
	requestHandler.ServeHTTP(recorder, req)

	var tasksResponse introspection.TasksResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &tasksResponse)
	if err != nil {
		t.Fatal(err)
	}
	if tasksResponse.Tasks[0].DesiredStatus != "" {
		t.Error("Expected '', was ", tasksResponse.Tasks[0].DesiredStatus)
	}
	if tasksResponse.Tasks[0].KnownStatus != "STOPPED" {
		t.Error("Expected STOPPED, was ", tasksResponse.Tasks[0].KnownStatus)
	}
}

func taskDiffHelper(t *testing.T, expected []*apitask.Task, actual introspection.TasksResponse) {
	if len(expected) != len(actual.Tasks) {
		t.Errorf("Expected %v tasks, had %v tasks", len(expected), len(actual.Tasks))
	}

	for _, task := range expected {
		// Find related actual task
		var respTask *introspection.TaskResponse
		for _, actualTask := range actual.Tasks {
			if actualTask.Arn == task.Arn {
				respTask = actualTask
			}
		}

		if respTask == nil {
			t.Errorf("Could not find matching task for arn: %v", task.Arn)
			continue
		}

		if respTask.DesiredStatus != task.GetDesiredStatus().String() {
			t.Errorf("DesiredStatus mismatch: %v != %v", respTask.DesiredStatus, task.GetDesiredStatus())
		}
		taskKnownStatus := task.GetKnownStatus().String()
		if respTask.KnownStatus != taskKnownStatus {
			t.Errorf("KnownStatus mismatch: %v != %v", respTask.KnownStatus, taskKnownStatus)
		}

		if respTask.Family != task.Family || respTask.Version != task.Version {
			t.Errorf("Family mismatch: %v:%v != %v:%v", respTask.Family, respTask.Version, task.Family, task.Version)
		}

		if len(respTask.Containers) != len(task.Containers) {
			t.Errorf("Expected %v containers in %v, was %v", len(task.Containers), task.Arn, len(respTask.Containers))
			continue
		}
		for _, respCont := range respTask.Containers {
			_, ok := task.ContainerByName(respCont.Name)
			if !ok {
				t.Errorf("Could not find container %v", respCont.Name)
			}
			if respCont.DockerID == "" {
				t.Error("blank dockerid")
			}
		}
	}
}

var testTasks = []*apitask.Task{
	{
		Arn:                 "task1",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "1",
		Containers: []*apicontainer.Container{
			{
				Name: "one",
			},
			{
				Name: "two",
			},
		},
	},
	{
		Arn:                 "task2",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "2",
		Containers: []*apicontainer.Container{
			{
				Name: "foo",
			},
		},
	},
	{
		Arn:                 "byShortId",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "2",
		Containers: []*apicontainer.Container{
			{
				Name: "shortId",
			},
		},
	},
	{
		Arn:                 "awsvpcTask",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "1",
		Containers: []*apicontainer.Container{
			{
				Name: "awsvpc",
			},
		},
		ENIs: []*ni.NetworkInterface{
			{
				IPV4Addresses: []*ni.IPV4Address{
					{
						Address: ipv4Address,
					},
				},
			},
		},
	},
	{
		Arn:                 "hostModeNetworkingTask",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "1",
		Containers: []*apicontainer.Container{
			{
				Name: "awsvpc",
				Ports: []apicontainer.PortBinding{
					{
						ContainerPort: 80,
						HostPort:      80,
						Protocol:      apicontainer.TransportProtocolTCP,
					},
				},
			},
		},
	},
	{
		Arn:                 "bridgeModeNetworkingTask",
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		Family:              "test",
		Version:             "1",
		Containers: []*apicontainer.Container{
			{
				Name: "awsvpc",
				KnownPortBindingsUnsafe: []apicontainer.PortBinding{
					{
						ContainerPort: 80,
						HostPort:      80,
						Protocol:      apicontainer.TransportProtocolTCP,
					},
				},
			},
		},
	},
}

func stateSetupHelper(state dockerstate.TaskEngineState, tasks []*apitask.Task) {
	for _, task := range tasks {
		state.AddTask(task)
		for _, container := range task.Containers {
			state.AddContainer(&apicontainer.DockerContainer{
				Container:  container,
				DockerID:   "dockerid-" + task.Arn + "-" + container.Name,
				DockerName: "dockername-" + task.Arn + "-" + container.Name,
			}, task)
		}
	}
}

func performMockRequest(t *testing.T, path string) *httptest.ResponseRecorder {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStateResolver := mock_utils.NewMockDockerStateResolver(ctrl)

	state := dockerstate.NewTaskEngineState()
	stateSetupHelper(state, testTasks)

	mockStateResolver.EXPECT().State().Return(state)

	server, _ := introspection.NewServer(&v1.AgentStateImpl{
		ContainerInstanceArn: aws.String(testContainerInstanceArn),
		ClusterName:          testClusterArn,
		TaskEngine:           mockStateResolver,
	}, metrics.NewNopEntryFactory(), introspection.WithRuntimeStats(runtimeStatsConfigForTest.Enabled()))

	requestHandler := server.Handler

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", path, nil)
	requestHandler.ServeHTTP(recorder, req)

	return recorder
}