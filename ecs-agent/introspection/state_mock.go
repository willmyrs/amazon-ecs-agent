// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/aws/amazon-ecs-agent/ecs-agent/introspection (interfaces: AgentState)

// Package introspection is a generated GoMock package.
package introspection

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockAgentState is a mock of AgentState interface.
type MockAgentState struct {
	ctrl     *gomock.Controller
	recorder *MockAgentStateMockRecorder
}

// MockAgentStateMockRecorder is the mock recorder for MockAgentState.
type MockAgentStateMockRecorder struct {
	mock *MockAgentState
}

// NewMockAgentState creates a new mock instance.
func NewMockAgentState(ctrl *gomock.Controller) *MockAgentState {
	mock := &MockAgentState{ctrl: ctrl}
	mock.recorder = &MockAgentStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentState) EXPECT() *MockAgentStateMockRecorder {
	return m.recorder
}

// GetAgentMetadata mocks base method.
func (m *MockAgentState) GetAgentMetadata() (*AgentMetadataResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentMetadata")
	ret0, _ := ret[0].(*AgentMetadataResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentMetadata indicates an expected call of GetAgentMetadata.
func (mr *MockAgentStateMockRecorder) GetAgentMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentMetadata", reflect.TypeOf((*MockAgentState)(nil).GetAgentMetadata))
}

// GetLicenseText mocks base method.
func (m *MockAgentState) GetLicenseText() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLicenseText")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLicenseText indicates an expected call of GetLicenseText.
func (mr *MockAgentStateMockRecorder) GetLicenseText() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLicenseText", reflect.TypeOf((*MockAgentState)(nil).GetLicenseText))
}

// GetTaskMetadataByArn mocks base method.
func (m *MockAgentState) GetTaskMetadataByArn(arg0 string) (*TaskResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTaskMetadataByArn", arg0)
	ret0, _ := ret[0].(*TaskResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTaskMetadataByArn indicates an expected call of GetTaskMetadataByArn.
func (mr *MockAgentStateMockRecorder) GetTaskMetadataByArn(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTaskMetadataByArn", reflect.TypeOf((*MockAgentState)(nil).GetTaskMetadataByArn), arg0)
}

// GetTaskMetadataByID mocks base method.
func (m *MockAgentState) GetTaskMetadataByID(arg0 string) (*TaskResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTaskMetadataByID", arg0)
	ret0, _ := ret[0].(*TaskResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTaskMetadataByID indicates an expected call of GetTaskMetadataByID.
func (mr *MockAgentStateMockRecorder) GetTaskMetadataByID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTaskMetadataByID", reflect.TypeOf((*MockAgentState)(nil).GetTaskMetadataByID), arg0)
}

// GetTaskMetadataByShortID mocks base method.
func (m *MockAgentState) GetTaskMetadataByShortID(arg0 string) (*TaskResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTaskMetadataByShortID", arg0)
	ret0, _ := ret[0].(*TaskResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTaskMetadataByShortID indicates an expected call of GetTaskMetadataByShortID.
func (mr *MockAgentStateMockRecorder) GetTaskMetadataByShortID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTaskMetadataByShortID", reflect.TypeOf((*MockAgentState)(nil).GetTaskMetadataByShortID), arg0)
}

// GetTasksMetadata mocks base method.
func (m *MockAgentState) GetTasksMetadata() (*TasksResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTasksMetadata")
	ret0, _ := ret[0].(*TasksResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTasksMetadata indicates an expected call of GetTasksMetadata.
func (mr *MockAgentStateMockRecorder) GetTasksMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTasksMetadata", reflect.TypeOf((*MockAgentState)(nil).GetTasksMetadata))
}