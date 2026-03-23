//go:build unit
// +build unit

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

package v2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mock_secrets "github.com/aws/amazon-ecs-agent/ecs-agent/secrets/mocks"
	"github.com/aws/amazon-ecs-agent/ecs-agent/tmds/handlers/utils"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testContainerID = "abc123-456"
	testToken       = "splunk-hec-token-value"
)

func TestSplunkTokenHandler(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		containerID        string
		setupMock          func(*mock_secrets.MockSplunkTokenStore)
		expectedStatusCode int
		expectedCode       string
		expectedToken      string
	}{
		{
			name:        "returns 200 with valid stored token",
			containerID: testContainerID,
			setupMock: func(store *mock_secrets.MockSplunkTokenStore) {
				store.EXPECT().Get(testContainerID).Return(testToken, true)
			},
			expectedStatusCode: http.StatusOK,
			expectedToken:      testToken,
		},
		{
			name:        "returns 404 when token not found",
			containerID: testContainerID,
			setupMock: func(store *mock_secrets.MockSplunkTokenStore) {
				store.EXPECT().Get(testContainerID).Return("", false)
			},
			expectedStatusCode: http.StatusNotFound,
			expectedCode:       "NotFound",
		},
		{
			name:               "returns 400 for empty container ID",
			containerID:        "",
			setupMock:          func(store *mock_secrets.MockSplunkTokenStore) {},
			expectedStatusCode: http.StatusBadRequest,
			expectedCode:       "BadRequest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := mock_secrets.NewMockSplunkTokenStore(ctrl)
			tc.setupMock(mockStore)

			router := mux.NewRouter()
			router.HandleFunc(SplunkTokenPath, SplunkTokenHandler(mockStore))

			path := "/v2/splunk-token/" + tc.containerID
			req, err := http.NewRequest("GET", path, nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			assert.Equal(t, tc.expectedStatusCode, recorder.Code)
			assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

			if tc.expectedStatusCode == http.StatusOK {
				var resp SplunkTokenResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedToken, resp.Token)
			} else {
				var errResp utils.ErrorMessage
				err = json.Unmarshal(recorder.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCode, errResp.Code)
				assert.NotEmpty(t, errResp.Message)
			}
		})
	}
}

func TestContainerEnvHandler(t *testing.T) {
	t.Parallel()

	testEnv := map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
	}

	testCases := []struct {
		name               string
		containerID        string
		setupMock          func(*mock_secrets.MockContainerEnvStore)
		expectedStatusCode int
		expectedCode       string
		expectedEnv        map[string]string
	}{
		{
			name:        "returns 200 with valid stored env",
			containerID: testContainerID,
			setupMock: func(store *mock_secrets.MockContainerEnvStore) {
				store.EXPECT().Get(testContainerID).Return(testEnv, true)
			},
			expectedStatusCode: http.StatusOK,
			expectedEnv:        testEnv,
		},
		{
			name:        "returns 404 when env not found",
			containerID: testContainerID,
			setupMock: func(store *mock_secrets.MockContainerEnvStore) {
				store.EXPECT().Get(testContainerID).Return(nil, false)
			},
			expectedStatusCode: http.StatusNotFound,
			expectedCode:       "NotFound",
		},
		{
			name:               "returns 400 for empty container ID",
			containerID:        "",
			setupMock:          func(store *mock_secrets.MockContainerEnvStore) {},
			expectedStatusCode: http.StatusBadRequest,
			expectedCode:       "BadRequest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := mock_secrets.NewMockContainerEnvStore(ctrl)
			tc.setupMock(mockStore)

			router := mux.NewRouter()
			router.HandleFunc(ContainerEnvPath, ContainerEnvHandler(mockStore))

			path := "/v2/container-env/" + tc.containerID
			req, err := http.NewRequest("GET", path, nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			assert.Equal(t, tc.expectedStatusCode, recorder.Code)
			assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

			if tc.expectedStatusCode == http.StatusOK {
				var resp ContainerEnvResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedEnv, resp.Env)
			} else {
				var errResp utils.ErrorMessage
				err = json.Unmarshal(recorder.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCode, errResp.Code)
				assert.NotEmpty(t, errResp.Message)
			}
		})
	}
}

func TestSplunkTokenHandler_ResponseBodyJSONStructure(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := mock_secrets.NewMockSplunkTokenStore(ctrl)
	mockStore.EXPECT().Get(testContainerID).Return(testToken, true)

	router := mux.NewRouter()
	router.HandleFunc(SplunkTokenPath, SplunkTokenHandler(mockStore))

	req, err := http.NewRequest("GET", "/v2/splunk-token/"+testContainerID, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify the JSON has exactly the expected structure.
	var raw map[string]interface{}
	err = json.Unmarshal(recorder.Body.Bytes(), &raw)
	require.NoError(t, err)
	assert.Len(t, raw, 1, "response should have exactly one key")
	assert.Contains(t, raw, "token")
	assert.Equal(t, testToken, raw["token"])

	// Verify the response body is byte-exact with no extra data.
	expectedJSON, _ := json.Marshal(SplunkTokenResponse{Token: testToken})
	assert.Equal(t, string(expectedJSON), recorder.Body.String())
}

func TestContainerEnvHandler_ResponseBodyJSONStructure(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testEnv := map[string]string{"FOO": "bar", "BAZ": "qux"}
	mockStore := mock_secrets.NewMockContainerEnvStore(ctrl)
	mockStore.EXPECT().Get(testContainerID).Return(testEnv, true)

	router := mux.NewRouter()
	router.HandleFunc(ContainerEnvPath, ContainerEnvHandler(mockStore))

	req, err := http.NewRequest("GET", "/v2/container-env/"+testContainerID, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify the JSON has exactly the expected structure.
	var raw map[string]interface{}
	err = json.Unmarshal(recorder.Body.Bytes(), &raw)
	require.NoError(t, err)
	assert.Len(t, raw, 1, "response should have exactly one key")
	assert.Contains(t, raw, "env")

	envMap, ok := raw["env"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "bar", envMap["FOO"])
	assert.Equal(t, "qux", envMap["BAZ"])

	// Verify the response body is byte-exact with no extra data.
	expectedJSON, _ := json.Marshal(ContainerEnvResponse{Env: testEnv})
	assert.Equal(t, string(expectedJSON), recorder.Body.String())
}

func TestSplunkTokenHandler_ErrorResponseContainsContainerID(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := mock_secrets.NewMockSplunkTokenStore(ctrl)
	mockStore.EXPECT().Get(testContainerID).Return("", false)

	router := mux.NewRouter()
	router.HandleFunc(SplunkTokenPath, SplunkTokenHandler(mockStore))

	req, err := http.NewRequest("GET", "/v2/splunk-token/"+testContainerID, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNotFound, recorder.Code)

	var errResp utils.ErrorMessage
	err = json.Unmarshal(recorder.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.True(t, strings.Contains(errResp.Message, testContainerID),
		"error message should contain the container ID")
}
